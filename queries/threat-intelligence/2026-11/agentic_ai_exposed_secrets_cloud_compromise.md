# Agentic AI Exposed Secrets and Cloud Compromise — Threat Hunts

**Created:** 2026-11-10
**Platform:** Microsoft Defender XDR
**Tables:** EntraIdSpnSignInEvents, CloudAppEvents, CloudAuditEvents, CloudStorageAggregatedEvents
**Keywords:** agentic AI, ARTEX, exposed secrets, public code repositories, service principal, workload identity, Key Vault, Storage Accounts, Azure resource discovery, cloud credential abuse
**MITRE:** T1552.001, T1078.004, T1526, T1580, T1530
**Domains:** cloud, identity, spn, exposure
**Timeframe:** Last 30 days (configurable)
**Source:** [Threat actors use agentic AI tooling to find and abuse exposed secrets (2026-11-05)](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/)

---
## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Published IPs in service principal sign-ins](#query-1-published-ips-in-service-principal-sign-ins) | Investigation | `EntraIdSpnSignInEvents` |
| 2 | [Published IPs in Microsoft 365 cloud-app activity](#query-2-published-ips-in-microsoft-365-cloud-app-activity) | Investigation | `CloudAppEvents` |
| 3 | [Published IPs in Azure cloud audit events](#query-3-published-ips-in-azure-cloud-audit-events) | Investigation | `CloudAuditEvents` |
| 4 | [One source using multiple service principals](#query-4-one-source-using-multiple-service-principals) | Investigation | `EntraIdSpnSignInEvents` |
| 5 | [Published IPs with successful cloud-storage operations](#query-5-published-ips-with-successful-cloud-storage-operations) | Investigation | `CloudStorageAggregatedEvents` |



## Threat Overview

Microsoft reported agentic tooling used to search public code repositories for exposed credentials and then use valid application credentials to access Entra ID tenants and connected Azure and Microsoft 365 resources. Reported follow-on activity included service principal sign-ins, cloud-resource discovery, Key Vault and Storage access, and attempts to access AI workloads. The article does not attribute this activity to a named actor.

The campaign's published IP indicators support direct hunts, while workload-identity and cloud-audit behavior remains useful if infrastructure changes. Treat the Tor-associated address with caution and correlate it with application, resource, and sign-in context.

### TTP Summary

| Capability | TTP |
|---|---|
| Exposed credentials in public code repositories | T1552.001 — Credentials in Files |
| Use of compromised service-principal credentials | T1078.004 — Cloud Accounts |
| Discovery of cloud services and resources | T1526, T1580 |
| Access to data in cloud storage | T1530 |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| `199.19.77[.]18` is a Tor exit node and may be associated with unrelated activity | Treat a match as an investigation lead, not proof of compromise; correlate identity, resource, and timing |
| Infrastructure and client fingerprints can change rapidly | Use the IPs as point-in-time IOCs and retain behavior-based workload-identity hunts |
| Multiple service principals from one source can be legitimate automation | Baseline known automation and review only attributable, non-empty source IPs; do not alert on the threshold alone |
| `CloudAuditEvents` is a subset of Azure audit telemetry | Use it as supporting evidence and check the relevant Entra, Azure Activity, and resource diagnostic sources available in the tenant |
| Live Advanced Hunting uses `IPAddress` on `CloudStorageAggregatedEvents` | Preserve the column casing accepted by the execution schema; schema catalogs may differ from the live table |

## IOC Reference

The following public IP indicators are quoted from the source article's narrative and hunting guidance. The article notes that indicators may rotate.

| Indicator | Type | Description |
|---|---|---|
| `199.19.77[.]84` | IPv4 | Source of successful service principal sign-ins and cloud-resource activity |
| `199.19.77[.]18` | IPv4 | Source associated with service principal sign-ins; reported as a Tor exit node |
| `65.87.223[.]26` | IPv4 | Source of malicious operations and attempts to obtain App Service authentication tokens |
| `157.22.126[.]128` | IPv4 | Source of reconnaissance against Azure AI workloads |

## Queries

### Query 1: Published IPs in service principal sign-ins

**Purpose:** Finds service principal sign-ins from the campaign's published IP addresses, including failed attempts.
**Severity:** High
**MITRE:** T1078.004
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Static IP IOC hunt; refresh indicators and correlate sign-in details before promotion."
-->
```kql
let iocIPs = dynamic(["199.19.77.84", "199.19.77.18", "65.87.223.26", "157.22.126.128"]);
EntraIdSpnSignInEvents
| where Timestamp > ago(30d)
| where IPAddress in (iocIPs)
| project Timestamp, ApplicationId, ServicePrincipalName, ServicePrincipalId,
          ResourceDisplayName, IPAddress, ErrorCode, CorrelationId, RequestId, ReportId
```
**Expected results:** Any match merits review of the service principal, resource, result code, and corresponding workload-identity activity.

### Query 2: Published IPs in Microsoft 365 cloud-app activity

**Purpose:** Summarizes cloud-app actions and applications associated with the published IPs.
**Severity:** High
**MITRE:** T1078.004, T1530
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated IOC investigation query; review underlying events before any detection use."
-->
```kql
let iocIPs = dynamic(["199.19.77.84", "199.19.77.18", "65.87.223.26", "157.22.126.128"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where IPAddress in (iocIPs)
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Applications=make_set(Application, 10), Actions=make_set(ActionType, 20) by IPAddress
| order by Events desc
```
**Expected results:** Review any matching source IP alongside the summarized applications and operations; IP-only matches are not sufficient for attribution.

### Query 3: Published IPs in Azure cloud audit events

**Purpose:** Finds Azure cloud-audit activity associated with the campaign IPs.
**Severity:** High
**MITRE:** T1078.004, T1526, T1580
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Supporting cloud-audit hunt; CloudAuditEvents coverage is partial and should be correlated with other Azure audit sources."
-->
```kql
let iocIPs = dynamic(["199.19.77.84", "199.19.77.18", "65.87.223.26", "157.22.126.128"]);
CloudAuditEvents
| where Timestamp > ago(30d)
| where IPAddress in (iocIPs)
| where DataSource =~ "Azure"
| project Timestamp, DataSource, IPAddress, ActionType, OperationName, UserAgent, ReportId
```
**Expected results:** Correlate any matching operation with service-principal sign-ins and Azure resource diagnostics.

### Query 4: One source using multiple service principals

**Purpose:** Highlights an IP associated with at least three distinct service principals in an hour, matching a behavioral signal described in the article.
**Severity:** Medium
**MITRE:** T1078.004, T1526
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Behavioral baseline requiring tenant-specific allowlisting and review; not suitable as a standalone alert."
-->
```kql
EntraIdSpnSignInEvents
| where Timestamp > ago(30d)
| where isnotempty(IPAddress)
| summarize SignIns=count(), ServicePrincipals=dcount(ServicePrincipalId), Applications=dcount(ApplicationId),
            Failures=countif(ErrorCode != 0), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by IPAddress, TimeWindow=bin(Timestamp, 1h)
| where ServicePrincipals >= 3
| project TimeWindow, IPAddress, SignIns, ServicePrincipals, Applications, Failures, FirstSeen, LastSeen
| order by ServicePrincipals desc, SignIns desc
```
**Expected results:** Investigate the source, app ownership, sign-in outcomes, and resource requests for each qualifying time window; established automation can create benign clusters.

### Query 5: Published IPs with successful cloud-storage operations

**Purpose:** Finds successful storage activity associated with the published IP indicators.
**Severity:** High
**MITRE:** T1078.004, T1530
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregated IOC investigation query; verify operation details in source storage diagnostics before any detection use."
-->
```kql
let iocIPs = dynamic(["199.19.77.84", "199.19.77.18", "65.87.223.26", "157.22.126.128"]);
CloudStorageAggregatedEvents
| where Timestamp > ago(30d)
| where IPAddress in (iocIPs)
| where SuccessfulOperationsCount > 0
| summarize Operations=sum(OperationsCount), SuccessfulOperations=sum(SuccessfulOperationsCount),
            SuccessfulReads=sum(SuccessfulReadOperations), Bytes=sum(TotalResponseLength),
            StorageAccounts=dcount(StorageAccount) by IPAddress
| order by SuccessfulReads desc
```
**Expected results:** Any successful read activity from a published IP should be correlated with the relevant storage-account audit records and service-principal sign-in.

## General Tuning Notes

1. Revalidate and refresh public IPs before operational use; the article warns that infrastructure can rotate.
2. Keep the multi-service-principal query as an investigation lead until normal workload-identity automation is baselined.
3. This campaign contains no tenant-derived identifiers or test-run entities.

## References

- Microsoft Threat Intelligence — [Threat actors use agentic AI tooling to find and abuse exposed secrets](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/)
- MITRE ATT&CK — [Credentials in Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/), [Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/), [Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/), [Cloud Infrastructure Discovery (T1580)](https://attack.mitre.org/techniques/T1580/), [Data from Cloud Storage Object (T1530)](https://attack.mitre.org/techniques/T1530/)
