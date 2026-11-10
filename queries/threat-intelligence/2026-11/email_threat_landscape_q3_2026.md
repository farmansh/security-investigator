# Email Threat Landscape Q3 2026 — Campaign Hunts

**Created:** 2026-11-10
**Platform:** Microsoft Defender XDR
**Tables:** EmailEvents, EmailAttachmentInfo, EmailUrlInfo, DeviceProcessEvents
**Keywords:** Q3 2026, phishing, QR code, device code phishing, CAPTCHA-gated phishing, SVG attachment, sender spoofing, Agent Tesla, double extension, salary review, purchase order, payroll lure
**MITRE:** T1566.001, T1566.002, T1204.001, T1204.002, T1528, T1059.001, T1059.007, T1105, T1656
**Domains:** email, endpoint, identity
**Timeframe:** Last 30 days (configurable)
**Source:** [Email threat landscape: Q3 2026 trends and insights (2026-11-05)](https://www.microsoft.com/en-us/security/blog/2026/11/05/email-threat-landscape-q3-2026-trends-and-insights/)

---
## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Published campaign sender IOC sweep](#query-1-published-campaign-sender-ioc-sweep) | Investigation | `EmailEvents` |
| 2 | [Published campaign attachment names and hashes](#query-2-published-campaign-attachment-names-and-hashes) | Investigation | `EmailAttachmentInfo` |
| 3 | [Published QR-phishing URL](#query-3-published-qr-phishing-url) | Investigation | `EmailUrlInfo` |
| 4 | [Published payload execution on endpoints](#query-4-published-payload-execution-on-endpoints) | Investigation | `DeviceProcessEvents` |



## Threat Overview

Microsoft reported a Q3 increase in phishing volume, continued credential theft, sender impersonation, QR-code and CAPTCHA-gated lures, and malicious activity through Microsoft Teams. Two detailed campaigns illustrate the techniques: an August salary-review document that used a QR code to initiate device-code phishing, and a September Spanish-language purchase-order/payroll campaign that delivered Agent Tesla through disguised archives and executable/script payloads.

This file focuses on those two technique-rich campaigns and their published indicators. The source also describes broad quarterly trends; the trend statistics alone are not suitable as a tenant detection threshold.

### TTP Summary

| Capability | TTP |
|---|---|
| Malicious email attachments and QR-code delivery | T1566.001, T1566.002 |
| Device-code phishing and token theft | T1528 |
| User execution of disguised script/executable payloads | T1204.002 |
| JavaScript and PowerShell execution | T1059.007, T1059.001 |
| Payload retrieval from attacker-controlled infrastructure | T1105 |
| Sender/display-name impersonation | T1656 |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| All campaign events in this report occurred in August or September 2026, outside the 30-day Advanced Hunting window at authoring time | A 0-row IOC result is expected for this run; use an authorized longer-retention source for retrospective coverage |
| `pixeldrain[.]com` and `microsoft.com/devicelogin` are legitimate services | Match the published full URL/path and campaign context; do not alert on a broad domain-only match |
| An attachment name or hash is campaign-specific and ages quickly | Refresh published indicators before operational use; keep behavioral email and endpoint detections separate from static IOC matches |
| The report’s quarterly volume statistics are aggregate research, not a local tenant baseline | Do not convert global counts or percentages into tenant thresholds |

## IOC Reference

Indicators below are transcribed from the source article's IOC table. Defanged values are shown as published; query literals use their refanged forms.

| Type | Indicator | Description |
|---|---|---|
| Domain | `wekash[.]net` | Sender domain for the August salary-review campaign |
| Email | `smtp[@]wekash[.]net` | Sender address for the August campaign |
| File name | `Your-Q3-Compensation-Summary.docx` | Word attachment carrying the QR-code lure |
| Domain | `splace[.]co[.]za` | Domain hosting the August phishing content |
| URL | `https://splace[.]co[.]za/0987643345678908765421234567890987654320987654321223456787654/onedrive/` | Published phishing URL |
| Domain | `carloxmextos[.]org` | Authenticated sender domain used by the September campaign |
| Email | `contacto06[@]carloxmextos[.]org` | Sender address for the September campaign |
| File name | `Nuevo orden de compra – 21092026.pdf.uu` | Purchase-order archive |
| File name | `Nuevo orden de compra – 21092026.pdf.js` | JavaScript downloader from the purchase-order archive |
| File name | `Lincoln.ps1` | PowerShell payload fetched by the downloader |
| File name | `Nomina 21.09.2026.xml.001` | Payroll archive |
| File name | `Nomina 21.09.2026.xml.exe` | Agent Tesla executable from the payroll archive |
| SHA-256 | `BEDD2297739632DA8EE470367295FE976E55BE74D628DCAEE7FA98121EE530F1` | Purchase-order archive |
| SHA-256 | `CE832350C165522DB03DB040CA07917976D1A91F97E7016EA36DCC6B53E0EB13` | JavaScript downloader |
| SHA-256 | `F8B49891D15A578E4DE28FECF99D0D78DB6B2C3DA81CD51C931B8D128E60C187` | PowerShell payload |
| SHA-256 | `C438B9A3BB67E2C10EFF0D01513422DC17DCE7C5508303A680E46F3DCEC886EF` | Payroll archive |
| SHA-256 | `72966B30BBD87E42C683D2AC7A42BB62021FC14389D508551432FFD70D62F33A` | Agent Tesla executable |

## Queries

### Query 1: Published campaign sender IOC sweep

**Purpose:** Finds mail using either published campaign sender address or sender domain.
**Severity:** High
**MITRE:** T1566.001, T1566.002, T1656
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Static campaign IOC hunt; the observed campaigns predate the Advanced Hunting 30-day window. Refresh indicators before promotion."
-->
```kql
let lookback = 30d;
let iocSenders = dynamic(["smtp@wekash.net", "contacto06@carloxmextos.org"]);
let iocDomains = dynamic(["wekash.net", "carloxmextos.org"]);
EmailEvents
| where Timestamp > ago(lookback)
| where SenderMailFromAddress in~ (iocSenders)
    or SenderFromAddress in~ (iocSenders)
    or SenderMailFromDomain in~ (iocDomains)
    or SenderFromDomain in~ (iocDomains)
| project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress,
          RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes, AttachmentCount, UrlCount
```
**Expected results:** No matches are expected in the current 30-day window because the campaigns occurred in August and September 2026.

### Query 2: Published campaign attachment names and hashes

**Purpose:** Matches the published campaign attachment names and SHA-256 values in email attachment telemetry.
**Severity:** High
**MITRE:** T1566.001, T1204.002
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Static campaign IOC hunt; campaign dates are outside the current Advanced Hunting window. Refresh indicators before promotion."
-->
```kql
let iocHashes = dynamic([
"BEDD2297739632DA8EE470367295FE976E55BE74D628DCAEE7FA98121EE530F1",
"CE832350C165522DB03DB040CA07917976D1A91F97E7016EA36DCC6B53E0EB13",
"F8B49891D15A578E4DE28FECF99D0D78DB6B2C3DA81CD51C931B8D128E60C187",
"C438B9A3BB67E2C10EFF0D01513422DC17DCE7C5508303A680E46F3DCEC886EF",
"72966B30BBD87E42C683D2AC7A42BB62021FC14389D508551432FFD70D62F33A"
]);
let iocFiles = dynamic([
"Your-Q3-Compensation-Summary.docx",
"Nuevo orden de compra – 21092026.pdf.uu",
"Nuevo orden de compra – 21092026.pdf.js",
"Lincoln.ps1",
"Nomina 21.09.2026.xml.001",
"Nomina 21.09.2026.xml.exe"
]);
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where SHA256 in~ (iocHashes) or FileName in~ (iocFiles)
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256, ThreatTypes, ThreatNames
```
**Expected results:** No matches are expected in the current window; any future match should be correlated with the sender, message, and delivery verdict.

### Query 3: Published QR-phishing URL

**Purpose:** Finds the exact published phishing host or URL path in email URL telemetry, including URLs extracted from QR-code content.
**Severity:** High
**MITRE:** T1566.002, T1528
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Static URL IOC hunt; the published URL is historical and should be refreshed before operational use."
-->
```kql
let iocUrl = "/0987643345678908765421234567890987654320987654321223456787654/onedrive/";
EmailUrlInfo
| where Timestamp > ago(30d)
| where UrlDomain =~ "splace.co.za" or Url contains iocUrl
| project Timestamp, NetworkMessageId, UrlDomain, UrlLocation, Url
```
**Expected results:** No matches are expected in this window. A future host or path match warrants review of the associated message and any device-code sign-in activity.

### Query 4: Published payload execution on endpoints

**Purpose:** Matches the campaign SHA-256 values and payload filenames in endpoint process telemetry.
**Severity:** High
**MITRE:** T1204.002, T1059.001, T1059.007
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Static IOC query with historical campaign indicators; use current indicators and behavioral follow-up before any detection deployment."
-->
```kql
let iocHashes = dynamic([
"BEDD2297739632DA8EE470367295FE976E55BE74D628DCAEE7FA98121EE530F1",
"CE832350C165522DB03DB040CA07917976D1A91F97E7016EA36DCC6B53E0EB13",
"F8B49891D15A578E4DE28FECF99D0D78DB6B2C3DA81CD51C931B8D128E60C187",
"C438B9A3BB67E2C10EFF0D01513422DC17DCE7C5508303A680E46F3DCEC886EF",
"72966B30BBD87E42C683D2AC7A42BB62021FC14389D508551432FFD70D62F33A"
]);
let iocFiles = dynamic(["Lincoln.ps1", "Nomina 21.09.2026.xml.exe", "Nuevo orden de compra – 21092026.pdf.js"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (iocHashes) or FileName in~ (iocFiles) or ProcessCommandLine has_any ("Lincoln.ps1", "Agent Tesla")
| project Timestamp, DeviceName, FileName, SHA256, ProcessCommandLine, InitiatingProcessFileName, ReportId
```
**Expected results:** No matches are expected for the historical campaign indicators in this 30-day window.

## General Tuning Notes

1. These exact IOC queries are not custom-detection ready: the campaign indicators are historical, and broad sender/URL matching can create false positives.
2. The live Advanced Hunting tests for all four queries returned 0 rows. The zero results are consistent with the source article's August and September event dates being outside the 30-day query window.
3. Before operational reuse, refresh indicators and consider current behavioral detections for QR-code URLs, suspicious attachment delivery, and device-code sign-ins.

## References

- Microsoft Threat Intelligence — [Email threat landscape: Q3 2026 trends and insights](https://www.microsoft.com/en-us/security/blog/2026/11/05/email-threat-landscape-q3-2026-trends-and-insights/)
- MITRE ATT&CK — [Phishing (T1566)](https://attack.mitre.org/techniques/T1566/), [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/), [User Execution (T1204)](https://attack.mitre.org/techniques/T1204/), [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/)
