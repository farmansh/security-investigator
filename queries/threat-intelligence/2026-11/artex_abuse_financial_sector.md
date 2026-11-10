# Storm-3358 ARTEX Abuse Against Financial Organizations — Threat Hunts

**Created:** 2026-11-10
**Platform:** Microsoft Defender XDR
**Tables:** DeviceNetworkEvents, DeviceProcessEvents
**Keywords:** Storm-3358, ARTEX, WISP, vshell, AdaptixC2, web shell, public-facing application, SSRF, anonymous file upload, curl, netcat, RAT, financial sector
**MITRE:** T1595, T1190, T1505.003, T1105, T1059.004, T1078.004, T1110.003
**Domains:** endpoint, cloud, identity
**Timeframe:** Last 30 days (configurable)
**Source:** [ARTEX abuse expands as cybercriminals target financial sector (2026-11-06)](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/)

---
## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Published ARTEX infrastructure sweep](#query-1-published-artex-infrastructure-sweep) | Investigation | `DeviceNetworkEvents` |
| 2 | [Web-server process spawning a shell or downloader](#query-2-web-server-process-spawning-a-shell-or-downloader) | Investigation | `DeviceProcessEvents` |
| 3 | [Execution of named ARTEX remote-access tools](#query-3-execution-of-named-artex-remote-access-tools) | Investigation | `DeviceProcessEvents` |
| 4 | [Web-server child downloader making outbound connections](#query-4-web-server-child-downloader-making-outbound-connections) | Investigation | `DeviceNetworkEvents` |



## Threat Overview

Microsoft attributes the reported activity to financially motivated actor Storm-3358, which used ARTEX alongside conventional tools to scan public-facing systems, exploit web-application weaknesses, and deploy remote-access trojans. Reported behaviors include anonymous file upload and SSRF exploitation, web-shell persistence, downloading WISP, vshell, and AdaptixC2, brute-force and password-spray attempts, API enumeration, and use of compromised cloud identities.

The campaign's published IPs support direct endpoint-network hunts. Behavioral queries look for server processes spawning shells or download utilities and for execution of the named RAT families; legitimate administrative and development use still requires review.

### TTP Summary

| Capability | TTP |
|---|---|
| Scanning internet-connected systems | T1595 — Active Scanning |
| Exploiting public-facing web applications | T1190 |
| Web-shell persistence | T1505.003 |
| Downloading RATs and other tooling | T1105 |
| Compromised cloud identities | T1078.004 |
| Brute-force and password-spray activity | T1110.003 |

### ⚠️ Hunt Pitfalls

| Pitfall | Mitigation |
|---|---|
| `curl`, `wget`, `netcat`, and scripting clients have legitimate uses | Prioritize them when launched beneath web-server processes or when paired with published indicators; review the process chain |
| Web-server and scripting process names vary by platform | Extend the parent-process list to match the server software actually deployed |
| Static IPs can rotate and may be shared through proxy/VPN infrastructure | Refresh indicators and correlate any match with process, host, and alert context |
| The article's sample Advanced Hunting query uses `TimeGenerated` for `DeviceNetworkEvents` | The verified Advanced Hunting schema uses `Timestamp`; these queries use that column |
| The source article's sample IP list differs from its IOC table for one address | This campaign follows the IOC table's `178.16.54[.]129` value |

## IOC Reference

The following indicators are copied from the article's IOC table. Queries use the corresponding un-defanged IP strings.

| Indicator | Type | Description |
|---|---|---|
| `199.19.95[.]66` | IPv4 | WISP C2 node |
| `199.19.95[.]67` | IPv4 | WISP C2 node |
| `199.19.95[.]68` | IPv4 | WISP C2 node |
| `91.92.240[.]238` | IPv4 | ARTEX server |
| `85.11.168[.]45` | IPv4 | ARTEX server |
| `85.11.167[.]52` | IPv4 | C2 server |
| `178.16.54[.]129` | IPv4 | ARTEX server |
| `31.77.229[.]35` | IPv4 | ARTEX server |

## Queries

### Query 1: Published ARTEX infrastructure sweep

**Purpose:** Finds endpoint network connections to the published ARTEX and WISP infrastructure.
**Severity:** High
**MITRE:** T1105
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Static network IOC hunt; refresh IPs and correlate matching connections with process and host context before promotion."
-->
```kql
let iocIPs = dynamic(["199.19.95.66", "199.19.95.67", "199.19.95.68", "91.92.240.238", "85.11.168.45", "85.11.167.52", "178.16.54.129", "31.77.229.35"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (iocIPs)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```
**Expected results:** A match to a published IP should be reviewed with the device, process, and connection action. A clean result does not establish absence beyond the 30-day window.

### Query 2: Web-server process spawning a shell or downloader

**Purpose:** Highlights shell and download utility processes whose initiating process chain descends from common web-server processes.
**Severity:** High
**MITRE:** T1190, T1505.003, T1059.004, T1105
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation query; server process names and legitimate deployment tooling vary by environment, so baseline before alerting."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessParentFileName in~ ("w3wp.exe", "php-cgi.exe", "httpd.exe", "apache2", "nginx")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "curl.exe", "wget.exe", "nc.exe", "ncat.exe")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName,
          InitiatingProcessParentFileName, ProcessCommandLine, AccountName, ReportId
```
**Expected results:** Investigate unexpected shell or downloader children, especially when followed by network activity or file creation.

### Query 3: Execution of named ARTEX remote-access tools

**Purpose:** Searches process names and command lines for the RAT families reported in the article.
**Severity:** High
**MITRE:** T1105, T1078.004
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Tool-name hunt can miss renamed binaries and may match benign references; combine with file reputation and process ancestry."
-->
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("wisp", "vshell", "adaptix")
    or ProcessCommandLine has_any ("WISP", "vshell", "AdaptixC2")
| project Timestamp, DeviceName, FileName, SHA256, ProcessCommandLine,
          InitiatingProcessFileName, ReportId
```
**Expected results:** Review the executable, parent process, signer, command line, and outbound connections; these names alone are not proof of malicious activity.

### Query 4: Web-server child downloader making outbound connections

**Purpose:** Correlates web-server process ancestry with outbound connections initiated by curl, wget, or netcat.
**Severity:** High
**MITRE:** T1190, T1505.003, T1105
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Investigation query; allowlist known deployment jobs only after verifying ownership and purpose."
-->
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessParentFileName in~ ("w3wp.exe", "php-cgi.exe", "httpd.exe", "apache2", "nginx")
| where InitiatingProcessFileName in~ ("curl", "curl.exe", "wget", "wget.exe", "nc", "ncat.exe")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, ActionType, InitiatingProcessFileName,
          InitiatingProcessParentFileName, InitiatingProcessCommandLine, ReportId
```
**Expected results:** Review any connection from a web-server-descended downloader for downloaded files, command execution, and subsequent persistence.

## General Tuning Notes

1. Use the IOC sweep as a point-in-time lead; the process-chain hunts are more resilient to infrastructure rotation.
2. Tune process ancestry to the web-server software deployed in the environment and distinguish approved deployment activity from unexpected shell execution.
3. Keep the tool-name query investigative unless corroborated by suspicious ancestry, network activity, or file reputation.

## References

- Microsoft Threat Intelligence — [ARTEX abuse expands as cybercriminals target financial sector](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/)
- MITRE ATT&CK — [Active Scanning (T1595)](https://attack.mitre.org/techniques/T1595/), [Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/), [Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/), [Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105/)
