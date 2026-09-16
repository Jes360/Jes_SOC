# DET-04: Network Share Access to Windows Administrative Shares

**Specification Version:** 1.0.0  
**Last Updated:** 2026-09-16  
**Author / Engineering Lead:** JestineSOC Detection Engineering Team  
**Lifecycle Status:** Validated  

---

## 1. Detection Metadata & Identification

| Specification Attribute | Value / Operational Definition |
| :--- | :--- |
| **1. Detection ID** | `DET-04` |
| **2. Detection Name** | Network Share Access to Windows Administrative Shares |
| **21. Maturity Level** | **Validated** (Empirically verified against authentic Sysmon Event 3 telemetry and 7 boundary conditions) |
| **15. Severity Rationale** | **High** (High-confidence indicator of lateral movement, remote staging, or privileged administration) |

---

## 2. Analytic Context & Threat Foundation

### 3. Objective
* Detect non-machine and non-system access to Windows default administrative shares (`C$`, `ADMIN$`, `IPC$`) across Windows Security Event 5140 / 5145 and direct network connections on SMB port 445 via Sysmon Event 3.
* Identify adversary lateral movement, remote file staging, and remote service invocation across internal network endpoints.

### 4. Threat / Analytic Hypothesis
* **Adversary Threat Model:** Once valid credentials or administrative privileges are obtained on a network, adversaries frequently leverage SMB administrative shares to move laterally. Tools like PsExec, Impacket (`psexec.py`, `smbclient.py`), and Cobalt Strike stage binaries in `ADMIN$` or `C$\Windows` and execute them remotely via the Service Control Manager or scheduled tasks.
* **Analytic Hypothesis:** When an adversary accesses an administrative share from a remote system, Windows Security auditing will record Event 5140 or 5145 with `ShareName` matching `*\C$`, `*\ADMIN$`, or `*\IPC$` and a non-machine `SubjectUserName`. Concurrently, endpoint sensors like Sysmon will record Event 3 with `DestinationPort: 445` initiated by a non-system process.
* **Pre-requisite Activity:** Credential compromise (`T1078`, `T1110`) and network reachability over TCP port 445.
* **Anticipated Post-Exploitation Activity:** Remote service installation (`T1543.003`), remote scheduled tasks (`T1053.005`), or file exfiltration.

### 8. MITRE ATT&CK Mapping
* **Enterprise Matrix Version:** MITRE ATT&CK v15 (Pinned)
* **Primary Tactic:** Lateral Movement ([TA0008](https://attack.mitre.org/tactics/TA0008/))
* **Primary Technique:** Remote Services: SMB/Windows Admin Shares ([T1021.002](https://attack.mitre.org/techniques/T1021/002/))
* **Secondary Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
* **Technique Relevance:** Administrative shares provide direct file system and remote management access to Windows endpoints. Remote access to `C$` and `ADMIN$` is rarely required by standard users and represents a primary vector for lateral propagation.

---

## 3. Telemetry & Data Requirements

### 5. Data Source
* **Platform / OS:** Microsoft Windows 11 / Windows Server 2022+
* **Primary Log Channel:** `Security.evtx` (Event 5140: A network share object was accessed; Event 5145: A detailed network share object was checked)
* **Secondary Log Channel:** `Microsoft-Windows-Sysmon/Operational` (Event 3: Network Connection)
* **Auditing Prerequisites:**
  * Advanced Audit Configuration $\rightarrow$ Object Access $\rightarrow$ File Share / Detailed File Share:
    ```cmd
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed File Share" /success:enable
    ```
  * Sysmon Network Connection monitoring active for TCP port 445.

### 6. Required Telemetry Fields
All fields resolve against `docs/data-model.md`:

| Telemetry Field (Security 5140 / Sysmon 3) | Normalized Field Name | Data Type | Field Purpose / Analytic Requirement |
| :--- | :--- | :--- | :--- |
| `EventID` | `event.code` | Integer | `5140`, `5145` (Share Access) or `3` (Network Connection) |
| `ShareName` / `RelativeTargetName` | `file.path` | String | Target share name (must contain `\C$`, `\ADMIN$`, or `\IPC$`) |
| `SubjectUserName` / `User` | `user.target.name` | String | User identity initiating the access; must not be machine account (`*$`) |
| `IpAddress` / `SourceIp` | `source.ip` | IP Address | Originating source IP of the SMB connection |
| `DestinationPort` | `destination.port` | Integer | Port 445 (SMB) |
| `Computer` | `host.name` | String | Destination hostname hosting the administrative share |

---

## 4. Canonical Sigma Rule Specification

### 7. Canonical Sigma Rule
Defined in [`detections/sigma/windows_smb_admin_shares.yml`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/detections/sigma/windows_smb_admin_shares.yml):

```yaml
title: Network Share Access to Windows Administrative Shares
id: a4b2c1d0-9e8f-4a5b-b6c7-1e2d3f4a5b04
status: test
description: |
  Detects access to Windows administrative network shares (C$, ADMIN$, IPC$)
  by non-machine and non-system accounts, or direct SMB network connections
  on port 445. Adversaries routinely utilize administrative shares for lateral
  movement, remote service execution, and file staging.
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: JestineSOC Detection Engineering Team
date: 2026-09-16
modified: 2026-09-16
tags:
  - attack.lateral-movement
  - attack.t1021.002
logsource:
  product: windows
detection:
  selection_share:
    EventID:
      - 5140
      - 5145
    ShareName|contains:
      - '\C$'
      - '\ADMIN$'
      - '\IPC$'
  selection_sysmon:
    EventID: 3
    DestinationPort: 445
  filter_machine_share:
    SubjectUserName|endswith: '$'
  filter_system_share:
    SubjectUserName:
      - 'SYSTEM'
      - 'ANONYMOUS LOGON'
      - 'LOCAL SERVICE'
      - 'NETWORK SERVICE'
      - '-'
      - ''
  filter_machine_sysmon:
    User|endswith: '$'
  filter_system_sysmon:
    User:
      - 'NT AUTHORITY\SYSTEM'
      - 'NT AUTHORITY\ANONYMOUS LOGON'
      - 'NT AUTHORITY\LOCAL SERVICE'
      - 'NT AUTHORITY\NETWORK SERVICE'
      - 'SYSTEM'
      - '-'
      - ''
  condition: (selection_share and not filter_machine_share and not filter_system_share) or (selection_sysmon and not filter_machine_sysmon and not filter_system_sysmon)
fields:
  - EventID
  - ShareName
  - SubjectUserName
  - User
  - IpAddress
  - DestinationPort
  - DestinationIp
  - Computer
falsepositives:
  - Legitimate administrative tasks or remote management via tools like SCCM/MECM or PowerShell Remoting
  - Routine system backup software accessing C$ for volume imaging
level: high
```

---

## 5. Verification Matrix & Empirical Test Results

### 9. Positive Test Cases
* **`TC-AUTH-005` (Authentic Sysmon Event 3 Ingestion):**
  * Telemetry Source: `evidence/telemetry/sysmon-sample.json`
  * EventID: `3` (Network Connection)
  * Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  * DestinationPort: `445` (`microsoft-ds`)
  * User: `LAB-HOST01\lab_user_test`
  * **Result:** **MATCH** (Alert emitted).
* **`TC-POS-006` (Administrative C$ Share Access):**
  * EventID: `5140`, `ShareName: \\*\C$`, `SubjectUserName: lab_user_test`
  * **Result:** **MATCH** (Alert emitted).
* **`TC-POS-007` (Administrative ADMIN$ Share Access):**
  * EventID: `5140`, `ShareName: \\*\ADMIN$`, `SubjectUserName: lab_user_test`
  * **Result:** **MATCH** (Alert emitted).

### 10. Negative Test Cases & False-Positive Suppression
* **`TC-NEG-017` (Standard Non-Administrative Share):** Access to `\\*\PublicReports` $\rightarrow$ **NO_MATCH** (Suppressed; departmental file share is not an admin share).
* **`TC-NEG-018` (Machine Account Access):** Computer identity `LAB-SRV01$` accessing `C$` $\rightarrow$ **NO_MATCH** (Suppressed; domain computer replication / cluster noise).
* **`TC-NEG-019` (Standard Local Logon Without Share Access):** Event 4624 logon without share access $\rightarrow$ **NO_MATCH** (Suppressed; wrong event channel).
* **`TC-NEG-020` (Non-SMB Network Connection):** Sysmon Event 3 to destination port `443` (HTTPS) $\rightarrow$ **NO_MATCH** (Suppressed; web traffic is not SMB).

### 11. Expected Result
100% boundary accuracy across all 7 test cases (3 matches on true positive attack conditions, 4 clean suppressions on non-qualifying telemetry).

### 12. Actual Result
Verified 7/7 passed via automated evaluation engine [`tests/runners/eval_det04_engine.py`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/tests/runners/eval_det04_engine.py). Output documented in [`evidence/detections/ev-det-04-boundary-matrix.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/detections/ev-det-04-boundary-matrix.json).

---

## 6. Operational Triage & SIEM Translations

### 13. False-Positive Scenarios & Tuning Guidance
* **Backup & Endpoint Management:** Backup agents (e.g. Veeam, Commvault) and endpoint management systems (MECM/SCCM) connect to `ADMIN$` and `C$` to push agent updates. Tune by excluding known backup service accounts or static management IP subnets.
* **Domain Controller Replication:** Ensure domain controller computer accounts are appropriately filtered using machine account exclusion rules (`*$`).

### 14. SOC Analyst Triage Checklist
When `DET-04` fires:
1. **Identify Source Identity:** Is `SubjectUserName` an enterprise admin, local user, or unexpected service account?
2. **Inspect Source IP:** Is the originating IP a jump host, administrative workstation, or standard user desktop?
3. **Correlate with Process Creation:** Query Sysmon Event 1 on the destination host within 5 minutes of share access. Look for suspicious service creation (`services.exe`), binary staging in `C$\Windows\Temp`, or execution via `cmd.exe`/`powershell.exe`.
4. **Determine Target Share:** Was access to `ADMIN$` (commonly used for service binary staging) or `C$` (raw drive access)?
5. **Immediate Containment:** If unapproved, isolate the source and target endpoints, revoke user sessions, and block SMB at host firewalls.

### 17. Derived Splunk SPL Translation
```spl
(
  (index=winsec source="XmlWinEventLog:Security" (EventCode=5140 OR EventCode=5145)
   (ShareName="*\\C$" OR ShareName="*\\ADMIN$" OR ShareName="*\\IPC$" OR RelativeTargetName="*C$*" OR RelativeTargetName="*ADMIN$*"))
  OR
  (index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationPort=445)
)
NOT (
  Account_Name="*$" OR User="*$" OR
  Account_Name="SYSTEM" OR Account_Name="ANONYMOUS LOGON" OR Account_Name="LOCAL SERVICE" OR Account_Name="NETWORK SERVICE" OR
  User="NT AUTHORITY\\SYSTEM" OR User="NT AUTHORITY\\ANONYMOUS LOGON" OR User="NT AUTHORITY\\LOCAL SERVICE" OR User="NT AUTHORITY\\NETWORK SERVICE" OR
  Account_Name="-" OR Account_Name=""
)
| eval UserIdentity=coalesce(Account_Name, User, user)
| eval TargetShare=coalesce(ShareName, RelativeTargetName, "SMB_Direct_Port_445")
| eval SourceAddress=coalesce(IpAddress, SourceIp, source_ip)
| stats min(_time) as FirstSeen max(_time) as LastSeen count by Computer, UserIdentity, TargetShare, SourceAddress
| eval AlertSeverity="High", MitreTechniques="T1021.002"
```

### 18. Derived Azure Sentinel KQL Translation
```kql
let lookback = 24h;
let systemAccounts = dynamic(["SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\ANONYMOUS LOGON", "-", ""]);
let ShareAccess = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID in (5140, 5145)
| where ShareName has_any (@"\C$", @"\ADMIN$", @"\IPC$")
| where not(TargetAccount endswith "$")
| where not(TargetAccount in~ (systemAccounts))
| project TimeGenerated, Computer, Account = TargetAccount, TargetShare = ShareName, SourceAddress = IpAddress, TableSource = "Security_ShareAccess";
let SysmonSMB = Event
| where TimeGenerated >= ago(lookback)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| extend DestPort = toint(parse_xml(EventData).Data[17]["#text"])
| extend UserName = tostring(parse_xml(EventData).Data[6]["#text"])
| extend SrcIp = tostring(parse_xml(EventData).Data[10]["#text"])
| where DestPort == 445
| where not(UserName endswith "$")
| where not(UserName in~ (systemAccounts))
| project TimeGenerated, Computer, Account = UserName, TargetShare = "SMB_Port_445", SourceAddress = SrcIp, TableSource = "Sysmon_Event3";
union isfuzzy=true ShareAccess, SysmonSMB
| summarize min(TimeGenerated), max(TimeGenerated), count() by Computer, Account, TargetShare, SourceAddress, TableSource
| extend AlertSeverity = "High", MitreTechniques = "T1021.002"
```

### 19. Semantic Reconciliation Matrix

| Feature | Canonical Sigma | Splunk SPL | Azure Sentinel KQL | Reconciliation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Share Name Matching** | `ShareName\|contains: ['\C$', '\ADMIN$', '\IPC$']` | Wildcard matches `ShareName="*\\C$"` etc. | `ShareName has_any (@"\C$", @"\ADMIN$", @"\IPC$")` | Matches administrative shares across all dialects. |
| **Multi-Source Logic** | Unions Share Access with Sysmon Port 445 | Unions EventCode 5140/5145 with EventCode 3 | Unions `SecurityEvent` and `Event` | Normalizes fields into common schema (`Account`, `TargetShare`, `SourceAddress`). |
| **Identity Filtering** | Rejects `*$` and standard system identities | Rejects `*$` and system accounts | Rejects `endswith "$"` and `in~ (systemAccounts)` | Equivalent noise suppression across SIEM platforms. |

---

## 7. Scope Limitations & Verification Provenance

### 20. Evidence Location & Provenance
* **Boundary Matrix Evidence:** [`evidence/detections/ev-det-04-boundary-matrix.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/detections/ev-det-04-boundary-matrix.json)
* **Execution Proof:** [`evidence/detections/ev-det-04-execution-proof.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/detections/ev-det-04-execution-proof.json)
* **Underlying Telemetry Sample:** [`evidence/telemetry/sysmon-sample.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/telemetry/sysmon-sample.json) (EventID 3)

### 22. Known Scope Limitations & Non-Claims
* **Scope Limitation `SL-12` (Standard Non-Administrative Shares):** Access to standard non-administrative file shares (e.g. `\\*\Public`, `\\*\Marketing`) is intentionally excluded. File activity on non-administrative shares must be monitored via dedicated data loss prevention (DLP) or file integrity monitoring rules.
* **Scope Limitation `SL-13` (IPC$ Ambient Baseline Noise):** `IPC$` connections occur legitimately and frequently in Windows environments for inter-process communication and remote RPC. While included in the base definition, production tuning may require promoting alerts to high priority only when access to `IPC$` is followed by pipe creation or service installation.
* **Scope Limitation `SL-14` (Encrypted SMBv3 Payloads):** When SMB encryption is negotiated (standard in modern Windows environments), network traffic on port 445 is fully encrypted in transit. This rule relies on host-level event log emission (Security 5140/5145 and Sysmon 3) rather than network packet inspection.

### 23. Operational Acceptance Criteria
* [x] Canonical Sigma rule created (`windows_smb_admin_shares.yml`).
* [x] Evaluates and matches authentic Sysmon Event 3 telemetry (`TC-AUTH-005`).
* [x] 7-case deterministic boundary test suite achieves 100% pass rate.
* [x] Strictly benign telemetry generator implemented (`gen-smb-events.ps1`).
* [x] Scope limitations `SL-12`, `SL-13`, and `SL-14` documented.
