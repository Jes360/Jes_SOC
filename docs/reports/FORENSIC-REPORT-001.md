# FORENSIC INVESTIGATION REPORT: INC-2026-001

**Case Reference:** INC-2026-001 / SCEN-01  
**Classification:** TLP:CLEAR / Laboratory Audit Standard  
**Lead Investigator:** SOC Incident Response Lead  
**Date of Incident:** 2026-09-16  
**Victim Asset:** `LAB-HOST01` (`192.0.2.100` / Windows Server 2022 / Workstation Baseline)  
**Threat Origin:** `198.51.100.55` (Simulated Adversary `APT-LAB-01`)  
**Compromised Identity:** `LAB\lab_user_test`  
**Overall Severity:** **CRITICAL (P1)**  
**Incident Verdict:** True Positive Incident — Credential Brute-Force, Account Breach, Obfuscated Execution & Admin Lateral Movement  

---

## 1. Executive Summary

On September 16, 2026, the JestineSOC Security Operations Center detected an alert sequence beginning with a burst of five failed network logon attempts targeting the local account `LAB\lab_user_test` from untrusted IP `198.51.100.55`. Within 15 seconds of the final failure, a successful network authentication occurred from the identical IP address, triggering canonical correlation rule **`CORR-01` (`mr_bruteforce_after_failures.yml`)** at severity **`CRITICAL`**.

Subsequent telemetry correlation revealed that the adversary leveraged the compromised session to launch base64-encoded discovery commands via Windows PowerShell (`DET-03` / `T1059.001`) and established connections to administrative file shares (`\\*\ADMIN$`) over SMB port 445 (`DET-04` / `T1021.002`).

Containment was executed per playbook [`IR-PLAYBOOK-001`](../playbooks/IR-PLAYBOOK-001-credential-compromise.md), isolating `LAB-HOST01` and disabling `lab_user_test`. Forensic artifact analysis confirms that while discovery commands executed, no persistent rootkits or data exfiltration occurred.

---

## 2. Evidence Provenance & Chain of Custody

All digital forensic artifacts were captured from authentic operating system event stores conforming to NFR-02 (Zero Secrets) and NFR-03 (RFC 5737 Sanitization):

| Artifact ID | Telemetry Source | Original Location | SHA-256 Digest | Description |
| :---: | :--- | :--- | :--- | :--- |
| **EV-01** | Windows Security | `C:\Windows\System32\Winevt\Logs\Security.evtx` | `8f1e4a...92b0` | Records 80211–80215 (Event 4625 Failures) |
| **EV-02** | Windows Security | `C:\Windows\System32\Winevt\Logs\Security.evtx` | `3c8d19...4f71` | Record 80216 (Event 4624 Success) |
| **EV-03** | Microsoft Sysmon | `Microsoft-Windows-Sysmon/Operational.evtx` | `a1b2c3...e4f5` | Event ID 1 (Process Creation: `powershell.exe`) |
| **EV-04** | Windows Security | `C:\Windows\System32\Winevt\Logs\Security.evtx` | `90a8d2...11c4` | Event ID 5140 (Share Access: `\\*\ADMIN$`) |
| **EV-05** | Microsoft Sysmon | `Microsoft-Windows-Sysmon/Operational.evtx` | `7d8e9f...33a2` | Event ID 3 (Network Connection: Port 445 SMB) |

---

## 3. Millisecond-Accurate Chronological Forensic Timeline

| Timestamp (UTC) | Event ID | Record ID | Source Entity | Target Entity | Action / Forensic Details | Triggered Rule |
| :---: | :---: | :---: | :---: | :---: | :--- | :---: |
| **2026-09-16T02:00:00.000Z** | 4625 | 80211 | `198.51.100.55` | `LAB\lab_user_test` | LogonType 3 failure; Status `0xc000006d`, SubStatus `0xc000006a` | `DET-01-PRIM` |
| **2026-09-16T02:00:05.120Z** | 4625 | 80212 | `198.51.100.55` | `LAB\lab_user_test` | LogonType 3 failure; Status `0xc000006d`, SubStatus `0xc000006a` | `DET-01-PRIM` |
| **2026-09-16T02:00:10.250Z** | 4625 | 80213 | `198.51.100.55` | `LAB\lab_user_test` | LogonType 3 failure; Status `0xc000006d`, SubStatus `0xc000006a` | `DET-01-PRIM` |
| **2026-09-16T02:00:15.380Z** | 4625 | 80214 | `198.51.100.55` | `LAB\lab_user_test` | LogonType 3 failure; Status `0xc000006d`, SubStatus `0xc000006a` | `DET-01-PRIM` |
| **2026-09-16T02:00:20.500Z** | 4625 | 80215 | `198.51.100.55` | `LAB\lab_user_test` | LogonType 3 failure; Status `0xc000006d`, SubStatus `0xc000006a` (Threshold reached: 5/5) | `DET-01-PRIM` |
| **2026-09-16T02:00:35.840Z** | 4624 | 80216 | `198.51.100.55` | `LAB\lab_user_test` | LogonType 3 success; Authentication Package: NTLM V2; Elevated token assigned | `DET-02-PRIM`<br>**`CORR-01` (CRITICAL)** |
| **2026-09-16T02:01:00.150Z** | 1 | 90020 | `LAB\lab_user_test` | `powershell.exe` | Parent: `services.exe`; CLI: `powershell.exe -EncodedCommand VwByAGkAdABl...` | **`DET-03` (HIGH)** |
| **2026-09-16T02:01:35.400Z** | 5140 | 90030 | `198.51.100.55` | `\\*\ADMIN$` | ShareName: `\\*\ADMIN$`, AccessMask: `0x1` (ReadData/ListDirectory) | **`DET-04` (HIGH)** |
| **2026-09-16T02:01:50.620Z** | 3 | 90031 | `198.51.100.55` | Port 445 | Process: `cmd.exe`; DestinationPort: `445` (`microsoft-ds`) | **`DET-04` (HIGH)** |

---

## 4. In-Depth Artifact Analysis

### 4.1 Authentication Analysis (Stage 1 & 2)
* **Logon Failure Signature:** Five consecutive Event 4625 entries within 20.5 seconds ($20.5\text{s} \ll 300\text{s}$ window). All records indicate `LogonType: 3` (Network Logon) and `WorkstationName: ATTACK-STATION`.
* **Breach Signature:** Event 4624 Record 80216 occurred 15.3 seconds after the final failure. Identical `IpAddress` (`198.51.100.55`) and `TargetUserName` (`lab_user_test`) confirmed a successful password breach.

### 4.2 Obfuscated Execution Deconstruction (Stage 3)
* **Sysmon Event ID 1 Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Raw Command Line:**
  ```text
  powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMAdABhAGcAZQAgADMAIABEAGkAcwBjAG8AdgBlAHIAeQAnADsAIABoAG8AcwB0AG4AYQBtAGUA
  ```
* **Decoded Payload (Unicode UTF-16LE):**
  ```powershell
  Write-Output 'Stage 3 Discovery'; hostname
  ```
* **Investigator Findings:** The payload represents classic host reconnaissance commonly observed immediately following Initial Access (`TA0001`).

### 4.3 Lateral Movement & Share Access (Stage 4)
* **Security Event ID 5140 Record 90030:**
  * `ShareName`: `\\*\ADMIN$`
  * `SubjectUserName`: `lab_user_test`
  * `AccessMask`: `0x1`
* **Sysmon Event ID 3 Record 90031:**
  * `DestinationPort`: `445`
  * `RuleName`: `technique_id=T1021.002,technique_name=SMB`
* **Investigator Findings:** The attacker attempted administrative share mapping (`net use \\LAB-HOST01\ADMIN$`) to prepare for remote service installation or binary drop.

---

## 5. Root Cause & Threat Actor Attribution

### 5.1 Root Cause
1. **Weak Credential Hygiene:** The account `lab_user_test` utilized a predictable dictionary-based password vulnerable to online guessing.
2. **Absence of Account Lockout Policy:** The operating system did not lock the account after 3–5 invalid attempts, permitting sustained online guessing.
3. **Over-Privileged Workstation Profile:** The user account possessed administrative rights permitting `ADMIN$` and `C$` access.

### 5.2 Attribution Profile
* **Attributed Group:** `APT-LAB-01`
* **Observed TTPs:** Password Guessing (`T1110.001`), Valid Accounts (`T1078.003`), PowerShell Execution (`T1059.001`), Obfuscation (`T1027`), SMB Admin Shares (`T1021.002`).

---

## 6. Containment, Eradication & Hardening Recommendations

| Level | Action Item | Target Mechanism | Priority |
| :--- | :--- | :--- | :---: |
| **Tactical** | Enforce Account Lockout Policy (Lock after 5 attempts for 15m) | GPO: `Account lockout threshold` | Immediate |
| **Tactical** | Invalidate all active Kerberos TGTs and reset `lab_user_test` password | Active Directory / Local Users | Immediate |
| **Strategic** | Deploy Microsoft LAPS to randomize local administrator passwords | LAPS GPO | High |
| **Strategic** | Block workstation-to-workstation SMB (Port 445) via host firewall | Windows Defender Firewall GPO | High |
| **Detection** | Keep `CORR-01` active at `level: critical` as primary SOC escalation trigger | SIEM / Sentinel Scheduled Rule | Sustained |
