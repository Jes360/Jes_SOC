# DET-03: Suspicious Encoded PowerShell Execution

**Specification Version:** 1.0.0  
**Last Updated:** 2026-09-16  
**Author / Engineering Lead:** JestineSOC Detection Engineering Team  
**Lifecycle Status:** Validated  

---

## 1. Detection Metadata & Identification

| Specification Attribute | Value / Operational Definition |
| :--- | :--- |
| **1. Detection ID** | `DET-03` |
| **2. Detection Name** | Suspicious Encoded PowerShell Execution |
| **21. Maturity Level** | **Validated** (Empirically verified against authentic Sysmon Event 1 telemetry and 7 boundary conditions) |
| **15. Severity Rationale** | **High** (Strong indicator of payload obfuscation, defense evasion, and automated script delivery) |

---

## 2. Analytic Context & Threat Foundation

### 3. Objective
* Detect instances of Windows PowerShell (`powershell.exe`) and PowerShell Core (`pwsh.exe`) launched with base64 encoded command arguments (`-EncodedCommand`, `-enc`, `-e`, etc.).
* Identify adversary attempts to obfuscate execution logic, conceal malicious command parameters, and bypass static string-matching controls during initial access, execution, and defense evasion phases.

### 4. Threat / Analytic Hypothesis
* **Adversary Threat Model:** Threat actors and automated attack frameworks (e.g. Cobalt Strike, Empire, Metasploit) routinely encode PowerShell payloads using UTF-16LE base64 encoding passed via the `-EncodedCommand` parameter. This technique allows arbitrary complex scripts to run in a single command line while avoiding character escaping issues and shielding strings from basic monitoring.
* **Analytic Hypothesis:** If an adversary or benign administrative agent executes a base64 encoded PowerShell script, Windows process creation telemetry (Sysmon Event 1 or Security Event 4688) will record `Image` resolving to `powershell.exe` or `pwsh.exe` with `CommandLine` containing one of the encoded parameter flags (`-enc`, `-encodedcommand`, `/enc`, `/encodedcommand`, `-e`, `/e`) followed by a space or equals sign.
* **Pre-requisite Activity:** Process spawning via parent process (`cmd.exe`, `explorer.exe`, `wscript.exe`, or service host).
* **Anticipated Post-Exploitation Activity:** Memory injection, internal discovery, credential theft, or network egress.

### 8. MITRE ATT&CK Mapping
* **Enterprise Matrix Version:** MITRE ATT&CK v15 (Pinned)
* **Primary Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
* **Primary Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
* **Secondary Tactic:** Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
* **Secondary Technique:** Obfuscated Files or Information ([T1027](https://attack.mitre.org/techniques/T1027/))
* **Technique Relevance:** PowerShell represents one of the most prolific execution environments in Windows. Base64 encoding parameters directly implement technique T1027 to conceal command intent.

---

## 3. Telemetry & Data Requirements

### 5. Data Source
* **Platform / OS:** Microsoft Windows 11 / Windows Server 2022+
* **Primary Log Channel:** `Microsoft-Windows-Sysmon/Operational` (Event ID 1: Process Creation)
* **Secondary Log Channel:** `Security.evtx` (Event ID 4688: A new process has been created)
* **Auditing Prerequisites:**
  * For Event 4688: Process Creation Auditing enabled + Command Line Auditing enabled via GPO:
    ```cmd
    auditpol /set /subcategory:"Process Creation" /success:enable
    ```
    Registry: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`
  * For Sysmon Event 1: Sysmon installed with XML configuration monitoring ProcessCreate events.

### 6. Required Telemetry Fields
All fields resolve against `docs/data-model.md`:

| Telemetry Field (Sysmon / Windows 4688) | Normalized Field Name | Data Type | Field Purpose / Analytic Requirement |
| :--- | :--- | :--- | :--- |
| `Image` / `NewProcessName` | `process.path` | String | Executable binary path; must match `powershell.exe` or `pwsh.exe` |
| `CommandLine` | `process.command_line` | String | Full command-line string containing encoded execution arguments |
| `ParentImage` | `process.parent.path` | String | Originating parent process spawning the PowerShell instance |
| `User` / `Account` | `user.target.name` | String | Security identity under which the process executed |
| `Computer` | `host.name` | String | Target hostname |
| `TimeCreated` / `UtcTime` | `event.timestamp` | ISO 8601 | Process execution timestamp |

---

## 4. Canonical Sigma Rule Specification

### 7. Canonical Sigma Rule
Defined in [`detections/sigma/windows_suspicious_powershell.yml`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/detections/sigma/windows_suspicious_powershell.yml):

```yaml
title: Suspicious Encoded PowerShell Execution
id: c7b3e1a2-9d8f-4c5e-8b1a-2f3e4d5c6b03
status: test
description: |
  Detects the execution of Windows PowerShell or PowerShell Core passing base64
  encoded commands via command-line flags (-EncodedCommand, -enc, -e, etc.).
  Adversaries frequently utilize encoded commands to conceal payloads and evade
  string-based command-line inspection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
author: JestineSOC Detection Engineering Team
date: 2026-09-16
modified: 2026-09-16
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense-evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName:
        - 'PowerShell.EXE'
        - 'pwsh.dll'
  selection_cli:
    - CommandLine|contains:
        - ' -EncodedCommand '
        - ' -encodedcommand '
        - ' -EncodedCommand='
        - ' -encodedcommand='
        - ' -encoded '
        - ' -encoded='
        - ' -enc '
        - ' -enc='
        - ' -e '
        - ' -e='
        - ' /EncodedCommand '
        - ' /encodedcommand '
        - ' /EncodedCommand='
        - ' /encodedcommand='
        - ' /encoded '
        - ' /encoded='
        - ' /enc '
        - ' /enc='
        - ' /e '
        - ' /e='
  condition: selection_img and selection_cli
fields:
  - CommandLine
  - Image
  - ParentImage
  - ParentCommandLine
  - User
  - Computer
falsepositives:
  - Legitimate enterprise deployment scripts or systems management agents (e.g. Microsoft Endpoint Configuration Manager, Chocolatey, Intune)
  - Administrative maintenance scripts wrapping complex commands in base64 encoding
level: high
```

---

## 5. Verification Matrix & Empirical Test Results

### 9. Positive Test Cases
* **`TC-AUTH-004` (Authentic Sysmon Ground Truth Ingestion):**
  * Source: `evidence/telemetry/sysmon-sample.json` (`ProcessGuid: {A839210F-9912-66E4-9182-0192837465FE}`)
  * Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  * CommandLine: `powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand VwByAGkAdABl...`
  * Decoded Benign Payload: `Write-Output 'JestineSOC Controlled Telemetry Test: Host Discovery'; hostname`
  * **Result:** **MATCH** (Alert emitted).
* **`TC-POS-004` (PowerShell Core Execution):**
  * Image: `C:\Program Files\PowerShell\7\pwsh.exe` with `-enc <base64>`
  * **Result:** **MATCH** (Alert emitted).
* **`TC-POS-005` (Forward-Slash Flag Delimiter):**
  * Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with `/encodedcommand=<base64>`
  * **Result:** **MATCH** (Alert emitted).

### 10. Negative Test Cases & False-Positive Suppression
* **`TC-NEG-013` (Standard Unencoded PowerShell):** `powershell.exe -NoProfile -Command Get-Process` $\rightarrow$ **NO_MATCH** (Suppressed; regular administrative execution).
* **`TC-NEG-014` (Non-PowerShell Process with `-enc` Flag):** `C:\Tools\custom_app.exe -enc data` $\rightarrow$ **NO_MATCH** (Suppressed; binary is not PowerShell).
* **`TC-NEG-015` (Non-Process Creation Telemetry):** Sysmon Event 3 Network Connection $\rightarrow$ **NO_MATCH** (Suppressed; incorrect event category).
* **`TC-NEG-016` (Command Prompt Process Creation):** `C:\Windows\System32\cmd.exe /c dir` $\rightarrow$ **NO_MATCH** (Suppressed; standard command execution).

### 11. Expected Result
100% boundary accuracy across all 7 test cases (3 matches on authentic/simulated attacks, 4 clean suppressions on non-qualifying telemetry).

### 12. Actual Result
Verified 7/7 test cases passed via automated evaluation engine [`tests/runners/eval_det03_engine.py`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/tests/runners/eval_det03_engine.py). Output documented in [`evidence/detections/ev-det-03-boundary-matrix.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/detections/ev-det-03-boundary-matrix.json).

---

## 6. Operational Triage & SIEM Translations

### 13. False-Positive Scenarios & Tuning Guidance
* **Enterprise Management Agents:** Tools like Chocolatey, Microsoft Intune, and MECM often invoke PowerShell using encoded commands. Tune by whitelisting trusted parent processes (e.g. `C:\Program Files\Microsoft Monitoring Agent\...\agent.exe`) or specific trusted code hashes.
* **Logon Scripts:** Review scheduled tasks or login scripts invoking encoded commands to determine if they can be migrated to plain `.ps1` files.

### 14. SOC Analyst Triage Checklist
When `DET-03` fires:
1. **Decode the Payload:** Immediately decode the base64 argument in a safe sandbox:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<EncodedPayload>"))
   ```
2. **Inspect Parent Process:** What spawned PowerShell? (e.g. `cmd.exe`, `wscript.exe`, `winword.exe` $\rightarrow$ High indicator of phishing/macro execution).
3. **Assess Network Activity:** Check Sysmon Event 3 for immediate network connections initiated by the process ID.
4. **Identify Child Processes:** Did the encoded PowerShell spawn `cmd.exe`, `whoami.exe`, `certutil.exe`, or `rundll32.exe`?
5. **Containment:** If malicious, isolate the host via EDR and terminate the process tree.

### 17. Derived Splunk SPL Translation
```spl
( (index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
  OR
  (index=winsec source="XmlWinEventLog:Security" EventCode=4688) )
| eval ProcessImage=coalesce(Image, NewProcessName, process_path)
| eval ProcessCommandLine=coalesce(CommandLine, Process_Command_Line, process_exec)
| where (match(ProcessImage, "(?i)[\\/](powershell|pwsh)\.exe$") OR match(ProcessCommandLine, "(?i)\b(powershell|pwsh)(\.exe)?\b"))
  AND match(ProcessCommandLine, "(?i)\s+[-/](enc|encodedcommand|encoded|e)([\s=]+|$)")
| stats min(_time) as FirstSeen max(_time) as LastSeen count by Computer, User, ProcessImage, ProcessCommandLine, ParentImage
| rename ProcessImage as Image, ProcessCommandLine as CommandLine
| eval AlertSeverity="High", MitreTechniques="T1059.001, T1027"
```

### 18. Derived Azure Sentinel KQL Translation
```kql
let lookback = 24h;
let encodedRegex = @"(?i)\s+[-/](enc|encodedcommand|encoded|e)([\s=]+|$)";
let powershellRegex = @"(?i)(powershell|pwsh)\.exe$";
let SysmonProcess = Event
| where TimeGenerated >= ago(lookback)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend ProcessCommandLine = tostring(parse_xml(EventData).Data[10]["#text"])
| extend ProcessImage = tostring(parse_xml(EventData).Data[4]["#text"])
| where ProcessImage matches regex powershellRegex
| where ProcessCommandLine matches regex encodedRegex
| project TimeGenerated, Computer, Account = UserName, Image = ProcessImage, CommandLine = ProcessCommandLine, TableSource = "Sysmon_Event1";
let Security4688 = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4688
| where NewProcessName matches regex powershellRegex
| where CommandLine matches regex encodedRegex
| project TimeGenerated, Computer, Account, Image = NewProcessName, CommandLine, TableSource = "Security_4688";
union isfuzzy=true SysmonProcess, Security4688
| summarize min(TimeGenerated), max(TimeGenerated), count() by Computer, Account, Image, CommandLine, TableSource
| extend AlertSeverity = "High", MitreTechniques = "T1059.001, T1027"
```

### 19. Semantic Reconciliation Matrix

| Feature | Canonical Sigma | Splunk SPL | Azure Sentinel KQL | Reconciliation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Image Resolution** | `Image\|endswith: '\powershell.exe'` | `match(ProcessImage, "(?i)...")` | `NewProcessName matches regex ...` | Case-insensitive regular expression matching `powershell.exe` and `pwsh.exe`. |
| **Argument Matching** | Multiple string contains checks (`-enc `, etc.) | Regex `\s+[-/](enc\|encodedcommand\|...)([\s=]+\|$)` | Regex `\s+[-/](enc\|encodedcommand\|...)([\s=]+\|$)` | Regex unifies space and equals delimiters across both platforms. |
| **Multi-Source Support** | Windows Process Creation category | Unions Sysmon 1 and Security 4688 | Unions Sysmon 1 and Security 4688 | Native multi-source coverage. |

---

## 7. Scope Limitations & Verification Provenance

### 20. Evidence Location & Provenance
* **Boundary Matrix Evidence:** [`evidence/detections/ev-det-03-boundary-matrix.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/detections/ev-det-03-boundary-matrix.json)
* **Execution Proof:** [`evidence/detections/ev-det-03-execution-proof.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/detections/ev-det-03-execution-proof.json)
* **Underlying Telemetry Sample:** [`evidence/telemetry/sysmon-sample.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/telemetry/sysmon-sample.json) (`ProcessGuid: {A839210F-9912-66E4-9182-0192837465FE}`)

### 22. Known Scope Limitations & Non-Claims
* **Scope Limitation `SL-09` (Unencoded Execution / Script Block Logging Scope):** DET-03 inspects command-line arguments at process launch. If an adversary executes an unencoded command or downloads code directly into memory without passing `-enc` (e.g. `IEX (New-Object Net.WebClient)...`), DET-03 will not fire. Detecting such activity requires PowerShell Script Block Logging (Event ID `4104`).
* **Scope Limitation `SL-10` (Unmanaged PowerShell / Process Injection):** Adversaries employing unmanaged PowerShell execution (e.g., executing PowerShell commands inside an arbitrary C# assembly without invoking `powershell.exe`) will not generate a PowerShell Process Creation event and evade DET-03.
* **Scope Limitation `SL-11` (Whitespace & Delimiter Evasion):** Adversaries utilizing non-standard parameter formatting (e.g. `-e:`, `-e""`, or tab-separated parameters) may evade naive string-containment rules. The derived regexes partially mitigate this by matching `[\s=]+`, but non-standard delimiters remain a known detection boundary.

### 23. Operational Acceptance Criteria
* [x] Canonical Sigma rule created (`windows_suspicious_powershell.yml`).
* [x] Evaluates and matches authentic Sysmon Event 1 telemetry (`TC-AUTH-004`).
* [x] 7-case deterministic boundary test suite achieves 100% pass rate.
* [x] Strictly benign telemetry generator implemented (`gen-powershell-events.ps1`).
* [x] Scope limitations `SL-09`, `SL-10`, and `SL-11` documented.
