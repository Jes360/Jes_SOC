# JestineSOC: Laboratory Environment Specification & Reproducibility Guide

**Document ID:** ENV-V1-SPEC  
**Version:** v0.1.0  
**Classification:** Laboratory Standard  

---

## 1. Overview & Purpose

To satisfy **NFR-01 (Reproducibility)**, this document specifies the precise operating system, runtime dependencies, sensor configurations, and audit policies required to reproduce the telemetry, detections, and test suites within JestineSOC.

---

## 2. Host System & Runtime Prerequisites

| Component | Specification / Tested Version | Purpose in Lab |
| :--- | :--- | :--- |
| **Host Operating System** | Windows 10 / 11 (22H2+), x64 Architecture | Primary telemetry generation and audit event emitter |
| **Windows Edition** | Professional / Enterprise | Enables Local Security Policy (`auditpol.exe`) and advanced auditing |
| **PowerShell Runtime** | PowerShell 5.1 (Built-in) & PowerShell 7.x (Core) | Execution of attack simulations and test harness scripts |
| **Python Runtime** | Python 3.10+ (`python.exe` on system `PATH`) | CI/CD linting, Sigma validation, and automated tooling |
| **Git SCM** | Git 2.40+ (`git-scm.com`) | Version control, release tagging, and pre-commit checks |
| **Microsoft Sysmon** | Sysinternals Sysmon v15.x | Endpoint Process Creation (Event 1) and Network Connection (Event 3) |
| **Sigma CLI** | `sigma-cli` (v0.8.x+) via `pip install sigma-cli` | Canonical rule validation and target query compilation |

---

## 3. Windows Security Audit Policy Baseline

For Windows to emit Event IDs **4624** (Successful Logon), **4625** (Failed Logon), and **4688** (Process Creation), advanced audit policies must be configured.

Run an elevated Administrator PowerShell session:

```powershell
# 1. Enable Audit for Logon / Logoff (Events 4624, 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# 2. Enable Audit for Credential Validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# 3. Enable Audit for Process Creation (Event 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

# 4. Include Command Line in Event 4688 Process Creation (Optional if Sysmon is running)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

To verify current audit policy:
```powershell
auditpol /get /subcategory:"Logon"
```

---

## 4. Sysmon Installation & Configuration

Sysmon provides deep kernel telemetry that complements standard Windows Event logs.

1. **Download Sysmon:** From [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. **Install using Lab Configuration:**
   ```powershell
   sysmon64.exe -accepteula -i .\telemetry\sysmon\sysmon-config.xml
   ```
3. **Verify Sysmon Service:**
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```
4. **Teardown / Uninstall (Post-Testing):**
   ```powershell
   sysmon64.exe -u
   ```

## 5. Lab Test Accounts & Isolation Boundary

To prevent cross-contamination of personal user profiles or accidental lockouts, and in strict compliance with **NFR-02**:

> [!IMPORTANT]
> **Credential Hygiene Policy:**  
> No static passwords or credentials are committed to this repository, including laboratory test passwords. All credentials used in test execution must be entered interactively via secure prompts or generated dynamically as transient secrets during script runs.

* **Designated Test Account:** `lab_user_test`
* **Local Test Password:** Set dynamically at runtime (never hardcoded in scripts or documentation)
* **Designated Service Account:** `svc_telemetry_test`
* **Network Boundary:** All authentication requests originate locally or target localhost / loopback (`127.0.0.1`, `::1`), emitting legitimate `LogonType 2` (Interactive) or `LogonType 3` (Network) events without external routable traffic.

### Quick Account Setup Script (Elevated PowerShell):
```powershell
# Prompt interactively for temporary laboratory password
$LabPassword = Read-Host "Enter temporary lab password for lab_user_test" -AsSecureString
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($LabPassword))

# Create isolated local test account
net user lab_user_test $PlainPassword /add /comment:"JestineSOC Isolated Test Account"
net user lab_user_test /active:yes

# Clear plain text memory immediately
$PlainPassword = $null
```

### Account Teardown Script:
```powershell
net user lab_user_test /delete
```


---

## 6. Python & Sigma Environment Setup

To run automated CI checks and rule compilation locally:

```bash
# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install Sigma CLI and pySigma plugins
pip install sigma-cli pySigma pySigma-backend-splunk pySigma-backend-kql
```

To validate a Sigma rule:
```bash
sigma check .\detections\sigma\windows_failed_logon.yml
```

To compile a Sigma rule to Splunk:
```bash
sigma convert -t splunk -p sysmon .\detections\sigma\windows_failed_logon.yml
```
