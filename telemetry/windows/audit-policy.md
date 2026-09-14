# Windows Security Audit Policy Specification

**Document ID:** POL-WIN-AUDIT  
**Version:** v0.1.0  
**Requirement Mapping:** FR-01, NFR-01  

---

## 1. Objective & Telemetry Rationale

To detect authentication attacks (brute force, credential guessing, lateral movement) and process execution without relying on synthetic event fabrication, the Windows Local Security Authority Subsystem Service (LSASS) and kernel auditing engine must be configured to record security events to the `Security` event log (`C:\Windows\System32\Winevt\Logs\Security.evtx`).

This document defines the mandatory Advanced Audit Policy Configuration required by JestineSOC.

---

## 2. Required Audit Policy Matrix

| Audit Category | Audit Subcategory | Success | Failure | Resulting Event IDs | Security Value |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Logon/Logoff** | `Logon` | **Enable** | **Enable** | **Event 4624** (Success)<br>**Event 4625** (Failure) | Captures logon attempts, authentic logon types (2, 3, 10), source workstation, and client IP address. |
| **Account Logon** | `Credential Validation` | **Enable** | **Enable** | **Event 4776** (NTLM validation)<br>**Event 4625** (Failure) | Validates credentials against SAM or domain database; provides error status codes (`0xC000006A`). |
| **Detailed Tracking** | `Process Creation` | **Enable** | **Disable** | **Event 4688** (Process Creation) | Provides native operating system process execution telemetry with parent and command-line fields. |

---

## 3. Configuration Verification & Enforcement

Run an elevated Administrator PowerShell session to verify and enforce these policies:

### 3.1 Verification (Check Current State)
```powershell
# Check current configuration for Logon, Credential Validation, and Process Creation
auditpol /get /subcategory:"Logon","Credential Validation","Process Creation"
```

### 3.2 Policy Enforcement Commands
```powershell
# 1. Enable Logon Auditing (Events 4624 and 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# 2. Enable Credential Validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# 3. Enable Process Creation Auditing (Event 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

# 4. Enable Command Line in Event 4688
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## 4. Expected Event Log Structures

### 4.1 Event ID 4625: An account failed to log on
* **Keywords:** `Audit Failure`
* **Channel:** `Security`
* **Critical Fields to Inspect:**
  * `SubjectUserSid`: Identifies context initiating the logon.
  * `TargetUserName`: Target account subject to the authentication attempt.
  * `TargetDomainName`: Domain or host context.
  * `Status`: NTSTATUS general failure code.
  * `SubStatus`: Detailed reason code (e.g. `0xC000006A` = User name is valid, but password is bad; `0xC0000064` = User does not exist).
  * `LogonType`: Numeric logon type (`2` = Interactive, `3` = Network, `10` = RemoteInteractive/RDP).
  * `WorkstationName`: Client workstation name.
  * `IpAddress`: Source IP address initiating request.

### 4.2 Event ID 4624: An account was successfully logged on
* **Keywords:** `Audit Success`
* **Channel:** `Security`
* **Critical Fields to Inspect:**
  * `TargetUserName`: Account successfully authenticated.
  * `TargetDomainName`: Authenticating authority.
  * `LogonType`: Authentication type.
  * `LogonGuid`: Unique session identifier for correlating subsequent session activity.
  * `WorkstationName`: Calling machine name.
  * `IpAddress`: Calling IP address.
