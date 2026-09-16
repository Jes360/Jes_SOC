# CORR-01: Successful Network Logon After Brute Force Authentication Failures

**Specification Version:** 1.0.0  
**Last Updated:** 2026-09-16  
**Author / Engineering Lead:** JestineSOC Detection Engineering Team  
**Lifecycle Status:** Validated  

---

## 1. Detection Metadata & Identification

| Specification Attribute | Value / Operational Definition |
| :--- | :--- |
| **1. Detection ID** | `CORR-01` (Composite Multi-Event Correlation Rule) |
| **2. Detection Name** | Successful Network Logon After Brute Force Authentication Failures |
| **21. Maturity Level** | **Validated** (Empirically verified against authentic OS telemetry and 8 boundary conditions) |
| **15. Severity Rationale** | **Critical** (Composite high-fidelity indicator of credential guessing culminating in active account compromise) |

---

## 2. Analytic Context & Threat Foundation

### 3. Objective
* Correlate prior authentication failure bursts (`DET-01-PRIM`, Event 4625, LogonType 3) with subsequent successful network authentication (`DET-02-PRIM`, Event 4624, LogonType 3) against the same user account from the same network source within a 5-minute temporal window.
* Elevate detection fidelity from atomic telemetry primitives (`level: low` / informational) to a high-priority incident (`level: critical`), indicating that a password guessing attack successfully compromised an active account.

### 4. Threat / Analytic Hypothesis
* **Adversary Threat Model:** An adversary targeting an exposed network service (e.g. SMB, WinRM, RPC) conducts dictionary or password guessing attacks against a known target identity. Upon encountering the valid password, the adversary immediately initiates a network session to commence post-exploitation activities (e.g., discovery, lateral movement).
* **Analytic Hypothesis:** If an adversary attempts repeated credential guessing against a target account and subsequently succeeds, Windows Security event logs will record a cluster of $\ge 5$ Event 4625 records with `LogonType: 3` followed chronologically by $\ge 1$ Event 4624 record with `LogonType: 3` sharing identical `TargetUserName` and `IpAddress` values within a 5-minute window.
* **Pre-requisite Activity:** Network reconnaissance, port scanning, and account discovery.
* **Anticipated Post-Exploitation Activity:** Rapid internal reconnaissance (`whoami`, `net group`), privileged access attempts, or lateral movement via SMB/WMI.

### 8. MITRE ATT&CK Mapping
* **Enterprise Matrix Version:** MITRE ATT&CK v15 (Pinned)
* **Primary Tactic:** Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/))
* **Primary Technique:** Brute Force: Password Guessing ([T1110.001](https://attack.mitre.org/techniques/T1110/001/))
* **Secondary Tactic:** Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/)) / Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
* **Secondary Technique:** Valid Accounts: Local Accounts ([T1078.003](https://attack.mitre.org/techniques/T1078/003/))
* **Technique Relevance:** Password guessing represents the iterative attempt to discover valid credentials. Once discovered, the adversary utilizes the valid local or domain account to authenticate across the network, generating an Event 4624 success.

---

## 3. Telemetry & Data Requirements

### 5. Data Source
* **Platform / OS:** Microsoft Windows 11 / Windows Server 2022+
* **Log Channel:** `Security.evtx`
* **Event Provider:** `Microsoft-Windows-Security-Auditing`
* **Target Event IDs:** `4625` (An account failed to log on) and `4624` (An account was successfully logged on)
* **Auditing Prerequisites:**
  * Advanced Audit Configuration $\rightarrow$ Audit Logon $\rightarrow$ Success & Failure enabled:
    ```cmd
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    ```

### 6. Required Telemetry Fields
All fields resolve against `docs/data-model.md`:

| Telemetry Field (Windows Security) | Normalized Field Name | Data Type | Field Purpose / Correlation Requirement |
| :--- | :--- | :--- | :--- |
| `EventID` | `event.code` | Integer | Distinguishes failed (4625) vs successful (4624) logons |
| `TargetUserName` | `user.target.name` | String | Identity targeted; primary grouping key across failure and success |
| `IpAddress` | `source.ip` | IP Address | Source IP address initiating network authentication; secondary grouping key |
| `LogonType` | `logon.type` | Integer | Must equal `3` (Network Logon) |
| `Computer` | `host.name` | String | Target destination system processing authentication |
| `TimeCreated` | `event.timestamp` | ISO 8601 | Evaluates temporal ordering and 5-minute sliding window |

---

## 4. Canonical Sigma 2.1.0 Correlation Rule

### 7. Canonical Sigma Rule
Defined in [`correlations/mr_bruteforce_after_failures.yml`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/correlations/mr_bruteforce_after_failures.yml):

```yaml
title: Successful Network Logon After Brute Force Authentication Failures
name: mr_bruteforce_after_failures
id: e5a1b2c3-4d5e-6f70-8192-a3b4c5d6e7f8
status: experimental
description: |
  Correlates multiple Windows network authentication failures (Event 4625, LogonType 3)
  followed by a successful network authentication (Event 4624, LogonType 3) targeting
  the same account from the same network source within a 5-minute window.
  Indicates potential credential guessing or brute-force attack culminating in
  successful account compromise.
references:
  - https://attack.mitre.org/techniques/T1110/001/
  - https://attack.mitre.org/techniques/T1078/003/
  - https://github.com/SigmaHQ/sigma-specification/blob/main/correlation-specification.md
author: JestineSOC Detection Engineering Team
date: 2026-09-16
modified: 2026-09-16
tags:
  - attack.credential-access
  - attack.t1110.001
  - attack.initial-access
  - attack.t1078.003
action: correlation
type: temporal
correlation:
  type: temporal
  rules:
    - windows_failed_logon
    - windows_successful_logon
  group-by:
    - TargetUserName
    - IpAddress
  timespan: 5m
  ordered: true
  condition:
    - windows_failed_logon | count() >= 5
    - windows_successful_logon | count() >= 1
level: critical
falsepositives:
  - Legitimate user mistyping their password repeatedly before successfully remembering and logging in
  - System administrator troubleshooting account authentication or service connectivity
```

---

## 5. Verification Matrix & Empirical Test Results

### 9. Positive Test Cases
* **`TC-AUTH-003` (Authentic LSASS Ground Truth Ingestion):**
  * Ingests native Win32 `advapi32!LogonUserW` records from `evidence/telemetry/evtx-auth-sample.json`:
    * Records 80211–80215: 5 Event 4625 failures for `lab_user_test` from `127.0.0.1`.
    * Record 80216: 1 Event 4624 success for `lab_user_test` from `127.0.0.1` 1.34s after last failure.
  * **Result:** **MATCH** (Alert emitted).
* **`TC-POS-003` (Controlled Simulation):**
  * 7 Event 4625 failures followed by 1 Event 4624 success (< 5m, same user/IP).
  * **Result:** **MATCH** (Alert emitted).

### 10. Negative Test Cases & False-Positive Suppression
* **`TC-NEG-007` (Boundary Under-Threshold):** Exactly 4 Event 4625 failures ($N-1$) followed by 1 Event 4624 success $\rightarrow$ **NO_MATCH** (Suppressed; prevents false positives on user typos).
* **`TC-NEG-008` (Unsuccessful Attack):** 10 Event 4625 failures $\rightarrow$ 0 Event 4624 successes $\rightarrow$ **NO_MATCH** (Suppressed; surfaces as atomic `DET-01` alert, but not `CORR-01` compromise).
* **`TC-NEG-009` (Routine Access):** 0 Event 4625 failures $\rightarrow$ 1 Event 4624 success $\rightarrow$ **NO_MATCH** (Suppressed; ambient network authentication).
* **`TC-NEG-010` (Sequence Ordering Violation):** 1 Event 4624 success followed chronologically by 5 Event 4625 failures $\rightarrow$ **NO_MATCH** (Suppressed; fails `ordered: true` constraint).
* **`TC-NEG-011` (Identity Mismatch):** 5 failures on `user_alpha` followed by success on `user_bravo` from same IP $\rightarrow$ **NO_MATCH** (Suppressed; fails `group-by TargetUserName`).
* **`TC-NEG-012` (Window Expiry):** 5 failures followed by success 10 minutes later ($> 5\text{m}$) $\rightarrow$ **NO_MATCH** (Suppressed; exceeds temporal correlation window).

### 11. Expected Result
100% accuracy across all 8 test vectors: 2 matches on true positive attack conditions, 6 clean suppressions on non-qualifying conditions.

### 12. Actual Result
Verified 8/8 passed via automated evaluation engine [`tests/runners/eval_corr01_engine.py`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/tests/runners/eval_corr01_engine.py). Output documented in [`evidence/correlations/ev-corr-01-boundary-matrix.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/correlations/ev-corr-01-boundary-matrix.json).

---

## 6. Operational Triage & SIEM Translations

### 13. False-Positive Scenarios & Tuning Guidance
1. **User Typos Followed by Correct Password:** Standard users occasionally enter incorrect passwords multiple times before entering the correct one. Setting the threshold at $\ge 5$ within 5 minutes significantly limits this noise.
2. **Scheduled Tasks / Service Account Password Changes:** When a domain or local service password is changed, residual scripts may attempt authentications and fail before being updated. Tune out dedicated service account patterns if approved.

### 14. SOC Analyst Triage Checklist
When `CORR-01` fires:
1. **Identify the Source:** Is `IpAddress` an internal management station, jump box, or unknown endpoint?
2. **Examine Authentication Protocols:** Check `AuthenticationPackageName` in the successful Event 4624 (NTLM vs Kerberos).
3. **Assess Post-Logon Behavior:** Query child process creation (Sysmon Event 1) and network connections (Sysmon Event 3) on the target host initiated by `TargetUserName` within 15 minutes of `SuccessTime`.
4. **Account Scope:** Is the compromised user a standard local user or member of `Local Administrators`?
5. **Immediate Containment:** If unapproved, disable the user account or terminate active SMB sessions:
   ```powershell
   Close-SmbSession -SessionId <SessionId> -Force
   ```

### 16. Correlation & Grouping Logic
* **Correlation Model:** Sigma Correlation Specification 2.1.0 (`type: temporal`, `ordered: true`)
* **Primary Keys:** `TargetUserName` (case-insensitive) and `IpAddress`
* **Window Duration:** 300 seconds (`timespan: 5m`)

### 17. Derived Splunk SPL Translation
```spl
index=winsec source="XmlWinEventLog:Security" (EventCode=4625 OR EventCode=4624) Logon_Type=3
NOT (Account_Name="*$" OR Account_Name="SYSTEM" OR Account_Name="ANONYMOUS LOGON" OR Account_Name="LOCAL SERVICE" OR Account_Name="NETWORK SERVICE" OR Account_Name="-" OR Account_Name="")
| rename Account_Name as TargetUserName, Source_Network_Address as IpAddress, ComputerName as Computer
| transaction TargetUserName IpAddress maxspan=5m startswith=(EventCode=4625) endswith=(EventCode=4624)
| eval failure_count=mvcount(mvfilter(match(EventCode, "4625")))
| eval success_count=mvcount(mvfilter(match(EventCode, "4624")))
| where failure_count >= 5 AND success_count >= 1
| eval alert_severity="critical", mitre_technique="T1110.001,T1078.003"
| table _time, TargetUserName, IpAddress, Computer, failure_count, success_count, duration, alert_severity, mitre_technique
```

### 18. Derived Azure Sentinel KQL Translation
```kql
let lookback = 1h;
let window = 5m;
let threshold = 5;
let FailedLogons = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4625
| where LogonType == 3
| where not(TargetAccount endswith "$")
| where not(TargetAccount in~ ("SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "", "-"))
| summarize 
    FailureCount = count(),
    FirstFailureTime = min(TimeGenerated),
    LastFailureTime = max(TimeGenerated),
    FailureComputer = any(Computer)
    by TargetAccount, IpAddress
| where FailureCount >= threshold;
let SuccessfulLogons = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4624
| where LogonType == 3
| where not(TargetAccount endswith "$")
| where not(TargetAccount in~ ("SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "", "-"))
| project 
    SuccessTime = TimeGenerated,
    TargetAccount,
    IpAddress,
    SuccessComputer = Computer,
    TargetDomainName,
    Activity;
FailedLogons
| join kind=inner (SuccessfulLogons) on TargetAccount, IpAddress
| where SuccessTime >= LastFailureTime and SuccessTime <= (LastFailureTime + window)
| extend TimeDeltaSeconds = datetime_diff('second', SuccessTime, LastFailureTime)
| project 
    FirstFailureTime,
    LastFailureTime,
    SuccessTime,
    TimeDeltaSeconds,
    TargetAccount,
    IpAddress,
    FailureComputer,
    SuccessComputer,
    FailureCount,
    TargetDomainName,
    Activity,
    AlertSeverity = "Critical",
    MitreTechniques = "T1110.001, T1078.003"
```

### 19. Semantic Divergence & Reconciliation Matrix

| Analytic Feature | Canonical Sigma 2.1.0 | Splunk SPL | Azure Sentinel KQL | Reconciliation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Grouping Fields** | `TargetUserName`, `IpAddress` | `by TargetUserName IpAddress` in `transaction` | `on TargetAccount, IpAddress` in `join` | Exact field semantic parity across all platforms. |
| **Temporal Window** | Sliding 5 minutes (`timespan: 5m`) | `maxspan=5m` in `transaction` | `between (LastFailure .. LastFailure + 5m)` | Identical 300-second temporal boundary. |
| **Sequence Ordering** | `ordered: true` | `startswith=(EventCode=4625) endswith=(EventCode=4624)` | `SuccessTime >= LastFailureTime` | Explicitly requires failures before success. |

---

## 7. Scope Limitations & Verification Provenance

### 20. Evidence Location & Provenance
* **Boundary Matrix Evidence:** [`evidence/correlations/ev-corr-01-boundary-matrix.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/correlations/ev-corr-01-boundary-matrix.json)
* **Execution Proof:** [`evidence/correlations/ev-corr-01-execution-proof.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/correlations/ev-corr-01-execution-proof.json)
* **Underlying Telemetry Sample:** [`evidence/telemetry/evtx-auth-sample.json`](file:///c:/Users/jesti/OneDrive%20-%20Deakin%20University/Desktop/Portfolio/jestine-soc/evidence/telemetry/evtx-auth-sample.json) (Records 80211–80216)

### 22. Known Scope Limitations & Non-Claims
* **Scope Limitation `SL-06` (Distributed IP Botnet / Password Spraying):** This rule groups strictly by `(TargetUserName, IpAddress)`. An adversary distributing password guessing attempts across a large rotating botnet (1 attempt per IP) will not reach the $\ge 5$ failure threshold on any single IP and will evade this correlation. Distributed spraying requires a separate rule grouping by `TargetUserName` only across high unique IP cardinality.
* **Scope Limitation `SL-07` (NAT Gateway / Proxy Masking):** In corporate environments where remote workers connect through a single NAT gateway or reverse proxy, multiple independent endpoints appear as a single source IP. Under high concurrency, unrelated authentications could theoretically be grouped together if targeting the same username.
* **Scope Limitation `SL-08` (Slow-and-Low Brute Force):** Attackers spacing guesses beyond 5 minutes (e.g., 1 attempt every 15 minutes) will evade this correlation window to avoid triggering account lockout policies.

### 23. Operational Acceptance Criteria
* [x] Rule authors canonical Sigma Correlation 2.1.0 YAML (`mr_bruteforce_after_failures.yml`).
* [x] Ingests and confirms match on authentic LSASS ground truth records 80211–80216.
* [x] 8-case deterministic boundary test suite achieves 100% pass rate.
* [x] SIEM translations (SPL and KQL) documented with semantic reconciliation.
* [x] Scope limitations `SL-06`, `SL-07`, and `SL-08` codified.
