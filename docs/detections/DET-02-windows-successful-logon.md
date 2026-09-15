# DET-02: Windows Network Authentication Success (Valid Account Network Logon Primitive)

**Specification Version:** 1.0.0  
**Last Updated:** 2026-09-15  
**Author / Engineering Lead:** JestineSOC Detection Engineering Team  
**Lifecycle Status:** Functional (Awaiting Empirical Test Promotion to Validated)  

---

## 1. Detection Metadata & Identification

| Specification Attribute | Value / Operational Definition |
| :--- | :--- |
| **1. Detection ID** | `DET-02` (Atomic Telemetry & Correlation Primitive: `DET-02-PRIM`) |
| **2. Detection Name** | Windows Network Authentication Success (Valid Account Network Logon) |
| **21. Maturity Level** | `Functional` (Syntax verified by `sigma check` & `yamllint`; tested against authentic OS ground truth `evtx-auth-sample.json` RecordId 80216) |
| **15. Severity Rationale** | `Low` / `Informational` (Classified as a high-volume telemetry primitive per Guardrail 1; standalone alerts would flood SOC triage queues; escalates to `Critical` when chained with `DET-01` in `CORR-01`) |

---

## 2. Analytic Context & Threat Foundation

### 3. Objective
Capture individual successful Windows network authentication events (Event 4624, LogonType = 3) targeting non-machine and non-system accounts. Serves as the critical success telemetry primitive (`DET-02-PRIM`) feeding multi-stage correlation engines (`CORR-01` / `mr_bruteforce_after_failures.yml`) to detect account compromise, unauthorized remote service access, and lateral movement.

### 4. Threat / Analytic Hypothesis
* **Adversary Threat Model:**
  After acquiring valid credentials (via online brute-forcing, password spraying, phishing, or credential dumping), adversaries authenticate to remote systems via network logon protocols (LogonType = 3: SMB, RPC, WinRM) to achieve initial access, persistence, or lateral movement across domain boundaries.
* **Analytic Hypothesis:**
  *If* an adversary successfully authenticates using valid credentials across the network,  
  *then* the Windows Local Security Authority Subsystem Service (LSASS) will emit an Event 4624 record with `LogonType = 3` and audit status success,  
  *distinguishable from machine noise* by filtering computer accounts (`*$`) and well-known system service identities (`SYSTEM`, `ANONYMOUS LOGON`, `LOCAL SERVICE`, `NETWORK SERVICE`),  
  *distinguishable from benign user activity* primarily through temporal correlation with prior authentication anomalies (e.g. preceding failed logon bursts in `DET-01`).
* **Role as Telemetry Primitive (Guardrail 1):**
  In enterprise environments, Event 4624 LogonType 3 occurs thousands of times daily from legitimate file share access, printer connections, and group policy updates. Consequently, `DET-02-PRIM` is intentionally classified at `level: low` as an atomic primitive. It is **not designed to generate standalone SOC alerts**, but rather to supply the definitive success confirmation in stateful multi-event detections.

### 8. MITRE ATT&CK Mapping
* **Enterprise Matrix Version:** MITRE ATT&CK v15 (Pinned)
* **Tactics:**
  * Initial Access (`TA0001`)
  * Persistence (`TA0003`)
  * Lateral Movement (`TA0008`)
* **Technique Name:** Valid Accounts
* **Technique ID:** `T1078`
* **Sub-Technique IDs:**
  * `T1078.003` (Valid Accounts: Local Accounts)
  * `T1078.002` (Valid Accounts: Domain Accounts)
* **Technique Justification:**
  Adversaries leverage compromised authentic credentials to access network services. The generation of Event 4624 with `LogonType = 3` directly represents the execution of network authentication using valid credentials.

---

## 3. Telemetry & Data Requirements

### 5. Data Source
* **Platform / OS:** Windows 11 / Windows Server 2022+
* **Log Channel:** `Security` (`C:\Windows\System32\Winevt\Logs\Security.evtx`)
* **Event Provider Name:** `Microsoft-Windows-Security-Auditing`
* **Target Event ID:** `4624` (An account was successfully logged on)
* **Prerequisite Auditing Policy:**
  Local Security Policy $\rightarrow$ Advanced Audit Policy Configuration $\rightarrow$ Audit Policies $\rightarrow$ Logon/Logoff $\rightarrow$ Audit Logon (`Success = Enabled`).
  Verification command: `auditpol /get /subcategory:"Logon"` must return `Success and Failure`.

### 6. Required Telemetry Fields
Fields mapped to `docs/data-model.md`:

| Telemetry Field (Security.evtx) | Normalized Field Name | Data Type | Analytic Requirement & Validation Rule |
| :--- | :--- | :--- | :--- |
| `TargetUserName` | `user.target.name` | String | Must NOT be empty, dash, or end with `$`; identifies logged-on user |
| `TargetDomainName` | `user.target.domain` | String | Machine name (local logon) or Active Directory domain name |
| `LogonType` | `logon.type` | Integer | Must equal `3` (Network logon via SMB/WinRM/RPC) |
| `WorkstationName` | `source.host.name` | String | Originating client workstation name |
| `IpAddress` | `source.ip` | IP Address | Source IP address (or `127.0.0.1` in local loopback testing) |
| `Computer` | `destination.host.name` | String | Target host system name |
| `TimeCreated` | `@timestamp` | ISO8601 | Event timestamp used for sequence correlation window |
| `LogonProcessName` | `process.logon.name` | String | Subsystem submitting logon (e.g. `Advapi  `, `Kerberos`, `NtLmSsp`) |
| `AuthenticationPackageName` | `auth.package.name` | String | Protocol package (e.g. `Negotiate`, `NTLM`, `Kerberos`) |

---

## 4. Canonical Detection Architecture (Sigma 2.1.0)

### 7. Canonical Sigma Rule: Atomic Event Primitive (`DET-02-PRIM`)
* **Rule File Location:** `detections/sigma/windows_successful_logon.yml`
* **Specification Compliance:** Sigma Specification 2.1.0

```yaml
title: Windows Network Authentication Success (Atomic Event Primitive)
name: windows_successful_logon
id: 7c8d9e0f-3a1b-4c2d-8e4f-5a6b7c8d9e02
status: experimental
description: |
    Matches individual successful Windows network authentication events (Event 4624, LogonType 3).
    Filters out computer accounts and well-known system service accounts.
    Classified as a low-severity telemetry primitive (DET-02-PRIM) intended for downstream
    correlation in 'mr_bruteforce_after_failures' (CORR-01) rather than standalone alerting.
references:
    - https://attack.mitre.org/techniques/T1078/003/
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
author: JestineSOC Detection Engineering Team
date: 2026-09-15
modified: 2026-09-15
tags:
    - attack.initial-access
    - attack.persistence
    - attack.t1078.003
    - attack.t1078.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
    filter_machine_accounts:
        TargetUserName|endswith: '$'
    filter_system_accounts:
        TargetUserName:
            - 'SYSTEM'
            - 'ANONYMOUS LOGON'
            - 'LOCAL SERVICE'
            - 'NETWORK SERVICE'
    filter_empty:
        TargetUserName:
            - ''
            - '-'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate administrative network shares (SMB) or WinRM remote sessions
    - Routine inter-system user authentication in Active Directory domains
level: low
```

### 16. Correlation & Downstream Alignment (CORR-01)
`DET-02-PRIM` is specifically architected to provide the terminal condition in composite sequence correlations:
* **Composite Rule:** `correlations/mr_bruteforce_after_failures.yml` (`CORR-01`)
* **Correlation Paradigm:** Temporal sequence correlation
* **Condition:** $\ge 5$ events matching `windows_failed_logon` (`DET-01-PRIM`) followed within 5 minutes by $\ge 1$ event matching `windows_successful_logon` (`DET-02-PRIM`)
* **Binding Keys:** `TargetUserName` AND `IpAddress` AND `Computer`
* **Analytic Meaning:** Elevates from ambient baseline to `Critical` incident because successful logon immediately follows an aggressive brute-force attempt from the same origin.

---

## 5. Derived SIEM Implementations & Semantic Reconciliation

### 17. SPL (Splunk Search Processing Language) Translation
* **Target Index / Sourcetype:** `index=security sourcetype=WinEventLog:Security`
* **Translation File:** `detections/splunk/windows_successful_logon.spl`

```spl
# Detection: Windows Network Authentication Success (DET-02-PRIM)
# Canonical Source: detections/sigma/windows_successful_logon.yml
index=security sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
    NOT TargetUserName="*$"
    NOT TargetUserName IN ("SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "", "-")
| table _time, TargetUserName, TargetDomainName, IpAddress, WorkstationName, Computer, Logon_Type
```

### 18. KQL (Microsoft Sentinel / Defender Kusto Query) Translation
* **Target Table:** `SecurityEvent`
* **Translation File:** `detections/kql/windows_successful_logon.kql`

```kql
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4624
| where LogonType == 3
| where not(TargetAccount endswith "$")
| where not(TargetAccount in~ ("SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "", "-"))
| project TimeGenerated, TargetAccount, TargetDomainName, IpAddress, WorkstationName, Computer, LogonType, Activity
```

### 19. Semantic Reconciliation Matrix
The following matrix resolves dialect mappings and filtering behavior for `DET-02`:

| Requirement | Canonical Sigma (`DET-02-PRIM`) | Splunk SPL Translation | Microsoft Sentinel KQL Translation |
| :--- | :--- | :--- | :--- |
| **Event 4624** | ✓ (`EventID: 4624`) | ✓ (`EventCode=4624`) | ✓ (`EventID == 4624`) |
| **LogonType 3** | ✓ (`LogonType: 3`) | ✓ (`Logon_Type=3`) | ✓ (`LogonType == 3`) |
| **Machine Account Filter** | ✓ (`TargetUserName\|endswith: '$'`) | ✓ (`NOT TargetUserName="*$"`) | ✓ (`not(TargetAccount endswith "$")`) |
| **System Account Filter** | ✓ (`SYSTEM`, `ANONYMOUS LOGON`, etc.) | ✓ (`NOT TargetUserName IN (...)`) | ✓ (`not(TargetAccount in~ (...))`) |
| **Case Sensitivity** | Case-insensitive in Sigma backend | Case-insensitive field comparison | Case-insensitive (`in~`) |
| **Operational Role** | Correlation Primitive | Telemetry Search / Hunting Subquery | Hunting Query / Analytics Rule Component |

---

## 6. Testing, Verification & Boundary Evidence

### 9. Positive Test Case (Authentic Ground Truth Ingestion)
* **`TC-AUTH-002` (Phase 1 Authentic OS Telemetry Ingestion):**
  - Data Source: `evidence/telemetry/evtx-auth-sample.json`
  - Ingested Event: `RecordId: 80216` (emitted by native Win32 `advapi32.dll LogonUserW` into LSASS)
  - Event Attributes: `EventID: 4624`, `LogonType: 3`, `TargetUserName: "lab_user_test"`, `IpAddress: "127.0.0.1"`
  - Expected Result: **QUALIFIES / MATCHES** as valid primitive event.
* **`TC-POS-002` (Controlled Network Success Simulation):**
  - Command: `.\telemetry\generators\gen-auth-events.ps1 -TargetUser "lab_user_test" -FailureCount 0 -TriggerSuccess`
  - Expected Result: **MATCHES** `DET-02-PRIM` criteria.

### 10. Negative Test Cases (Benign Noise & Filter Suppression)
* **`TC-NEG-001` (Failed Logon Rejection):** Event 4625 records (`RecordId: 80211-80215`) $\rightarrow$ Rejected (incorrect EventID).
* **`TC-NEG-002` (Interactive Logon Rejection):** Event 4624 with `LogonType = 2` (Interactive console logon) $\rightarrow$ Rejected (LogonType $\ne 3$).
* **`TC-NEG-003` (Machine Account Exclusion):** Event 4624 with `TargetUserName = "LAB-SRV01$"` $\rightarrow$ Suppressed by `filter_machine_accounts`.
* **`TC-NEG-004` (System Account Exclusion):** Event 4624 with `TargetUserName = "SYSTEM"` $\rightarrow$ Suppressed by `filter_system_accounts`.
* **`TC-NEG-005` (Anonymous Logon Exclusion):** Event 4624 with `TargetUserName = "ANONYMOUS LOGON"` $\rightarrow$ Suppressed by `filter_system_accounts`.
* **`TC-NEG-006` (Local Service Exclusion):** Event 4624 with `TargetUserName = "LOCAL SERVICE"` $\rightarrow$ Suppressed by `filter_system_accounts`.

### 11. Boundary Test Matrix Results
Automated execution results generated by `tests/runners/eval_det02_engine.py` and recorded in `evidence/detections/ev-det-02-boundary-matrix.json`:

| Test ID | Case ID | Category | Event Details | Expected State | Actual State | Verdict | Boundary Condition Tested |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `AUTH-002` | `TC-AUTH-002` | Authentic Ingestion | Event 4624, LogonType 3 (`RecordId: 80216`) | `MATCH` | `MATCH` | ✅ PASS | Genuine Win32 LSASS network logon record matches primitive |
| `POS-002` | `TC-POS-002` | Controlled Simulation | Event 4624, LogonType 3 (`lab_user_test`) | `MATCH` | `MATCH` | ✅ PASS | Standard valid network logon qualifies |
| `NEG-001` | `TC-NEG-001` | Channel / ID Filter | Event 4625, LogonType 3 (`RecordId: 80211-80215`) | `NO_MATCH` | `NO_MATCH` | ✅ PASS | Failed logon records correctly rejected by DET-02 |
| `NEG-002` | `TC-NEG-002` | LogonType Filter | Event 4624, LogonType 2 (Interactive) | `NO_MATCH` | `NO_MATCH` | ✅ PASS | Interactive console logins rejected (network logon boundary) |
| `NEG-003` | `TC-NEG-003` | Machine Filter | Event 4624, LogonType 3 (`LAB-SRV01$`) | `NO_MATCH` | `NO_MATCH` | ✅ PASS | Computer accounts ($ suffix) filtered |
| `NEG-004` | `TC-NEG-004` | System Filter | Event 4624, LogonType 3 (`SYSTEM`) | `NO_MATCH` | `NO_MATCH` | ✅ PASS | Built-in NT AUTHORITY\SYSTEM filtered |
| `NEG-005` | `TC-NEG-005` | Anonymous Filter | Event 4624, LogonType 3 (`ANONYMOUS LOGON`) | `NO_MATCH` | `NO_MATCH` | ✅ PASS | Anonymous network logons filtered |
| `NEG-006` | `TC-NEG-006` | Service Filter | Event 4624, LogonType 3 (`LOCAL SERVICE`) | `NO_MATCH` | `NO_MATCH` | ✅ PASS | Local system services filtered |

### 12. Actual Result & Backend Execution Proof
* **Backend Evaluation Engine:** `tests/runners/eval_det02_engine.py` (wired into `.github/workflows/validate.yml`).
* **Execution Proof Artifact:** `evidence/detections/ev-det-02-execution-proof.json` logs the programmatic verification of authentic OS records and boundary cases.
* **Empirical Pass Rate:** 8 / 8 test cases passed (100% accuracy).

### 20. Evidence Location / Provenance Chain
* **Boundary Matrix:** `evidence/detections/ev-det-02-boundary-matrix.json`
* **Execution Proof:** `evidence/detections/ev-det-02-execution-proof.json`
* **Positive Attack Evidence:** `evidence/detections/ev-det-02-positive.json`
* **Negative Benign Evidence:** `evidence/detections/ev-det-02-negative.json`
* **Raw Telemetry Ground Truth:** `evidence/telemetry/evtx-auth-sample.json` (Record 80216)

---

## 7. Operational Triage, Tuning & Engineering Boundaries

### 13. False-Positive Scenarios & Operational Noise
1. **Scenario 1 (Routine Administrative SMB Connections):**
   * *Trigger Cause:* Network administrator mounts administrative shares (`C$`, `ADMIN$`) to perform software deployments.
   * *Classification:* Legitimate business activity; handled by pairing with correlation rules rather than alerting standalone.
2. **Scenario 2 (Scheduled Tasks / Batch Jobs):**
   * *Trigger Cause:* Automated management scripts logging in across the network.
   * *Tuning:* Filter specific dedicated service accounts if known and managed under credential vaults.

### 14. Investigation Questions & SOC Triage Workflow
Structured triage path for Tier-1/Tier-2 SOC analysts when evaluating network logon successes:
1. **Contextual History:** Did this network logon follow a burst of authentication failures (`DET-01`) from the same source IP? (If yes, trigger `CORR-01` triage).
2. **Account Role:** Is `TargetUserName` a standard user, privileged administrator, or service account?
3. **Source Host:** Is `IpAddress` / `WorkstationName` a recognized corporate device, VPN endpoint, or unexpected asset?
4. **Post-Authentication Activity:** What processes were executed on the destination host within 10 minutes of logon (Sysmon Event 1)?

### 15. Severity Rationale & Scoring Formula
* **Base Severity:** `Low` / `Informational` (Reflects baseline ambient volume of routine network authentications).
* **Escalated Severity:** Elevates to `Critical` when bound within `CORR-01` (Logon failures $\rightarrow$ Logon success sequence breach).

### 22. Known Limitations & Non-Claims (Scope Limitations SL-04 and SL-05)
* **Scope Limitations (Explicit Non-Claims):**
  * **`SL-04` (Absence of Standalone Malicious Signal):** This primitive does NOT differentiate between legitimate remote administration and adversary lateral movement without contextual baseline or correlation with prior anomalous events.
  * **`SL-05` (Pass-the-Hash / Ticket Anomalies):** This primitive monitors only successful logon establishment (`EventID: 4624`); it does not detect NTLM Pass-the-Hash or Kerberos Golden Ticket generation (which requires Event 4768/4769 ticket encryption inspection).
* **Evasion Vectors:**
  * Adversaries using local interactive console logins (LogonType = 2) or RDP with RemoteFX/direct console sessions evade LogonType = 3 network filters.

### 23. Acceptance Criteria
- [x] Canonical 23-section detection specification authored and reviewed.
- [x] Canonical Sigma rule `windows_successful_logon.yml` (`DET-02-PRIM`) passes `sigma check` with 0 errors.
- [x] Rule YAML complies with `yamllint` configuration.
- [x] Evaluated against authentic OS ground truth in `evtx-auth-sample.json` (`RecordId: 80216` matches, `80211-80215` rejected).
- [x] Boundary suite `tests/test_det02_boundary_suite.ps1` executes all 8 boundary conditions with 100% pass rate.
- [x] Backend evaluation engine `tests/runners/eval_det02_engine.py` executes and outputs verified stream proof.
- [x] Derived SPL translation authored and verified.
- [x] Derived KQL translation authored and verified.
- [x] Semantic Reconciliation Matrix resolves all dialect mappings, noise filters, and field equivalences.
- [x] Raw evidence JSON captured and committed to `evidence/detections/ev-det-02-boundary-matrix.json` and `ev-det-02-execution-proof.json`.
- [x] Traceability matrix updated mapping `FR-01`, `FR-02`, and `T1078.003` to `DET-02-PRIM`.
