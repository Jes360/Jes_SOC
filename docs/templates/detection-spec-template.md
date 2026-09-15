# [DET-ID]: [Detection Title / Descriptive Name]

**Specification Version:** 1.0.0  
**Last Updated:** [YYYY-MM-DD]  
**Author / Engineering Lead:** [Author / JestineSOC Team]  
**Lifecycle Status:** [Draft / Under Review / Approved / Deprecated]  

---

## 1. Detection Metadata & Identification

| Specification Attribute | Value / Operational Definition |
| :--- | :--- |
| **1. Detection ID** | `DET-XX` or `CORR-XX` (Unique repository identifier) |
| **2. Detection Name** | Human-readable title (e.g., Multiple Failed Logons - Single Account) |
| **21. Maturity Level** | `Experimental` \| `Functional` \| `Validated` \| `Tuned` \| `Production-Candidate` |
| **15. Severity Rationale** | `Informational` \| `Low` \| `Medium` \| `High` \| `Critical` (Include explicit risk formula below) |

---

## 2. Analytic Context & Threat Foundation

### 3. Objective
* [Defensive objective statement: Describe exactly what adversary behavior, operational anomaly, or security violation this detection aims to surface.]
* [Define the security boundary: Host-level, network-level, or identity-level.]

### 4. Threat / Analytic Hypothesis
* **Adversary Threat Model:** [Describe the threat actor profile, objective, and operational context (e.g., initial access attempt, credential stuffing, lateral movement).]
* **Analytic Hypothesis:** [Formal hypothesis: "If an adversary attempts to [action] against [asset], then [telemetry source] will record [pattern], distinguishable from normal behavior by [differentiator]."]
* **Pre-requisite Activity:** [What actions must occur before this detection triggers?]
* **Anticipated Post-Exploitation Activity:** [What will the adversary likely attempt immediately following success?]

### 8. MITRE ATT&CK Mapping
* **Enterprise Matrix Version:** MITRE ATT&CK v15 (Pinned)
* **Tactic:** [e.g., Credential Access (TA0006) / Execution (TA0002) / Lateral Movement (TA0008)]
* **Technique Name:** [e.g., Brute Force / Command and Scripting Interpreter]
* **Technique ID:** `TXXXX` (e.g., `T1110`)
* **Sub-Technique ID:** `TXXXX.XXX` (e.g., `T1110.001` - Password Guessing)
* **Technique Description & Relevance:** [Provide 2-3 sentences explaining why this technique applies to the telemetry footprint.]

---

## 3. Telemetry & Data Requirements

### 5. Data Source
* **Platform / OS:** [Windows 11 / Windows Server 2025 / Linux / Network]
* **Log Channel / Provider:** [e.g., `Security.evtx` / `Microsoft-Windows-Sysmon/Operational`]
* **Event Provider Name:** [e.g., `Microsoft-Windows-Security-Auditing` / `Microsoft-Windows-Sysmon`]
* **Target Event ID(s):** [e.g., `4625`, `4624`, `1`, `3`]
* **Prerequisite Auditing / Configuration:** [Explicit GPO / auditpol setting or Sysmon XML config block required to produce this event.]

### 6. Required Telemetry Fields
All fields must resolve against `docs/data-model.md`:

| Telemetry Field (OS / Provider) | Normalized Field Name | Data Type | Field Purpose / Analytic Requirement |
| :--- | :--- | :--- | :--- |
| `TargetUserName` | `user.target.name` | String | Identity identifier targeted by authentication activity |
| `WorkstationName` | `source.host.name` | String | Source workstation initiating authentication request |
| `IpAddress` | `source.ip` | IP Address | Network source IPv4/IPv6 (or `127.0.0.1` for local loopback) |
| `LogonType` | `logon.type` | Integer | Windows logon mechanism (e.g., 3 = Network, 2 = Interactive) |
| `Status` / `SubStatus` | `error.code` | Hex / String | LSASS NTSTATUS failure code (e.g., `0xc000006a` = bad password) |

---

## 4. Canonical Detection Logic (Sigma 2.1.0)

### 7. Canonical Sigma Rule
* **Rule File Location:** `detections/sigma/[rule_filename].yml` or `correlations/[correlation_filename].yml`
* **Sigma Specification Version:** 2.1.0 / Correlation Specification 2.1.0

```yaml
# Embed the exact canonical Sigma 2.1.0 YAML definition here
title: [Detection Title]
id: [UUID v4]
status: experimental
description: [Rule description matching analytic hypothesis]
references:
    - https://attack.mitre.org/techniques/TXXXX/XXX/
author: [Author Name / JestineSOC]
date: [YYYY-MM-DD]
modified: [YYYY-MM-DD]
tags:
    - attack.credential-access
    - attack.t1110.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        LogonType: 3
    condition: selection
falsepositives:
    - [Documented false positive scenario]
level: high
```

### 16. Correlation & Grouping Logic (If Applicable)
For multi-event, sequence, or threshold detections, define the explicit correlation parameters:
* **Correlation Type:** [e.g., `temporal` / `ordered` / `event_count`]
* **Primary Entity Key (Account):** `TargetUserName` (exact case-insensitive match)
* **Secondary Entity Key (Source):** `WorkstationName` AND/OR `IpAddress`
* **Tertiary Entity Key (Destination):** `Computer` / target system hostname
* **Correlation Window / Timespan:** [e.g., `5m` (300 seconds)]
* **Threshold Condition:** [e.g., $\ge 5 \times 4625$ followed by $\ge 1 \times 4624$ within timespan]
* **Cardinality & Aggregation:** [Explain how grouping prevents cross-account aggregation noise]

---

## 5. Derived SIEM Implementations & Semantic Divergence

### 17. SPL (Splunk Search Processing Language) Translation
* **Target Index / Sourcetype:** `index=security sourcetype=WinEventLog:Security`
* **Translation File:** `detections/splunk/[rule_filename].spl`

```spl
# Canonical equivalent SPL query
index=security sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3
| stats count by TargetUserName, WorkstationName, IpAddress, src_ip
| where count >= 5
```

### 18. KQL (Microsoft Sentinel / Defender Kusto Query) Translation
* **Target Table:** `SecurityEvent`
* **Translation File:** `detections/kql/[rule_filename].kql`

```kql
// Canonical equivalent KQL query
SecurityEvent
| where TimeGenerated >= ago(5m)
| where EventID == 4625 and LogonType == 3
| summarize FailureCount = count() by TargetAccount, WorkstationName, IpAddress
| where FailureCount >= 5
```

### 19. Semantic Divergence from Sigma
Document all variances, limitations, and behavioral divergences between canonical Sigma and target SIEM languages:
* **Field Mapping Divergences:** [e.g., Sigma `TargetUserName` maps to Splunk `TargetUserName` vs KQL `TargetAccount` vs Sysmon `user`.]
* **Temporal Grouping Nuances:** [e.g., Sigma temporal correlations evaluate sliding time windows; Splunk `bucket _time span=5m` evaluates fixed tumbling windows unless using `transaction` or `streamstats`.]
* **Type Coercion & Case Sensitivity:** [e.g., Hex status codes in Windows (`0xc000006a`) may be treated as integers or strings depending on ingestion parser.]
* **Missing Feature Caveats:** [Identify any Sigma 2.1.0 feature unsupported by standard SIEM translations.]

---

## 6. Testing, Verification & Empirical Evidence

### 9. Positive Test Case (Attack Simulation)
* **Test Case ID:** `TC-POS-XXX`
* **Simulation Type:** [Controlled Atomic Simulation / Lab Execution Script]
* **Lab Execution Command:**
  ```powershell
  .\telemetry\generators\[generator_script].ps1 -TargetUser "lab_user_test" -Param "Value" -TestCaseId "TC-POS-XXX"
  ```
* **Simulation Safety Boundary:** Explicitly confirm that this simulation runs locally, affects only designated test accounts (`lab_user_*`), and does NOT execute live malware or hostile external traffic.
* **Prerequisites:** [Test account created, audit policy enabled, Sysmon running]

### 10. Negative Test Case (Benign Baseline / Sub-Threshold)
* **Test Case ID:** `TC-NEG-XXX`
* **Benign Operational Scenario:** [Describe routine operational activity that must NOT trigger the alert, such as 1-2 password typos or legitimate scheduled administrative logon.]
* **Execution Command:**
  ```powershell
  .\telemetry\generators\[generator_script].ps1 -TargetUser "lab_user_test" -FailureCount 2 -TestCaseId "TC-NEG-XXX"
  ```
* **Boundary Condition Tested:** [e.g., $N = 4$ when threshold is 5; or mixed accounts from different hosts]

### 11. Expected Result
* **Positive Test:** Rule MUST fire; alert emitted with Severity = `[High]`, MITRE tag = `[TXXXX.XXX]`, matching `[TargetUserName]`.
* **Negative Test:** Rule MUST NOT fire; alert count remains 0; noise is suppressed by threshold / grouping logic.

### 12. Actual Result
* **Execution Date & Environment:** [YYYY-MM-DD / Windows 11 Build XXXXX]
* **Positive Test Result:** [PASS / FAIL — Detailed execution summary]
* **Negative Test Result:** [PASS / FAIL — Detailed execution summary]
* **Empirical Match Asserted:** [Requested == Emitted == Observed]

### 20. Evidence Location / Provenance Chain
* **Seven-Stage Provenance:**
  `Test Case` $\rightarrow$ `RunId` $\rightarrow$ `Generator` $\rightarrow$ `Windows Log (evtx)` $\rightarrow$ `RecordId Extraction` $\rightarrow$ `Sanitization` $\rightarrow$ `Committed Artifact`
* **Primary Evidence File:** `evidence/detections/[evidence_filename].json`
* **Observed Windows Record IDs:** `[Record#XXXXX, Record#XXXXX, ...]`
* **Verification State:** `VERIFIED_ACCURATE` (confirmed via programmatic comparison)

---

## 7. Operational Triage, Tuning & Engineering Boundaries

### 13. False-Positive Scenarios & Operational Noise
1. **Scenario 1 (Automated Service Accounts):**
   * *Trigger Cause:* Service account with expired password attempted by multiple Windows services.
   * *Mitigation / Tuning:* Exclude service account prefix naming conventions (`svc_*`) only after explicit identity review.
2. **Scenario 2 (Vulnerability / Compliance Scanners):**
   * *Trigger Cause:* Authorized vulnerability scanner probing local SMB/RDP endpoints.
   * *Mitigation / Tuning:* Filter by approved static scanner IP range using RFC 5737 sanitized documentation addresses in lab.
3. **Scenario 3 (Misconfigured Network Share Mappings):**
   * *Trigger Cause:* User disconnected share retaining cached invalid credentials generating repetitive logon type 3 rejections.
   * *Mitigation / Tuning:* Correlate with subsequent successful interactive logon (`LogonType = 2`) to distinguish user error from malicious brute force.

### 14. Investigation Questions & SOC Triage Workflow
Structured triage path for Tier-1/Tier-2 SOC analysts (aligned with NIST SP 800-61 Rev. 3 & CSF 2.0 Detect / Respond):
1. **Identity Context:** Is `TargetUserName` a privileged administrative account, a service account, or a standard user?
2. **Host Context:** Is the source `WorkstationName` or `IpAddress` recognized as an internal managed corporate asset or an unauthorized endpoint?
3. **Temporal Analysis:** Did the authentication failures occur in rapid bursts (seconds) indicating automated tooling, or spread out over hours?
4. **Subsequent Activity:** Did a successful logon (`Event 4624`) follow the failures? What process was spawned immediately after logon (`Sysmon Event 1` / `Event 4688`)?
5. **Lateral Spread:** Did the same source IP attempt authentication against multiple distinct accounts (password spraying) or solely this target?

### 15. Severity Rationale & Scoring Formula
* **Base Severity:** `High`
* **Impact Justification:** Unauthorized access leading to credential compromise and lateral movement.
* **Likelihood Justification:** High false-positive potential if threshold is set $< 5$; tuned threshold ($\ge 5$ within 5 min followed by success) indicates high attack fidelity.
* **Escalation Trigger:** Automatically elevate to `Critical` if `TargetUserName` belongs to Domain Admins / Local Administrators or if subsequent process execution includes reconnaissance/privilege escalation utilities.

### 22. Known Limitations & Non-Claims
Explicit defensive boundaries and out-of-scope constraints:
* **Detection Non-Claims:**
  * This detection does NOT claim to detect slow, distributed password guessing (low-and-slow attacks under the 5-attempt threshold).
  * This detection does NOT inspect Kerberos ticket anomalies (Event 4768/4771) unless Kerberos audit subcategories are configured.
  * This detection does NOT prevent credential guessing; it alerts post-activity within the SIEM ingestion window.
* **Evasion Vectors:**
  * Adversaries rotating source IP addresses across distributed proxies will evade single-source grouping.
  * Adversaries guessing passwords at a rate of 1 attempt every 2 minutes will bypass the 5-minute sliding window.

### 23. Acceptance Criteria
Objective engineering requirements for formal sign-off:
- [ ] Canonical Sigma rule passes `sigma check` with 0 errors.
- [ ] Rule YAML conforms to `yamllint` configuration.
- [ ] Positive test simulation triggers detection alert with 100% precision.
- [ ] Negative test simulation generates 0 alerts (clean suppression).
- [ ] Boundary test ($N - 1$ attempts) verified silent.
- [ ] SPL and KQL translations authored with explicit semantic difference documentation.
- [ ] Raw JSON evidence committed to `evidence/detections/` with auditable OS `RecordId` mapping.
- [ ] Investigation workflow and false-positive scenarios fully documented.
- [ ] Peer / Auditor review approved without outstanding critical findings.
