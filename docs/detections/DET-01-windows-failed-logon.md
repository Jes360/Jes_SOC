# DET-01: Multiple Failed Windows Network Logons (Brute-Force / Password Guessing)

**Specification Version:** 1.1.0  
**Last Updated:** 2026-09-15  
**Author / Engineering Lead:** JestineSOC Detection Engineering Team  
**Lifecycle Status:** Validated (Empirical Boundary Testing & Backend Execution Verified)  

---

## 1. Detection Metadata & Identification

| Specification Attribute | Value / Operational Definition |
| :--- | :--- |
| **1. Detection ID** | `DET-01` (Composite Architecture: `DET-01-PRIM` + `CORR-DET01`) |
| **2. Detection Name** | Multiple Failed Windows Network Logons (Threshold Breach) |
| **21. Maturity Level** | `Validated` (Passed canonical syntax linting, empirical 5-case boundary test suite, and backend execution engine proof) |
| **15. Severity Rationale** | `Medium` for atomic failed logon primitive (`DET-01-PRIM`); elevates to `High` upon threshold breach ($\ge 5$ within 5 min, `CORR-DET01`); `Critical` if targeting Domain Admins or followed by successful logon (`CORR-01`) |

---

## 2. Analytic Context & Threat Foundation

### 3. Objective
Detect rapid, repeated network logon rejections targeting a single local or domain user account from a single source host within a narrow temporal window. This surfaces active online password guessing, automated credential brute-forcing, or dictionary attacks directed against Windows network services (SMB, WinRM, RPC) before credentials are breached.

### 4. Threat / Analytic Hypothesis
* **Adversary Threat Model:**
  Adversaries possessing valid username targets (acquired via active directory enumeration, OSINT, or initial network reconnaissance) attempt to discover passwords by repeatedly authenticating via network logon protocols (LogonType = 3). Automated tools (e.g., Hydra, CrackMapExec, Metasploit SMB login modules) cycle through wordlists or common password variations.
* **Analytic Hypothesis:**
  *If* an adversary initiates an online password-guessing attack against a Windows asset,  
  *then* the Windows Local Security Authority Subsystem Service (LSASS) will generate a cluster of Event 4625 records with `LogonType = 3`, `Status = 0xc000006d` (login failure), and `SubStatus = 0xc000006a` (bad password),  
  *distinguishable from normal user error* by temporal frequency (seconds apart rather than minutes) and volume exceeding standard human mistype patterns ($\ge 5$ attempts within 5 minutes).
* **Analytic Distinction Matrix:**

| Condition | Event Volume | Time Span | Behavioral Characteristic | Analytic Classification |
| :--- | :--- | :--- | :--- | :--- |
| **Single 4625** | $N = 1$ | Instant | Single authentication rejection | Ambient noise / routine typo (`TC-NEG-001`) |
| **Sub-threshold Boundary** | $N = 4$ | $\le 5$ minutes | User retry burst below threshold | Benign retry boundary (`TC-NEG-002`) |
| **Temporal Dilution** | $N = 5$ | $> 5$ minutes | 5 attempts spaced across $> 5$ min | Sub-threshold sliding window (`TC-NEG-003`) |
| **Exact Threshold Breach** | $N = 5$ | $\le 5$ minutes | Rapid repetitive programmatic attempts | **Suspicious Password Guessing (`CORR-DET01` / `TC-POS-001`)** |
| **Above-Threshold Breach** | $N \ge 6$ | $\le 5$ minutes | Sustained brute-force guessing | **Active Credential Attack (`CORR-DET01` / `TC-POS-002`)** |
| **Sequence Breach** | $N \ge 5 \rightarrow 1 \times 4624$ | $\le 5$ minutes | Failures immediately succeeded by valid login | **Account Compromise (`CORR-01`)** |

* **Why Threshold = 5 Attempts in 5 Minutes?**
  Human users rarely mistype their password 5 consecutive times within a 5-minute window without pausing to reset their password or contacting the helpdesk. Conversely, automated brute-force tools emit attempts in sub-second to low-second intervals. A threshold of 5 attempts within 300 seconds provides an optimal balance between sensitivity (catching rapid attacks early) and specificity (preventing alert fatigue from standard user typos).
* **Pre-requisite Activity:** Target account identification and network reachability to SMB/RPC/WinRM ports (445, 139, 5985).
* **Anticipated Post-Exploitation Activity:** If guessing succeeds, adversary emits Event 4624 (Logon Success), followed by process creation (Sysmon Event 1) for reconnaissance (`whoami`, `net user`).

### 8. MITRE ATT&CK Mapping
* **Enterprise Matrix Version:** MITRE ATT&CK v15 (Pinned)
* **Tactic:** Credential Access (`TA0006`)
* **Technique Name:** Brute Force
* **Technique ID:** `T1110`
* **Sub-Technique ID:** `T1110.001` (Password Guessing)
* **Technique Justification:**
  Sub-technique `T1110.001` specifies adversaries attempting many passwords against a single account to discover valid credentials. The combination of `LogonType = 3`, repetitive bad password status codes (`0xc000006a`), and rapid cadence directly aligns with this MITRE definition.
* **Scope Note:** The ATT&CK mapping belongs strictly to the **analytic correlation hypothesis** (`CORR-DET01`), not to individual ambient Event 4625 records.

---

## 3. Telemetry & Data Requirements

### 5. Data Source
* **Platform / OS:** Windows 11 / Windows Server 2022+
* **Log Channel:** `Security` (`C:\Windows\System32\Winevt\Logs\Security.evtx`)
* **Event Provider Name:** `Microsoft-Windows-Security-Auditing`
* **Target Event ID:** `4625` (An account failed to log on)
* **Prerequisite Auditing Policy:**
  Local Security Policy $\rightarrow$ Advanced Audit Policy Configuration $\rightarrow$ Audit Policies $\rightarrow$ Account Logon $\rightarrow$ Audit Kerberos Authentication Service / Audit Credential Validation (`Failure = Enabled`), and Logon/Logoff $\rightarrow$ Audit Logon (`Failure = Enabled`).
  Verification command: `auditpol /get /subcategory:"Logon"` must return `Success and Failure`.

### 6. Required Telemetry Fields
Fields mapped to `docs/data-model.md`:

| Telemetry Field (Security.evtx) | Normalized Field Name | Data Type | Analytic Requirement & Validation Rule |
| :--- | :--- | :--- | :--- |
| `TargetUserName` | `user.target.name` | String | Must NOT be empty; identifies targeted account |
| `TargetDomainName` | `user.target.domain` | String | Identifies local machine name or Active Directory domain |
| `LogonType` | `logon.type` | Integer | Must equal `3` (Network logon via SMB/WinRM/RPC) |
| `Status` | `error.status` | Hex String | Must equal `0xc000006d` (`STATUS_LOGON_FAILURE`) |
| `SubStatus` | `error.substatus` | Hex String | Must equal `0xc000006a` (`STATUS_WRONG_PASSWORD`) |
| `WorkstationName` | `source.host.name` | String | Originating client workstation name |
| `IpAddress` | `source.ip` | IP Address | Source IP address (or `127.0.0.1` in local loopback testing) |
| `Computer` | `destination.host.name` | String | Target destination system name |
| `TimeCreated` | `@timestamp` | ISO8601 | Event timestamp used for sliding window evaluation |

---

## 4. Canonical Detection Architecture (Sigma 2.1.0)

To eliminate the semantic gap between atomic event filtering and temporal threshold correlation (Auditor Finding `DET01-01`), DET-01 is explicitly structured into two canonical tiers:

```
┌─────────────────────────────────────────────────────────────┐
│  Tier 1: Atomic Qualifying Event Primitive (DET-01-PRIM)     │
│  detections/sigma/windows_failed_logon.yml                  │
│  - Filters Event 4625, LogonType 3, 0xc000006d / 0xc000006a │
│  - Excludes machine accounts ($ suffix)                     │
└──────────────────────────────┬──────────────────────────────┘
                               │ Qualifying Events
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Tier 2: Canonical Threshold Correlation (CORR-DET01)       │
│  correlations/corr_det01_bruteforce_threshold.yml           │
│  - Type: event_count                                        │
│  - Group-by: [TargetUserName, IpAddress, Computer]          │
│  - Timespan: 5m (300s sliding window)                       │
│  - Condition: count >= 5                                    │
└─────────────────────────────────────────────────────────────┘
```

### 7. Canonical Sigma Rule 1: Atomic Event Primitive (`DET-01-PRIM`)
* **Rule File Location:** `detections/sigma/windows_failed_logon.yml`
* **Specification Compliance:** Sigma Specification 2.1.0

```yaml
title: Windows Network Authentication Failure (Atomic Event Primitive)
name: windows_failed_logon
id: 5a8a0b02-1f3e-4b48-9c12-789a45612301
status: experimental
description: |
    Matches individual Windows network authentication failure events (Event 4625, LogonType 3)
    exhibiting NTSTATUS bad password status codes (0xc000006d / 0xc000006a).
    Serves as the atomic detection primitive (DET-01-PRIM) referenced by threshold correlation
    rule 'corr_det01_bruteforce_threshold' and planned composite correlation
    'mr_bruteforce_after_failures' (CORR-01, scheduled in Phase 2 roadmap).
references:
    - https://attack.mitre.org/techniques/T1110/001/
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
author: JestineSOC Detection Engineering Team
date: 2026-09-15
modified: 2026-09-15
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
        Status: '0xc000006d'
        SubStatus: '0xc000006a'
    filter_machine_accounts:
        TargetUserName|endswith: '$'
    condition: selection and not filter_machine_accounts
falsepositives:
    - User entering incorrect password on network resource access
    - Service accounts with expired credentials
level: medium
```

### 16. Canonical Sigma Rule 2: Threshold Correlation (`CORR-DET01`)
* **Rule File Location:** `correlations/corr_det01_bruteforce_threshold.yml`
* **Specification Compliance:** Sigma Correlation Specification 2.1.0

```yaml
title: Multiple Windows Network Logon Failures (Threshold Breach)
name: corr_det01_bruteforce_threshold
id: 6b9b1c13-2a4f-4c59-ad23-890b56723402
status: experimental
description: |
    Correlates multiple Windows network authentication failures (Event 4625, LogonType 3)
    targeting the same account from the same source within a 5-minute sliding window.
    Implements the canonical correlation layer for DET-01.
references:
    - https://attack.mitre.org/techniques/T1110/001/
    - https://github.com/SigmaHQ/sigma-specification/blob/main/correlation-specification.md
author: JestineSOC Detection Engineering Team
date: 2026-09-15
modified: 2026-09-15
tags:
    - attack.credential-access
    - attack.t1110.001
correlation:
    type: event_count
    rules:
        - windows_failed_logon
    group-by:
        - TargetUserName
        - IpAddress
        - Computer
    timespan: 5m
    condition:
        gte: 5
level: high
falsepositives:
    - Automated service accounts with expired passwords attempting network service access
    - Misconfigured administrative scripts or scheduled tasks retaining outdated credentials
    - Authorized vulnerability scanners (identified by static scanner asset IP in production)
```

---

## 5. Derived SIEM Implementations & Semantic Reconciliation

### 17. SPL (Splunk Search Processing Language) Translation
* **Target Index / Sourcetype:** `index=security sourcetype=WinEventLog:Security`
* **Translation File:** `detections/splunk/windows_failed_logon.spl`

```spl
# Detection: Multiple Failed Windows Network Logons (DET-01)
# Canonical Source: detections/sigma/windows_failed_logon.yml & correlations/corr_det01_bruteforce_threshold.yml
index=security sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3
    (Status="0xc000006d" OR Status="0xC000006D")
    (SubStatus="0xc000006a" OR SubStatus="0xC000006A")
    NOT TargetUserName="*$"
| streamstats time_window=5m count as failure_count by TargetUserName, IpAddress, Computer
| where failure_count >= 5
| fields _time, TargetUserName, IpAddress, WorkstationName, Computer, failure_count, Status, SubStatus
```

### 18. KQL (Microsoft Sentinel / Defender Kusto Query) Translation
* **Target Table:** `SecurityEvent`
* **Translation File:** `detections/kql/windows_failed_logon.kql`

#### Approach A: High-Efficiency Tumbling Bucket (Standard Sentinel Scheduled Analytic Rule)
```kql
SecurityEvent
| where TimeGenerated >= ago(1h)
| where EventID == 4625
| where LogonType == 3
| where Status =~ "0xc000006d" and SubStatus =~ "0xc000006a"
| where not(TargetAccount endswith "$")
| summarize 
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    FailureCount = count()
    by TargetAccount, IpAddress, WorkstationName, Computer, bin(TimeGenerated, 5m)
| where FailureCount >= 5
| project StartTime, EndTime, TargetAccount, IpAddress, WorkstationName, Computer, FailureCount
```

#### Approach B: Strict 5-Minute Sliding Window (Exact Semantic Equivalence)
```kql
let RawFailures = SecurityEvent
    | where TimeGenerated >= ago(1h)
    | where EventID == 4625 and LogonType == 3
    | where Status =~ "0xc000006d" and SubStatus =~ "0xc000006a"
    | where not(TargetAccount endswith "$");
RawFailures
| join kind=inner (
    RawFailures
    | project JoinAccount=TargetAccount, JoinIp=IpAddress, WindowStart=TimeGenerated, WindowEnd=datetime_add('minute', 5, TimeGenerated)
) on $left.TargetAccount == $right.JoinAccount and $left.IpAddress == $right.JoinIp
| where TimeGenerated between (WindowStart .. WindowEnd)
| summarize RollingCount = count() by TargetAccount, IpAddress, Computer, WindowStart, WindowEnd
| where RollingCount >= 5
| summarize min(WindowStart), max(WindowEnd), max(RollingCount) by TargetAccount, IpAddress, Computer
```

### 19. Semantic Reconciliation Matrix (Resolving DET01-04)
The following matrix resolves all dialect mappings, windowing semantics, and field equivalences across backends:

| Requirement | Canonical Sigma Primitive (`DET-01-PRIM`) | Canonical Sigma Correlation (`CORR-DET01`) | Splunk SPL Translation (`streamstats`) | Microsoft Sentinel KQL (Approach A - Tumbling) | Microsoft Sentinel KQL (Approach B - Sliding) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Event 4625** | ✓ (`EventID: 4625`) | ✓ (Referenced via PRIM) | ✓ (`EventCode=4625`) | ✓ (`EventID == 4625`) | ✓ (`EventID == 4625`) |
| **LogonType 3** | ✓ (`LogonType: 3`) | ✓ (Referenced via PRIM) | ✓ (`Logon_Type=3`) | ✓ (`LogonType == 3`) | ✓ (`LogonType == 3`) |
| **Status / SubStatus** | ✓ (`0xc000006d` / `0xc000006a`) | ✓ (Referenced via PRIM) | ✓ (`0xc000006d` OR `0xC000006D`) | ✓ (`=~ "0xc000006d"` / `0xc000006a`) | ✓ (`=~ "0xc000006d"` / `0xc000006a`) |
| **Same Account** | N/A (Single event match) | ✓ (`group-by: TargetUserName`) | ✓ (`by TargetUserName`) | ✓ (`by TargetAccount`) | ✓ (`by TargetAccount`) |
| **Same Source** | N/A (Single event match) | ✓ (`group-by: IpAddress, Computer`) | ✓ (`by IpAddress, Computer`) | ✓ (`by IpAddress, Computer`) | ✓ (`by IpAddress, Computer`) |
| **$\ge 5$ Events** | N/A (Delegated to correlation) | ✓ (`condition: gte: 5`) | ✓ (`where failure_count >= 5`) | ✓ (`where FailureCount >= 5`) | ✓ (`where RollingCount >= 5`) |
| **5-Minute Window** | N/A (Delegated to correlation) | ✓ (`timespan: 5m`, sliding) | ✓ (`time_window=5m`, sliding) | ⚠️ Approximate (`bin(5m)`, tumbling) | ✓ (`between (WindowStart..WindowEnd)`, sliding) |
| **Machine Account Exclusion** | ✓ (`TargetUserName\|endswith: '$'`) | ✓ (Inherited from PRIM) | ✓ (`NOT TargetUserName="*$"`) | ✓ (`not(TargetAccount endswith "$")`) | ✓ (`not(TargetAccount endswith "$")`) |

* **Grouping Key Divergence Note (F-15):** The canonical Sigma correlation `CORR-DET01` groups strictly by the 3D key `(TargetUserName, IpAddress, Computer)`. The KQL translation includes `WorkstationName` in its grouping clause for host attribution. In enterprise environments where network clients emit transient, spoofed, or blank `WorkstationName` values (e.g. anonymous NTLM negotiations), this additional key can split failure clusters across separate buckets. Where workstation naming is inconsistent, Sentinel rules should omit `WorkstationName` from the `by` clause to mirror canonical Sigma behavior.

---

## 6. Testing, Verification & Boundary Evidence

### 9. Positive Test Cases (Attack Simulation)
* **`TC-POS-001` (Exact Threshold Breach):** 5 consecutive failed network logons executed within 120 seconds ($N=5$).
  - Command: `.\telemetry\generators\gen-auth-events.ps1 -TargetUser "lab_user_test" -FailureCount 5 -TestCaseId "TC-POS-001"`
  - Verification: Reaches exactly threshold 5 within 5 minutes; alert MUST fire.
* **`TC-POS-002` (Above-Threshold Sustained Attack):** 6 consecutive failed network logons executed within 100 seconds ($N=6$).
  - Verification: Exceeds threshold; alert MUST fire and sustain breach state.

### 10. Negative Test Cases (Benign Baseline & Boundary Suppression)
* **`TC-NEG-001` (Isolated Typo Baseline):** Single failed network logon ($N=1$).
  - Command: `.\telemetry\generators\gen-auth-events.ps1 -TargetUser "lab_user_test" -FailureCount 1 -TestCaseId "TC-NEG-001"`
  - Verification: Routine ambient noise; alert suppressed.
* **`TC-NEG-002` (Immediate Boundary $N-1$):** 4 failed logons within 90 seconds ($N=4$).
  - Verification: Exactly 1 failure below threshold ($N=4 < 5$); proves boundary cut-off; alert suppressed.
* **`TC-NEG-003` (Temporal Dilution / Sliding Window Enforcement):** 5 failed logons spread across 400 seconds (6.67 minutes), spaced 100s apart.
  - Verification: Even though total events = 5, the maximum count within any 300-second sliding window is 4 ($<5$); proves sliding window enforcement suppresses false alerts.
* **`TC-NEG-004` (Machine Account Exclusion):** 5 failed logons for machine account `LAB-SRV01$`.
  - Verification: Excluded by primitive machine account filter; alert suppressed.
* **`TC-NEG-005` (Account Variance / Horizontal Spraying):** 5 failed logons within 60s targeting 5 distinct usernames.
  - Verification: Grouping key `TargetUserName` isolates counts to $N=1$ per user; alert suppressed.

### 11. Comprehensive Boundary Test Matrix Results (Resolving DET01-02)
Automated execution results generated by `tests/runners/eval_det01_engine.py` and recorded in `evidence/detections/ev-det-01-boundary-matrix.json`:

| Test ID | Case ID | Category | Event Count | Duration | Window Evaluated | Expected Alert | Actual Alert | Max Window Count | Verdict | Boundary Rationale |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `NEG-001` | `TC-NEG-001` | Benign Baseline | 1 | 0s | 5m (300s) | `NO_ALERT` | `NO_ALERT` | 1 | ✅ PASS | Single failure represents routine mistype; sub-threshold |
| `NEG-002` | `TC-NEG-002` | Boundary $N-1$ | 4 | 90s | 5m (300s) | `NO_ALERT` | `NO_ALERT` | 4 | ✅ PASS | Exactly 1 attempt below threshold; verifies cutoff suppression |
| `POS-001` | `TC-POS-001` | Exact Threshold | 5 | 120s | 5m (300s) | `ALERT` | `ALERT` | 5 | ✅ PASS | Reaches threshold 5 within 5 minutes; alert fires |
| `POS-002` | `TC-POS-002` | Above Threshold | 6 | 100s | 5m (300s) | `ALERT` | `ALERT` | 6 | ✅ PASS | Exceeds threshold 5; continuous breach recorded |
| `NEG-003` | `TC-NEG-003` | Temporal Dilution | 5 | 400s | 5m (300s) | `NO_ALERT` | `NO_ALERT` | 4 | ✅ PASS | Total count=5, but sliding window max count=4; proves temporal constraint |
| `NEG-004` | `TC-NEG-004` | Machine Filter | 5 | 60s | 5m (300s) | `NO_ALERT` | `NO_ALERT` | 0 | ✅ PASS | Machine accounts ($ suffix) excluded by atomic primitive filter |
| `NEG-005` | `TC-NEG-005` | Spray / Variance | 5 | 60s | 5m (300s) | `NO_ALERT` | `NO_ALERT` | 1 | ✅ PASS | Distinct accounts isolated by `TargetUserName` grouping key |

### 12. Actual Result & Backend Execution Proof (Resolving DET01-03)
* **Backend Evaluation Engine:** `tests/runners/eval_det01_engine.py` (executed via PowerShell runner `tests/test_det01_boundary_suite.ps1`).
* **Execution Proof Artifact:** `evidence/detections/ev-det-01-execution-proof.json` captures the full stream trace:
  $$\text{Input Events} \longrightarrow \text{Primitive Filtering} \longrightarrow \text{Sliding Window Aggregation} \longrightarrow \text{Alert Decision} \longrightarrow \text{PASS/FAIL}$$
* **Observed Empirical Pass Rate:** 7 / 7 test cases passed (100% boundary accuracy).

### 20. Evidence Location / Provenance Chain
* **Boundary Matrix:** `evidence/detections/ev-det-01-boundary-matrix.json`
* **Execution Proof:** `evidence/detections/ev-det-01-execution-proof.json`
* **Positive Attack Evidence:** `evidence/detections/ev-det-01-positive.json`
* **Negative Benign Evidence:** `evidence/detections/ev-det-01-negative.json`
* **Raw Telemetry Provenance:** `evidence/telemetry/evtx-auth-sample.json`

---

## 7. Operational Triage, Tuning & Engineering Boundaries

### 13. False-Positive Scenarios & Operational Noise
1. **Scenario 1 (Expired Service Account Credentials):**
   * *Trigger Cause:* A scheduled task running under `svc_backup` attempts to connect to remote administrative shares after password rotation.
   * *Mitigation / Tuning:* Exclude service account prefix naming conventions (`svc_*`) only after verifying the source process path and confirming the account is intended for non-interactive service execution.
2. **Scenario 2 (Internal Compliance & Vulnerability Scanning):**
   * *Trigger Cause:* Authorized security tools (e.g. Nessus, Qualys) performing authenticated SMB credential auditing.
   * *Production Mitigation:* Identify authorized vulnerability scanners using an explicitly configured scanner IP range, subnet, or asset identity.
   * *Evidence Sanitization Standard:* For committed evidence and lab documentation, scanner addresses are represented using RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in accordance with NFR-03.
3. **Scenario 3 (Orphaned Network Drive Mappings):**
   * *Trigger Cause:* Disconnected user workstation continuously attempting to remount mapped network shares using expired Kerberos/NTLM tokens.
   * *Mitigation / Tuning:* Verify whether the failures correlate with subsequent successful interactive logons (`LogonType = 2`) from the user's primary workstation.

### 14. Investigation Questions & SOC Triage Workflow
Structured triage path for Tier-1/Tier-2 SOC analysts (aligned with NIST SP 800-61 Rev. 3 & CSF 2.0 Detect / Respond):
1. **Target Account Context:** Is `TargetUserName` an active employee, a disabled/former employee, a privileged administrator, or a non-existent account (indicating user enumeration)?
2. **Source Host Context:** Is `IpAddress` / `WorkstationName` a known corporate asset, a DHCP client, a VPN IP, or an unknown external address?
3. **Volume & Cadence:** Did the 5+ failed attempts occur in less than 10 seconds (automated tooling) or over several minutes?
4. **Subsequent Authentication:** Did a successful logon (`Event 4624`) follow the failures from the same source IP? (If yes, escalate immediately to Incident Playbook `CORR-01` / Account Compromise).
5. **Horizontal Scope:** Did the source IP attempt authentications against other usernames on the same host or across the network (password spraying)?

### 15. Severity Rationale & Scoring Formula
* **Base Severity:** `Medium` for individual failed logons.
* **Elevated Severity:** `High` when threshold of 5 failures in 5 minutes is breached (`CORR-DET01`), as the probability of deliberate brute-force exceeds 90%.
* **Critical Escalation Trigger:** Automatically elevate to `Critical` if:
  1. `TargetUserName` is a Domain Admin, Enterprise Admin, or Local Administrator; OR
  2. The failed logon burst is followed within 5 minutes by a successful authentication (`CORR-01`).

### 22. Known Limitations & Non-Claims (Scope Limitations SL-01 through SL-03)
* **Scope Limitations (Explicit Non-Claims):**
  * **`SL-01` (Low-and-Slow Threshold Evasion):** This detection does NOT detect low-and-slow password guessing (e.g., 1 attempt every 6–10 minutes) deliberately timed to evade the 5-minute sliding window (`timespan: 5m`). Such adversary activity must be addressed by extended-window baseline analytics (e.g., 24-hour failed logon aggregations).
  * **`SL-02` (Distributed / Proxy IP Rotation):** Adversaries cycling through rotating proxy IP addresses or botnet nodes will bypass the single-source `IpAddress` grouping dimension.
  * **`SL-03` (Horizontal Password Spraying):** This detection is designed for single-target brute-force and does NOT detect horizontal password spraying where an adversary attempts 1 password across dozens or hundreds of different user accounts (addressed by a separate horizontal spray detection rule grouping by source IP across unique accounts).
  * **Service Protocol Scope:** This detection monitors only Windows network authentications (LogonType = 3) recorded in Security Event 4625; it does not monitor cloud identity (Entra ID), web portal, or Kerberos pre-authentication failures (Event 4771).
* **Evasion Vectors:**
  * Adversaries guessing below the threshold ($N \le 4$) will not trigger this rule (empirically confirmed by `TC-NEG-002`).
  * Adversaries spreading attempts across multiple source IP addresses or distinct target accounts will not breach single-entity grouping thresholds (empirically confirmed by `TC-NEG-005`).

### 23. Acceptance Criteria
- [x] Canonical 23-section detection specification authored and reviewed.
- [x] Canonical Sigma rule `windows_failed_logon.yml` (`DET-01-PRIM`) passes `sigma check` with 0 errors.
- [x] Canonical Sigma correlation rule `corr_det01_bruteforce_threshold.yml` (`CORR-DET01`) complies with Sigma Correlation Specification 2.1.0.
- [x] Rule YAML complies with `yamllint` configuration.
- [x] Boundary suite `tests/test_det01_boundary_suite.ps1` executes all 5 boundary conditions plus controls ($N=1, 4, 5, 6, >5\text{m}$) with 100% pass rate.
- [x] Backend evaluation engine `tests/runners/eval_det01_engine.py` executes and outputs verified stream proof.
- [x] Derived SPL translation authored with documented `streamstats` sliding-window equivalence.
- [x] Derived KQL translations authored documenting Approach A tumbling vs Approach B sliding windows.
- [x] Semantic Reconciliation Matrix resolves all dialect mappings, window types, and field equivalences.
- [x] Raw evidence JSON captured and committed to `evidence/detections/ev-det-01-boundary-matrix.json` and `ev-det-01-execution-proof.json`.
- [x] Traceability matrix updated mapping `FR-03` to `DET-01-PRIM` and `CORR-DET01`.
