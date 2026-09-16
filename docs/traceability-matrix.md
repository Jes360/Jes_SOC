# JestineSOC: Master Traceability Matrix

**Document ID:** TRACE-V1-CONTROL  
**Version:** v0.1.0 (Baseline Established)  
**Control Standard:** NIST CSF 2.0 / Sigma 2.1.0 Traceability Harness  

---

## 1. Overview & Purpose

The **Traceability Matrix** serves as the central control mechanism for JestineSOC. It establishes unbroken bidirectional lineage between high-level engineering requirements, technical specifications, canonical detection implementations, empirical test cases, sanitized forensic evidence, and final verification results.

$$\text{FR / NFR} \iff \text{Design (DES)} \iff \text{Detection (DET)} \iff \text{Test Case (TC)} \iff \text{Evidence (EV)} \iff \text{Audit Status}$$

---

## 2. Functional Requirements (FR) Traceability Table

| Req ID | Requirement Summary | Design Specification | Implementation File | Test Case ID | Evidence Artifact | Current Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FR-01** | Windows Authentication Telemetry & Success Primitive (4624/4625) | `docs/data-model.md#windows-auth`<br>`docs/detections/DET-02-windows-successful-logon.md` | `telemetry/windows/audit-policy.md`<br>`telemetry/generators/gen-auth-events.ps1`<br>`detections/sigma/windows_successful_logon.yml`<br>`detections/splunk/windows_successful_logon.spl`<br>`detections/kql/windows_successful_logon.kql` | `TC-TEL-001`<br>`TC-AUTH-002`<br>`TC-POS-002` | `evidence/telemetry/evtx-auth-sample.json`<br>`evidence/detections/ev-det-02-boundary-matrix.json`<br>`evidence/detections/ev-det-02-execution-proof.json` | 🟢 VALIDATED — Audit PASS (Commit `015bb1e`, CI Run `34935781996`) |
| **FR-02** | Sysmon Telemetry & Encoded Execution Primitive (DET-03) | `docs/data-model.md#sysmon-schema`<br>`docs/detections/DET-03-windows-suspicious-powershell.md` | `telemetry/sysmon/sysmon-config.xml`<br>`telemetry/generators/gen-powershell-events.ps1`<br>`detections/sigma/windows_suspicious_powershell.yml`<br>`detections/splunk/windows_suspicious_powershell.spl`<br>`detections/kql/windows_suspicious_powershell.kql` | `TC-TEL-002`<br>`TC-AUTH-004`<br>`TC-POS-004`..`005`<br>`TC-NEG-013`..`016` | `evidence/telemetry/sysmon-sample.json`<br>`evidence/detections/ev-det-03-boundary-matrix.json`<br>`evidence/detections/ev-det-03-execution-proof.json` | 🟢 VALIDATED — Audit PASS (Commit `661e41e`, CI Quality Gate Badge: Passing) |
| **FR-03** | Atomic Failed Logon Detection & Threshold Correlation (Event 4625) | `docs/detections/DET-01-windows-failed-logon.md` | `detections/sigma/windows_failed_logon.yml`<br>`correlations/corr_det01_bruteforce_threshold.yml`<br>`detections/splunk/windows_failed_logon.spl`<br>`detections/kql/windows_failed_logon.kql` | `TC-AUTH-001`<br>`TC-POS-001`<br>`TC-POS-002`<br>`TC-NEG-001`<br>`TC-NEG-002`<br>`TC-NEG-003` | `evidence/detections/ev-det-01-boundary-matrix.json`<br>`evidence/detections/ev-det-01-execution-proof.json`<br>`evidence/telemetry/evtx-auth-sample.json` | 🟢 VALIDATED — Audit PASS (Tag `v0.3.0`, Commit `4bdf920`, CI Run `34933601381`) |
| **FR-04** | Brute-Force Sequence Correlation (CORR-01) | `docs/correlations/CORR-01-mr_bruteforce_after_failures.md` | `correlations/mr_bruteforce_after_failures.yml`<br>`detections/splunk/mr_bruteforce_after_failures.spl`<br>`detections/kql/mr_bruteforce_after_failures.kql` | `TC-AUTH-003`<br>`TC-POS-003`<br>`TC-NEG-007`..`012` | `evidence/correlations/ev-corr-01-boundary-matrix.json`<br>`evidence/correlations/ev-corr-01-execution-proof.json` | 🟢 VALIDATED — Audit PASS (Commit `a9eb97a`, CI Run `35045305149`) |
| **FR-05** | Negative Testing & FP Suppression | `docs/testing.md#negative-testing` | `tests/negative/test_bruteforce_negative.ps1` | `TC-NEG-004` | `evidence/detections/ev-neg-test-suppressed.log` | 🟡 Initialized |
| **FR-06** | MITRE ATT&CK Mapping & Provenance | `docs/threat-model.md#technique-matrix` | `detections/sigma/*.yml` (metadata blocks) | `TC-AUD-001` | `docs/traceability-matrix.md#mitre-coverage` | 🟡 Initialized |
| **FR-07** | False Positive Documentation & Tuning | `docs/detection-engineering.md#tuning` | `detections/sigma/*.yml` (`falsepositives`) | `TC-AUD-002` | `docs/detection-engineering.md` | 🟡 Initialized |
| **FR-08** | SIEM Query Translation (SPL & KQL) | `docs/adr/ADR-003-siem-translation.md` | `detections/splunk/`<br>`detections/kql/` | `TC-AUD-003` | `evidence/detections/ev-translation-log.md` | 🟡 Initialized |

---

## 3. Non-Functional Requirements (NFR) Traceability Table

| Req ID | Requirement Summary | Architectural Document | Verification Mechanism | Audit Evidence | Current Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NFR-01** | Workstation Reproducibility | `docs/lab-environment.md` | Clean setup script test | `docs/lab-environment.md` | 🟡 Initialized |
| **NFR-02** | Credential & Secret Hygiene | `docs/architecture.md#security` | TruffleHog / Git pre-commit scan | `evidence/ci/trufflehog-clean.log` | 🟡 Initialized |
| **NFR-03** | Telemetry & Evidence Sanitization | `docs/data-model.md#sanitization` | Manual review + Automated RFC1918 CI scan | `evidence/` directory audit | 🟠 PARTIAL — manual control exists; automated RFC1918 CI check active |
| **NFR-04** | Continuous Integration Quality Gate | `docs/architecture.md#ci-cd` | GitHub Actions workflow execution | `.github/workflows/validate.yml` | 🟡 IN PROGRESS — Phase-Aware Workflow Active |



---

## 4. MITRE ATT&CK Enterprise Technique Coverage (V1 Scope)

| MITRE ID | Technique Name | Tactic | Implemented In | Test Case ID | Validation Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **T1110.001** | Brute Force: Password Guessing | Credential Access | `detections/sigma/windows_failed_logon.yml`<br>`correlations/corr_det01_bruteforce_threshold.yml`<br>`correlations/mr_bruteforce_after_failures.yml` | `TC-AUTH-001`<br>`TC-AUTH-003`<br>`TC-POS-001`..`003`<br>`TC-NEG-001`..`012` | 🟢 VALIDATED — Audit PASS (Tag `v0.3.0`, Commit `4bdf920`, CI Run `34933601381`) |
| **T1078.003** | Valid Accounts: Local Accounts | Initial Access / Persistence | `detections/sigma/windows_successful_logon.yml`<br>`correlations/mr_bruteforce_after_failures.yml` | `TC-AUTH-002`<br>`TC-AUTH-003`<br>`TC-POS-002`..`003`<br>`TC-NEG-001`..`012` | 🟢 VALIDATED — Audit PASS (Commit `015bb1e`, CI Run `34935781996`) |
| **T1059.001** | Command & Scripting Interpreter: PowerShell | Execution | `detections/sigma/windows_suspicious_powershell.yml`<br>`telemetry/generators/gen-powershell-events.ps1` | `TC-AUTH-004`<br>`TC-POS-004`..`005`<br>`TC-NEG-013`..`016` | 🟢 VALIDATED — Audit PASS (Commit `661e41e`, CI Quality Gate Badge: Passing) |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | Lateral Movement | `detections/sigma/windows_smb_admin_shares.yml`<br>`docs/detections/DET-04-windows-smb-admin-shares.md`<br>`telemetry/generators/gen-smb-events.ps1` | `TC-AUTH-005`<br>`TC-POS-006`..`007`<br>`TC-NEG-017`..`020` | 🟡 IMPLEMENTED — DET-04 Canonical Rule, Translations & 7-Case Boundary Engine Verified |

---

## 5. Summary Metrics (V1 Target Gate)

* **Total Functional Requirements:** 8
* **Total Non-Functional Requirements:** 4
* **Total Requirements:** 12
* **Current Status:** 4 Validated (FR-01, FR-02, FR-03, FR-04) / 12 Initialized (Target: 12/12 Passed for V1.0.0 Tag)
