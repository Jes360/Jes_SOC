# Changelog

All notable changes to **JestineSOC** will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0-phase3] - 2026-09-16
### Added
- **SCEN-01 Specification:** Authored comprehensive scenario documentation `docs/scenarios/SCEN-01-compromise-to-lateral-movement.md` detailing the 4-stage intrusion lifecycle (`APT-LAB-01`), MITRE ATT&CK coverage (`T1110.001`, `T1078.003`, `T1059.001`, `T1027`, `T1021.002`), chronological 180-second telemetry timeline, alert fusion incident model (`INC-2026-001`), and scope limitations `SL-15` and `SL-16`.
- **Integrated Test Harness:** Created `tests/integration/test_e2e_threat_scenario.ps1` orchestrating the sequential execution of all 4 attack stages under strictly benign OS operations.
- **Integrated Evaluation Engine:** Authored `tests/runners/eval_e2e_scenario.py` evaluating 3 primary end-to-end integration scenarios:
  - `TC-E2E-001`: Full True Positive 4-stage intrusion chain asserting temporal ordering ($t_1 \le t_2 \le t_3 \le t_4$) across `DET-01-PRIM`, `DET-02-PRIM`, `CORR-01`, `DET-03`, and `DET-04`.
  - `TC-E2E-002`: Broken attack chain verifying that credential brute-force without subsequent logon success leaves `CORR-01` strictly silent.
  - `TC-E2E-003`: Benign operational noise verifying that unencoded PowerShell and standard user share access (`PublicReports`) suppress `DET-03` and `DET-04`.
- **Committed Forensic Evidence:** Generated sanitized scenario evidence `evidence/scenarios/ev-scen-01-boundary-matrix.json`, `ev-scen-01-execution-proof.json`, and `ev-scen-01-timeline.json`.
- **CI Quality Gate Expansion:** Wired `eval_e2e_scenario.py` into `.github/workflows/validate.yml`, expanding total automated CI test battery to **41 / 41 test cases**.
- **Traceability Updates:** Promoted `FR-05` (Negative Testing & FP Suppression) and `T1021.002` (DET-04) to `VALIDATED` in `docs/traceability-matrix.md`.

## [0.3.4-det04] - 2026-09-16
### Added
- **DET-04 Specification:** Authored complete 23-section detection specification `docs/detections/DET-04-windows-smb-admin-shares.md` defining the SMB administrative share access detection (`DET-04`), ATT&CK `T1021.002` (Remote Services: SMB/Windows Admin Shares) mapping, scope limitations `SL-12`, `SL-13`, and `SL-14`, and 5-stage SOC triage playbook.
- **Canonical Sigma Rule:** Created `detections/sigma/windows_smb_admin_shares.yml` (`level: high`) targeting Security Event 5140/5145 (`ShareName` matching `*\\C$`, `*\\ADMIN$`, `*\\IPC$`) and Sysmon Event 3 (`DestinationPort: 445`), with system and machine account (`*$`) suppression.
- **Derived SIEM Translations:** Built `detections/splunk/windows_smb_admin_shares.spl` and `detections/kql/windows_smb_admin_shares.kql` supporting multi-source union over Windows Security Share Access and Sysmon Network Connection events.
- **Controlled Telemetry Generator:** Implemented `telemetry/generators/gen-smb-events.ps1` strictly adhering to the benign lab simulation policy (executing harmless share discovery `Get-SmbShare` and loopback `\\127.0.0.1\IPC$` connection).
- **Automated Evaluation Engine & Boundary Suite:** Implemented `tests/runners/eval_det04_engine.py` and `tests/test_det04_boundary_suite.ps1` evaluating authentic Sysmon Event 3 (`TC-AUTH-005`) from `sysmon-sample.json` and 6 boundary conditions (`TC-POS-006`..`007`, `TC-NEG-017`..`020`), generating `evidence/detections/ev-det-04-boundary-matrix.json` and `ev-det-04-execution-proof.json`.
- **CI Pipeline Integration:** Integrated `eval_det04_engine.py` into `.github/workflows/validate.yml` expanding automated test suite to 38 test cases.
- **Traceability Updates:** Promoted `FR-02` and `T1059.001` (DET-03) to `VALIDATED`; advanced `T1021.002` (DET-04) to `IMPLEMENTED` with full empirical lineage.

## [0.3.3-det03] - 2026-09-16
### Added
- **DET-03 Specification:** Authored complete 23-section detection specification `docs/detections/DET-03-windows-suspicious-powershell.md` defining the suspicious encoded execution primitive (`DET-03`), ATT&CK `T1059.001` and `T1027` mappings, scope limitations `SL-09`, `SL-10`, and `SL-11`, and 5-stage SOC triage playbook.
- **Canonical Sigma Rule:** Created `detections/sigma/windows_suspicious_powershell.yml` (`level: high`) targeting `powershell.exe` and `pwsh.exe` with base64 encoded command argument variations (`-EncodedCommand`, `-encoded`, `-enc`, `-e`, `/enc`, `/e`, etc.) across space and equals delimiters.
- **Derived SIEM Translations:** Built `detections/splunk/windows_suspicious_powershell.spl` and `detections/kql/windows_suspicious_powershell.kql` supporting multi-source union over Sysmon Event 1 and Windows Security Event 4688.
- **Controlled Telemetry Generator:** Implemented `telemetry/generators/gen-powershell-events.ps1` strictly adhering to the benign lab simulation policy (executing harmless discovery commands `Write-Output`, `Get-Date`, `hostname`).
- **Automated Evaluation Engine & Boundary Suite:** Implemented `tests/runners/eval_det03_engine.py` and `tests/test_det03_boundary_suite.ps1` evaluating authentic Sysmon Event 1 (`TC-AUTH-004`) from `sysmon-sample.json` and 6 boundary conditions (`TC-POS-004`..`005`, `TC-NEG-013`..`016`), generating `evidence/detections/ev-det-03-boundary-matrix.json` and `ev-det-03-execution-proof.json`.
- **CI Pipeline Integration:** Wired `eval_det03_engine.py` into `.github/workflows/validate.yml`.
- **Traceability Updates:** Promoted `FR-04` and `CORR-01` to `VALIDATED`; advanced `FR-02` and `T1059.001` to `IMPLEMENTED` with complete audit lineage.

## [0.3.2-corr01] - 2026-09-16
### Added
- **CORR-01 Specification:** Authored complete 23-section detection specification `docs/correlations/CORR-01-mr_bruteforce_after_failures.md` defining the composite multi-event correlation rule (`CORR-01`), ATT&CK `T1110.001` and `T1078.003` mappings, scope limitations `SL-06`, `SL-07`, and `SL-08`, and 5-stage SOC triage checklist.
- **Canonical Sigma 2.1.0 Correlation:** Created `correlations/mr_bruteforce_after_failures.yml` (`level: critical`, `action: correlation`, `type: temporal`, `ordered: true`) correlating >= 5 Event 4625 failures followed by >= 1 Event 4624 success within a 5-minute sliding window grouped by `TargetUserName` and `IpAddress`.
- **Derived SIEM Translations:** Built `detections/splunk/mr_bruteforce_after_failures.spl` (using `transaction maxspan=5m startswith/endswith`) and `detections/kql/mr_bruteforce_after_failures.kql` (using Sentinel inner join bounded by `SuccessTime between (LastFailure .. LastFailure + 5m)`).
- **Automated Evaluation Engine & Boundary Suite:** Implemented `tests/runners/eval_corr01_engine.py` and `tests/test_corr01_boundary_suite.ps1` evaluating authentic LSASS Records 80211-80216 (`TC-AUTH-003`) and 7 boundary conditions (`TC-POS-003`, `TC-NEG-007` through `TC-NEG-012`), generating `evidence/correlations/ev-corr-01-boundary-matrix.json` and `ev-corr-01-execution-proof.json`.
- **CI Pipeline Integration:** Integrated `eval_corr01_engine.py` into `.github/workflows/validate.yml` under GitHub Actions.
- **Traceability Updates:** Promoted `FR-01` and `T1078.003` to `VALIDATED` in `docs/traceability-matrix.md`; advanced `FR-04` to `IMPLEMENTED` with full lineage.

## [0.3.1-det02] - 2026-09-15
### Added
- **DET-02 Specification:** Authored complete 23-section detection specification `docs/detections/DET-02-windows-successful-logon.md` defining the network authentication success primitive (`DET-02-PRIM`), ATT&CK `T1078.003` mapping, scope limitations `SL-04` and `SL-05`, and downstream correlation role (`CORR-01`).
- **Canonical Sigma Primitive:** Created `detections/sigma/windows_successful_logon.yml` (`level: low`) targeting Event 4624 (LogonType 3) with machine account (`*$`) and well-known system service account exclusions.
- **Derived SIEM Translations:** Built `detections/splunk/windows_successful_logon.spl` and `detections/kql/windows_successful_logon.kql` with translation headers and documented noise classification.
- **Automated Evaluation Engine & Evidence:** Implemented `tests/runners/eval_det02_engine.py` and `tests/test_det02_boundary_suite.ps1` evaluating authentic LSASS Record 80216 and 7 boundary conditions, generating `evidence/detections/ev-det-02-boundary-matrix.json` and `ev-det-02-execution-proof.json`.
- **CI Pipeline Integration:** Wired DET-02 evaluation engine natively into `.github/workflows/validate.yml`.

## [0.3.0] - 2026-09-15
### Milestone
- **DET-01 Promoted to Validated:** Formal Auditor PASS achieved.
- **Scope Limitations (SL-01, SL-02, SL-03):** Formally codified low-and-slow threshold evasion, proxy IP rotation, and horizontal spray non-claims in `docs/detections/DET-01-windows-failed-logon.md`.
- **Authentic Telemetry Ingestion (TC-AUTH-001):** Validated authentic LSASS Event 4625 records via automated evaluation engine executed natively in GitHub Actions CI.
- **SIEM Alignment (F-15 & F-16):** Documented Sentinel KQL `WorkstationName` grouping key divergence and clarified scheduled lookback window in `detections/kql/windows_failed_logon.kql`.

## [0.3.0-det01-closure] - 2026-09-15
### Fixed
- **DET01-01 (Canonical Semantic Split):** Factored DET-01 into a two-tier canonical architecture: (1) Atomic Event Primitive `DET-01-PRIM` (`detections/sigma/windows_failed_logon.yml`) and (2) Canonical Threshold Correlation `CORR-DET01` (`correlations/corr_det01_bruteforce_threshold.yml`) strictly conforming to Sigma Correlation Specification 2.1.0 (`type: event_count`, `timespan: 5m`, `condition: gte: 5`).
- **DET01-02 (Comprehensive Boundary Test Suite):** Implemented the 5-case boundary matrix mandated by the Auditor (`NEG-001` $N=1$, `NEG-002` $N=4$, `POS-001` $N=5$, `POS-002` $N=6$, `NEG-003` $N=5$ over $>5\text{m}$) plus control cases (`NEG-004` machine account filter, `NEG-005` horizontal spray), achieving 100% boundary assertion pass rate in `tests/test_det01_boundary_suite.ps1`.
- **DET01-03 (Backend Execution Proof):** Authored `tests/runners/eval_det01_engine.py` providing programmatic evaluation of raw event streams against canonical correlation logic, producing auditable execution proof in `evidence/detections/ev-det-01-execution-proof.json` and `ev-det-01-boundary-matrix.json`.
- **DET01-04 (SIEM Semantic Alignment & FP Realism):** Formulated the complete Semantic Reconciliation Matrix in `docs/detections/DET-01-windows-failed-logon.md` resolving all dialect, field, and windowing mappings across Sigma, Splunk SPL (`streamstats`), and Sentinel KQL (Approach A tumbling vs Approach B sliding). Calibrated vulnerability scanner false-positive documentation to distinguish production asset identity from RFC 5737 sanitized evidence.

## [0.3.0-det01] - 2026-09-15
### Added
- **DET-01 Specification:** Authored complete 23-section detection specification `docs/detections/DET-01-windows-failed-logon.md` detailing the password-guessing analytic hypothesis, threshold rationale, 5 SOC investigation questions, and MITRE `T1110.001` mapping.
- **Canonical Sigma Rule:** Created `detections/sigma/windows_failed_logon.yml` targeting Windows Event 4625 (LogonType 3, status `0xc000006d` / substatus `0xc000006a`) with machine-account exclusion filters.
- **Derived SIEM Translations:** Developed `detections/splunk/windows_failed_logon.spl` and `detections/kql/windows_failed_logon.kql` with comprehensive architectural translation headers and documented semantic divergences (sliding vs tumbling windows).
- **Automated Test Harnesses:** Built positive attack simulation harness `tests/positive/test_failed_logon_positive.ps1` (`TC-POS-001`) and negative benign suppression harness `tests/negative/test_failed_logon_negative.ps1` (`TC-NEG-001`).
- **Empirical Evidence Artifacts:** Generated and committed sanitized execution evidence `evidence/detections/ev-det-01-positive.json` and `evidence/detections/ev-det-01-negative.json`.
- **Traceability Updates:** Mapped `FR-03` and `T1110.001` in `docs/traceability-matrix.md` to `IMPLEMENTED` with linked test harnesses and evidence.

## [0.3.0-gate0] - 2026-09-15
### Added
- **Phase 2 Gate 0 Architecture:** Established canonical 23-section Detection Specification Template (`docs/templates/detection-spec-template.md`) mandating threat hypotheses, explicit non-claims, 4-dimensional correlation keys, and empirical positive/negative testing fields.
- **Evidence-Driven Maturity Model:** Documented 5-stage lifecycle (`Experimental` $\rightarrow$ `Functional` $\rightarrow$ `Validated` $\rightarrow$ `Tuned` $\rightarrow$ `Production-Candidate`) in `docs/detection-engineering.md`, enforcing that Sigma linting does not equate to detection validation.
- **Correlation Key Architecture:** Specified 4D grouping standard for `CORR-01`: $\text{same account} + \text{same source} + \text{same destination} + \text{defined time window}$.
- **Traceability Updates:** Mapped `FR-03` and `FR-04` to the Gate 0 specification standard in `docs/traceability-matrix.md`.

## [0.2.2] - 2026-09-15
### Fixed
- **P1-07 (Verification Completeness & Logic Tightening):** Closed verification loophole in `telemetry/generators/gen-auth-events.ps1` by enforcing strict multi-factor equality: `FailuresRequested == FailuresEmitted == FailuresObserved` AND `SuccessRequested == SuccessEmitted == SuccessObserved`.
- **Query Boundary Hardening:** Bounded `Get-WinEvent` Security log query with both lower (`StartTime`) and upper (`EndTime`) time limits, preventing historical event false matching.
- **Event Record Identification:** Enriched verification engine to extract and record the unique operating system `RecordId`, `EventID`, `TimeCreated`, `TargetUserName`, and `LogonType` for every observed event.
- **Terminology Calibration:** Corrected event generation terminology to reflect authentic OS causality: *"A successful native Windows authentication was performed, causing Windows Security auditing to record Event 4624."*
- **Evidence Provenance & Lineage:** Documented the 7-stage chain of custody in `evidence/telemetry/README.md` and enriched `evidence/telemetry/evtx-auth-sample.json` with an explicit `ProvenanceChain` and individual event `RecordId` fields.
- **Full Supply Chain Pinning:** Pinned all third-party GitHub Actions in `.github/workflows/validate.yml` to immutable commit SHAs (`actions/checkout@11d5960a3267...`, `actions/setup-python@a26af69b...`, `trufflesecurity/trufflehog@4b7d1d3a...`).
- **NFR-03 Calibration:** Calibrated verification wording in `docs/traceability-matrix.md` and CI workflow to accurately reflect automated RFC 1918 private-IP checking.

## [0.2.1] - 2026-09-14
### Fixed
- **P1-01 (CI Pipeline):** Made Sigma rule and correlation validation steps in GitHub Actions phase-aware, preventing premature failures on empty directories during Phase 1.
- **P1-02 (Authentic 4624 Generation):** Removed synthetic branch from `telemetry/generators/gen-auth-events.ps1`; successful authentication strictly invokes Win32 `LogonUserW` with a genuine password.
- **P1-03 (Programmatic Event Verification):** Integrated post-execution `Get-WinEvent` verification into `gen-auth-events.ps1` to assert that Security log received the expected event count.
- **P1-04 (Evidence Metadata & Provenance):** Added structured `ExecutionMetadata` block to `evidence/telemetry/evtx-auth-sample.json` detailing RunId, TestCaseId, execution command, start/end timestamps, requested counts, and observed counts.
- **P1-05 (Traceability Calibration):** Calibrated FR-01 and FR-02 in `docs/traceability-matrix.md` from `VALIDATED` to `IMPLEMENTED — Generator & Schema Functional; Sample Logged`, reserving `VALIDATED` for Phase 3 integration testing.
- **P1-06 (Supply Chain Security):** Pinned `trufflesecurity/trufflehog` in `.github/workflows/validate.yml` to immutable commit SHA (`4b7d1d3a6827691637eff750b6482042e06462d0`).
- **CI Shell Robustness:** Converted PowerShell syntax validation job step in `.github/workflows/validate.yml` to native `shell: pwsh`.

## [0.2.0] - 2026-09-14
### Added
- Authored Windows Security Audit policy specification (`telemetry/windows/audit-policy.md`) detailing Events 4624, 4625, and 4688.
- Developed tuned laboratory Sysmon configuration (`telemetry/sysmon/sysmon-config.xml`) for Event 1 (Process Creation) and Event 3 (Network Connection).
- Created authentic authentication event generator (`telemetry/generators/gen-auth-events.ps1`) using native Win32 `LogonUserW` API without synthetic log fabrication.
- Created controlled process execution generator (`telemetry/generators/gen-powershell-events.ps1`) simulating T1059.001 encoded command behaviors.
- Captured and logged sanitized JSON telemetry evidence for Event 4624/4625 (`evidence/telemetry/evtx-auth-sample.json`) and Sysmon Event 1/3 (`evidence/telemetry/sysmon-sample.json`).
- Updated master traceability matrix (`docs/traceability-matrix.md`) validating FR-01 and FR-02.

## [0.1.0] - 2026-09-14

### Added
- Initialized core repository skeleton and governance architecture.
- Authored master requirements specification (`docs/requirements.md`) establishing functional requirements (FR-01 to FR-08), non-functional requirements (NFR-01 to NFR-04), detection maturity levels, and explicit non-claims.
- Established master traceability matrix (`docs/traceability-matrix.md`) mapping requirements to design, detections, test cases, and evidence.
- Authored laboratory environment specification (`docs/lab-environment.md`) detailing Windows OS prerequisites, audit policies, Sysmon, and test accounts.
- Created Architecture Decision Records (`ADR-001` through `ADR-005`) documenting canonical Sigma selection, Sysmon boundaries, SIEM translation strategy, authentic telemetry generation, and AI safety governance.
- Documented normalized field dictionary (`docs/data-model.md`) mapping fields across Windows Events 4624, 4625 and Sysmon Events 1, 3.
- Authored threat modeling boundaries (`docs/threat-model.md`) scoped to T1110.001, T1078.003, T1059.001, and T1021.002.
- Documented NIST SP 800-61 Rev. 3 and CSF 2.0 system architecture (`docs/architecture.md`).
- Authored detection engineering methodology (`docs/detection-engineering.md`) and positive/negative testing matrix.
- Established future AI safety boundaries and evaluation benchmark (`docs/ai-validation.md`).
- Configured CI/CD automated linting and validation pipeline (`.github/workflows/validate.yml`).
