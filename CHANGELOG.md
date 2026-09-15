# Changelog

All notable changes to **JestineSOC** will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
