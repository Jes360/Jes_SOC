# Changelog

All notable changes to **JestineSOC** will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
