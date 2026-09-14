# JestineSOC: Architecture Specification & NIST CSF 2.0 Alignment

**Document ID:** ARC-V1-SPEC  
**Version:** v0.1.0  
**Framework Standards:** NIST SP 800-61 Rev. 3, NIST Cybersecurity Framework (CSF) 2.0  

---

## 1. System Architecture Overview

JestineSOC operates a decoupled, multi-tier detection engineering pipeline. The architecture decouples telemetry generation, event capture, canonical detection definition, stateful correlation, and structured incident investigation.

```mermaid
flowchart TD
    subgraph SENSORS["1. Telemetry Generation & Sensors"]
        WIN_SEC["Windows Security Auditing (Events 4624, 4625, 4688)"]
        SYSMON["Microsoft Sysinternals Sysmon (Events 1, 3)"]
        GEN_AUTH["telemetry/generators/gen-auth-events.ps1"] -->|Triggers| WIN_SEC
        GEN_PS["telemetry/generators/gen-powershell-events.ps1"] -->|Triggers| SYSMON
    end

    subgraph LOG_STORE["2. Event Store & Normalization"]
        EVTX["Windows Event Log Service"]
        DATA_MODEL["Normalized Data Dictionary (docs/data-model.md)"]
        WIN_SEC --> EVTX
        SYSMON --> EVTX
        EVTX --> DATA_MODEL
    end

    subgraph DETECTION_ENGINE["3. Canonical Detection & Correlation"]
        SIGMA_ATOMIC["Canonical Atomic Rules (detections/sigma/)"]
        SIGMA_CORR["Sigma Correlation 2.1.0 (correlations/)"]
        DATA_MODEL --> SIGMA_ATOMIC
        SIGMA_ATOMIC --> SIGMA_CORR
        SIGMA_ATOMIC -.->|Compile| SPL["Splunk SPL Target"]
        SIGMA_ATOMIC -.->|Compile| KQL["Sentinel KQL Target"]
    end

    subgraph TEST_HARNESS["4. Testing & Verification"]
        POS_TEST["Positive Test Suite (tests/positive/)"]
        NEG_TEST["Negative Test Suite (tests/negative/)"]
        SIGMA_CORR --> POS_TEST
        SIGMA_CORR --> NEG_TEST
        POS_TEST --> EV_DIR["Sanitized Evidence (/evidence/)"]
        NEG_TEST --> EV_DIR
    end

    subgraph INCIDENT_RESPONSE["5. Operational Response & Analysis"]
        PLAYBOOK["Playbooks (playbooks/)"]
        REPORT["NIST CSF 2.0 Incident Report (reports/incident-001.md)"]
        EV_DIR --> REPORT
        PLAYBOOK --> REPORT
    end
```

---

## 2. NIST Cybersecurity Framework (CSF) 2.0 Integration

In strict alignment with **NIST SP 800-61 Rev. 3** (finalized April 2025), incident response is structured across all six core functions of **NIST CSF 2.0**:

| CSF 2.0 Function | Specific NIST Category / Subcategory | JestineSOC Platform Implementation |
| :--- | :--- | :--- |
| **GOVERN (GV)** | `GV.OC-01`, `GV.PO-01` (Organizational Context & Policy) | Explicit requirements (`docs/requirements.md`), ADRs (`docs/adr/`), and testing criteria established prior to implementation. |
| **IDENTIFY (ID)** | `ID.AM-01`, `ID.RA-01` (Asset Management & Risk Assessment) | Asset inventory and threat modeling documented in `docs/threat-model.md` with explicit in-scope/out-of-scope boundaries. |
| **PROTECT (PR)** | `PR.AA-01`, `PR.PS-01` (Identity Management & Data Security) | Credential protection standards, local audit baseline enforcement (`telemetry/windows/audit-policy.md`), and pre-commit secret hygiene. |
| **DETECT (DE)** | `DE.CM-01`, `DE.AE-01` (Continuous Monitoring & Adverse Event Detection) | Tuned Sysmon configuration (`telemetry/sysmon/`), canonical Sigma atomic rules, and temporal correlation rules under Sigma Correlation Spec 2.1.0. |
| **RESPOND (RS)** | `RS.MA-01`, `RS.AN-01`, `RS.MI-01` (Incident Management, Analysis & Mitigation) | Operational incident response playbooks (`playbooks/account-compromise.md`) and Tier-1/Tier-2 forensic timeline reconstruction in `reports/incident-001.md`. |
| **RECOVER (RC)** | `RC.RP-01` (Recovery Execution & Restoration) | Account credential reset procedures, isolation rollback routines, and post-incident detection tuning documented in investigation reports. |

---

## 3. Data Flow & Sensor Boundaries

1. **Authentication Sensor:** Uses local LSASS security event generation. The telemetry script `gen-auth-events.ps1` calls legitimate Windows logon APIs using test accounts, ensuring Windows generates genuine 4625/4624 events with authentic logon types.
2. **Process Sensor:** Sysmon driver intercepts process execution and logs full command-line strings, parent-child process relationships, and unique `ProcessGuid` values.
3. **Correlation Engine:** Evaluates events temporally. A correlation alert is emitted only when the defined threshold of Event 4625 records matches within the sliding time window and is terminated by an Event 4624 record sharing the same `TargetUserName` and `WorkstationName`/`IpAddress`.
