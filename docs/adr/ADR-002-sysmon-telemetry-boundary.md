# ADR-002: Endpoint Telemetry Model and Sysmon Scope

**Status:** Accepted  
**Date:** 2026-09-14  
**Context:** Telemetry Engineering  

---

## 1. Context and Problem Statement

Standard Windows Security Event Logs provide essential authentication and system tracking (e.g. Events 4624, 4625), but have significant blind spots regarding process ancestry, command-line arguments, file hashes, and granular network socket creation. Commercial EDR agents (CrowdStrike Falcon, Microsoft Defender for Endpoint) are proprietary and require expensive cloud subscriptions. We need a defensible, standardized endpoint telemetry provider for laboratory detection experiments.

## 2. Decision Drivers

* **Granular Process & Network Visibility:** Ability to correlate child processes with parent commands and outbound network connections.
* **Correlatable Identifiers:** Inclusion of unique identifiers like `ProcessGuid` to correlate process execution with network sockets.
* **Laboratory Feasibility:** Must run reliably on standard Windows 10/11 endpoints without proprietary licensing.
* **Controlled Telemetry Volume:** Must filter benign operating system noise to maintain laboratory reproducibility.

## 3. Decision Outcome

**Chosen Option: Microsoft Sysinternals Sysmon with a tuned laboratory configuration.**

We will deploy Sysmon specifically configured for:
* **Event ID 1 (Process Creation):** Capturing `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, and `ProcessGuid`.
* **Event ID 3 (Network Connection):** Capturing `SourceIp`, `DestinationIp`, `DestinationPort`, and linking them via `ProcessGuid`.

### Explicit Boundary Note
This configuration is designated as a **tuned laboratory configuration** designed for security experiments. It is not designated as "production-grade" because production enterprise deployment requires extensive environment-specific performance tuning, enterprise software exclusion baselining, event-volume throttling, and centralized fleet management (GPO/Intune/SCCM).
