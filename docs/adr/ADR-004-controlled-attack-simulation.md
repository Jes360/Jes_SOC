# ADR-004: Controlled, Authentic Telemetry Generation vs. Synthetic Event Injection

**Status:** Accepted  
**Date:** 2026-09-14  
**Context:** Telemetry Verification & Attack Simulation  

---

## 1. Context and Problem Statement

To test detection rules, engineers often face two choices: injecting synthetic event log records into a log collector (e.g. manufacturing raw JSON logs with spoofed IP addresses), or triggering authentic operating system activity that causes the kernel and security subsystems to emit genuine audit events. We must decide which method serves as our validation standard.

## 2. Decision Drivers

* **Technical Defensibility:** The telemetry must reflect real operating system behavior, genuine logon sessions, and actual Windows security structures.
* **Avoidance of False Claims:** Fabricating an event containing a spoofed external IP and calling it "Windows Event 4625" is technically indefensible because Windows generates 4624/4625 events when a logon session is created or rejected by the Local Security Authority Subsystem Service (LSASS).
* **Safety & Non-Destructiveness:** Activities must remain strictly contained within the test boundary, posing zero risk to host stability.

## 3. Decision Outcome

**Chosen Option: Authentic Authentication Activity Generation.**

1. Test generators in `telemetry/generators/` will execute genuine authentication calls via native Windows APIs (e.g. `LogonUser` via .NET / Win32 API, or controlled network authentication via SMB/loopback).
2. The operating system itself will generate authentic Event 4625 and Event 4624 records in the Windows Security Event Log.
3. Test harnesses will extract and evaluate the actual resulting event fields (`TargetUserName`, `LogonType`, `WorkstationName`, `IpAddress`).
4. Synthetic event files will only be used as read-only fixtures for offline CI unit tests in `.github/workflows/`, and will be clearly identified as test fixtures.
