# ADR-003: Multi-Target SIEM Translation Strategy

**Status:** Accepted  
**Date:** 2026-09-14  
**Context:** Detection Engineering Pipeline  

---

## 1. Context and Problem Statement

When compiling canonical Sigma rules to target SIEM query languages such as Splunk SPL and Microsoft Sentinel KQL, automated transpilers often produce valid syntax but may fail to preserve nuanced temporal or stateful semantics—especially with multi-event correlations. We need a defined strategy for managing target query generation without causing rule drift.

## 2. Decision Drivers

* **Semantic Fidelity:** The derived SPL or KQL query must execute the identical detection logic as the canonical Sigma rule.
* **Traceability:** Reviewers must be able to verify how a Sigma field maps to a Splunk index or Sentinel table.
* **Handling Backend Limitations:** Transparently documenting where a backend lacks native support for a specific correlation mechanism.

## 3. Decision Outcome

**Chosen Option: Canonical Compilation with Documented Translation Caveats.**

1. Automated translation using `sigma-cli` / `pySigma` is the default starting point.
2. Each translated query is placed in `/detections/splunk/` and `/detections/kql/`.
3. If an automated translation requires manual optimization (e.g. replacing a generic search with an indexed `tstats` query in Splunk, or using `join kind=inner` vs `summarize` in KQL), the divergence must be documented in a Translation Notes section.
4. The canonical Sigma rule remains the single source of truth; no logic changes may be introduced in the target queries without first updating the Sigma specification.
