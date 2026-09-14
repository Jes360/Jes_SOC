# ADR-001: Selection of Sigma as Canonical Detection Definition

**Status:** Accepted  
**Date:** 2026-09-14  
**Context:** Detection Engineering Specification  

---

## 1. Context and Problem Statement

A core challenge in detection engineering is multi-platform portability. In real-world security operations, organizations often migrate between SIEM platforms (e.g., Splunk to Microsoft Sentinel, or Elastic to Chronicle) or operate hybrid environments. Maintaining detection logic independently in proprietary query languages (SPL, KQL, EQL) creates technical debt, version drift, and inconsistent detection semantics.

## 2. Decision Drivers

* **Single Source of Truth:** Detection logic must be written and maintained once in a vendor-agnostic format.
* **Modern Specification Support:** The framework must support both atomic conditions and temporal, stateful multi-event correlations (Sigma Correlation Specification 2.1.0).
* **Community & Tooling Ecosystem:** Strong tooling must exist for automated linting, testing, and query conversion (`pySigma`, `sigma-cli`).
* **Educational & Professional Portfolio Value:** Demonstrating proficiency in Sigma illustrates professional detection engineering rather than basic query typing.

## 3. Considered Options

* **Option A: Proprietary First (SPL-first or KQL-first).** Write detection rules in Splunk SPL, then reverse-engineer them into KQL or generic YAML.
* **Option B: Canonical Sigma (Specification 2.1.0).** Author all detection rules as canonical Sigma rules. Derive Splunk SPL, Microsoft Sentinel KQL, and other backend queries via automated or documented compilation.
* **Option C: Custom Internal JSON/YAML Schema.** Create a bespoke rule definition format.

## 4. Decision Outcome

**Chosen Option: Option B — Canonical Sigma.**

All detection logic in JestineSOC will be authored canonically in Sigma format according to the Sigma Specification 2.1.0 and Sigma Correlation Specification 2.1.0. Derived SPL and KQL queries will be generated from these canonical definitions. Where automated translation does not produce semantically equivalent queries due to backend differences, the divergence will be explicitly documented.

### Positive Consequences
* Version control and rule review happen on a single, standardized YAML artifact.
* Eliminates rule divergence between SIEM backends.
* Seamless integration with automated CI/CD linting.

### Negative Consequences / Trade-offs
* Sigma conversion tools may not support every specialized backend feature (e.g., complex SPL transaction or eventstats pipelines). These cases require explicit translation notes.
