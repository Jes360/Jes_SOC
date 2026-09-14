# ADR-005: AI Boundary Governance and Exclusion from V1 Execution

**Status:** Accepted  
**Date:** 2026-09-14  
**Context:** Security Operations & AI Integration  

---

## 1. Context and Problem Statement

Generative AI and Large Language Models (LLMs) are increasingly marketed as autonomous security analysts. However, in security operations, unconstrained AI integration introduces acute risks: hallucinations, unverified attribution, false closures of active incidents, and unauthorized execution of containment actions. We must define the operational boundary of AI within JestineSOC.

## 2. Decision Drivers

* **Deterministic Grounding:** Security operations must be rooted in verifiable telemetry, deterministic detection rules, and reproducible tests.
* **Human-in-the-Loop Requirement:** Autonomous actions that alter production state or close security incidents violate core defensive security standards.
* **Portfolio Defensibility:** Demonstrating solid engineering foundations (V1) before introducing AI (V5) proves genuine competence rather than reliance on external AI generation.

## 3. Decision Outcome

**Chosen Option: Strict Human-in-the-Loop Governance & Deferral of AI Execution to Version 5.**

1. **Version 1 Scope:** AI execution is strictly excluded from V1. The pipeline will operate on deterministic Sigma logic and empirical telemetry.
2. **Future Boundary Defined:** `docs/ai-validation.md` establishes strict boundaries:
   * **AI May:** Summarize timeline evidence, suggest investigative hypotheses, propose MITRE ATT&CK technique tags, and draft preliminary incident notes.
   * **AI May NOT:** Independently close an incident, mark an IOC as benign or malicious without corroborating evidence, alter host or network configurations, isolate hosts, or serve as the authoritative evidence source.
3. **Empirical Benchmarking:** When implemented in V5, the AI assistant will be evaluated against a benchmark dataset of 20 realistic incidents with explicit scoring for factual accuracy and hallucination rate.
