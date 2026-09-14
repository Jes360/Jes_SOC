# Security & Sanitization Policy

## 1. Evidence Sanitization & Responsible Disclosure

JestineSOC is a public defensive security laboratory. In compliance with **NFR-02 (Credential & Secret Hygiene)** and **NFR-03 (Evidence Sanitization)**:

* **No Production Secrets:** No active API keys, production tokens, private SSH keys, or live passwords are stored in this repository.
* **Sanitized Artifacts:** All telemetry captures, event logs, and incident reports committed to `/evidence/` utilize sanitized RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 2606 reserved domains (`.local`, `.example`), and synthetic usernames (`lab_user_test`, `analyst_test`).
* **Safe Telemetry Generation:** Attack simulations generate authentic operating system audit events via safe Windows API calls targeting local non-destructive endpoints. No external network scanning or exploit payloads are utilized.

## 2. Reporting Potential Exposure

If you identify an accidental inclusion of sensitive personal data or un-sanitized infrastructure information in this repository, please report it immediately:

* **Maintainer:** Jestine Jojo
* **Communication Channel:** GitHub Issues (tagged `security-review`) or direct communication via LinkedIn.
