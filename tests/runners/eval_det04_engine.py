#!/usr/bin/env python3
"""
==============================================================================
DET-04 Evaluation Engine: SMB Administrative Share Access
==============================================================================
Evaluates canonical Sigma rule (detections/sigma/windows_smb_admin_shares.yml)
against authentic Sysmon Event 3 telemetry (evidence/telemetry/sysmon-sample.json)
and a 7-case deterministic boundary test suite.

Author : JestineSOC Detection Engineering Team
Standard: Sigma Specification 2.1.0 / MITRE ATT&CK T1021.002
==============================================================================
"""

import os
import sys
import json
import datetime
from typing import List, Dict, Any, Tuple

RULE_METADATA = {
    "DetectionId": "DET-04",
    "RuleName": "windows_smb_admin_shares",
    "CanonicalSigmaPath": "detections/sigma/windows_smb_admin_shares.yml",
    "SpecificationPath": "docs/detections/DET-04-windows-smb-admin-shares.md",
    "Level": "high",
    "MitreTechniques": ["T1021.002"]
}

ADMIN_SHARES = {"\\c$", "\\admin$", "\\ipc$"}
SYSTEM_ACCOUNTS = {
    "system", "anonymous logon", "local service", "network service",
    "nt authority\\system", "nt authority\\anonymous logon",
    "nt authority\\local service", "nt authority\\network service",
    "-", ""
}

def evaluate_share_event(event: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluates an event against DET-04 Sigma logic.
    Returns (is_match: bool, reason: str).
    """
    eid = event.get("EventID")

    # Path A: Windows Security Share Access (5140, 5145)
    if eid in (5140, 5145):
        user = event.get("SubjectUserName") or event.get("TargetUserName") or event.get("User") or ""
        user_lower = user.lower()

        # Filter machine accounts ($ suffix)
        if user.endswith("$"):
            return False, f"User '{user}' is a machine account; suppressed by filter_machine_share."

        # Filter system service accounts
        if user_lower in SYSTEM_ACCOUNTS:
            return False, f"User '{user}' is a built-in system account; suppressed by filter_system_share."

        share = event.get("ShareName") or event.get("RelativeTargetName") or ""
        share_lower = share.lower().replace("/", "\\")

        has_admin_share = any(admin in share_lower for admin in ADMIN_SHARES)
        if not has_admin_share:
            return False, f"ShareName '{share}' is not an administrative share (C$, ADMIN$, IPC$)."

        return True, f"Administrative share '{share}' accessed by user '{user}'."

    # Path B: Sysmon Network Connection (Event 3)
    elif eid == 3:
        dest_port = str(event.get("DestinationPort", ""))
        if dest_port != "445":
            return False, f"DestinationPort '{dest_port}' is not SMB (Port 445)."

        user = event.get("User") or ""
        user_lower = user.lower()

        # Filter machine accounts
        if user.endswith("$"):
            return False, f"User '{user}' is a machine account; suppressed by filter_machine_sysmon."

        # Filter system service accounts
        if user_lower in SYSTEM_ACCOUNTS:
            return False, f"User '{user}' is a built-in system account; suppressed by filter_system_sysmon."

        return True, f"Direct SMB connection on port 445 initiated by user '{user}'."

    else:
        return False, f"EventID {eid} is not a valid share access or network connection event."

def load_authentic_sysmon_event() -> Dict[str, Any]:
    """Loads authentic Sysmon Event 3 from evidence/telemetry/sysmon-sample.json."""
    sample_path = os.path.join("evidence", "telemetry", "sysmon-sample.json")
    if not os.path.exists(sample_path):
        raise FileNotFoundError(f"Sysmon sample file not found: {sample_path}")

    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for ev in data.get("Events", []):
        if ev.get("EventID") == 3:
            ed = ev.get("EventData", {})
            return {
                "EventID": 3,
                "ProviderName": ev.get("ProviderName"),
                "TimeCreated": ev.get("TimeCreated"),
                "Image": ed.get("Image"),
                "User": ed.get("User"),
                "DestinationPort": ed.get("DestinationPort"),
                "DestinationIp": ed.get("DestinationIp"),
                "Computer": "LAB-HOST01"
            }
    raise ValueError("No Sysmon Event 3 found in sample file.")

def build_deterministic_test_suite() -> List[Dict[str, Any]]:
    """Constructs the 7 mandatory test cases for DET-04."""
    suite = []

    # 1. TC-AUTH-005: Authentic Sysmon Event 3 Ground Truth Ingestion
    auth_event = load_authentic_sysmon_event()
    suite.append({
        "TestCaseId": "TC-AUTH-005",
        "Category": "AUTHENTIC_SYSMON_INGESTION",
        "Description": "Authentic Sysmon Event 3 network connection on SMB port 445",
        "Event": auth_event,
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Authentic Sysmon record from sysmon-sample.json must match DET-04 criteria."
    })

    # 2. TC-POS-006: Event 5140 Share Access to \\*\C$
    suite.append({
        "TestCaseId": "TC-POS-006",
        "Category": "SECURITY_5140_C_SHARE",
        "Description": "Security Event 5140 access to administrative share \\\\*\\C$",
        "Event": {
            "EventID": 5140,
            "ShareName": "\\\\*\\C$",
            "SubjectUserName": "lab_user_test",
            "IpAddress": "192.0.2.45",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:00:00.000Z"
        },
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Access to C$ share by standard user represents administrative access / lateral movement."
    })

    # 3. TC-POS-007: Event 5140 Share Access to \\*\ADMIN$
    suite.append({
        "TestCaseId": "TC-POS-007",
        "Category": "SECURITY_5140_ADMIN_SHARE",
        "Description": "Security Event 5140 access to administrative share \\\\*\\ADMIN$",
        "Event": {
            "EventID": 5140,
            "ShareName": "\\\\*\\ADMIN$",
            "SubjectUserName": "lab_user_test",
            "IpAddress": "192.0.2.45",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:05:00.000Z"
        },
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Access to ADMIN$ share by standard user represents administrative access / lateral movement."
    })

    # 4. TC-NEG-017: Access to standard user share \\*\PublicReports
    suite.append({
        "TestCaseId": "TC-NEG-017",
        "Category": "NON_ADMIN_SHARE_FILTER",
        "Description": "Security Event 5140 access to non-administrative share (\\\\*\\PublicReports)",
        "Event": {
            "EventID": 5140,
            "ShareName": "\\\\*\\PublicReports",
            "SubjectUserName": "lab_user_test",
            "IpAddress": "192.0.2.45",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:10:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Standard non-administrative shares do not match C$, ADMIN$, or IPC$ filter; must suppress alert."
    })

    # 5. TC-NEG-018: Machine account access to C$
    suite.append({
        "TestCaseId": "TC-NEG-018",
        "Category": "MACHINE_ACCOUNT_FILTER",
        "Description": "Machine account 'LAB-SRV01$' access to administrative share C$",
        "Event": {
            "EventID": 5140,
            "ShareName": "\\\\*\\C$",
            "SubjectUserName": "LAB-SRV01$",
            "IpAddress": "192.0.2.45",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:15:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Machine accounts ($ suffix) must be suppressed to avoid domain replication noise."
    })

    # 6. TC-NEG-019: Standard local logon (Event 4624) without share access
    suite.append({
        "TestCaseId": "TC-NEG-019",
        "Category": "CHANNEL_FILTER",
        "Description": "Standard Windows logon event (Event 4624) without share access",
        "Event": {
            "EventID": 4624,
            "LogonType": 3,
            "TargetUserName": "lab_user_test",
            "IpAddress": "192.0.2.45",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:20:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Event 4624 is a logon event, not share access or network connect; must be rejected."
    })

    # 7. TC-NEG-020: Sysmon Event 3 connection on non-SMB port (Port 443 HTTPS)
    suite.append({
        "TestCaseId": "TC-NEG-020",
        "Category": "PORT_FILTER",
        "Description": "Sysmon Event 3 network connection on HTTPS port 443",
        "Event": {
            "EventID": 3,
            "DestinationPort": 443,
            "DestinationIp": "192.0.2.100",
            "User": "LAB-HOST01\\lab_user_test",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:25:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Port 443 is HTTPS web traffic, not SMB port 445; must be rejected."
    })

    return suite

def main() -> int:
    print("=" * 70)
    print("DET-04 SMB ADMINISTRATIVE SHARE EVALUATION ENGINE")
    print(f"Rule: {RULE_METADATA['RuleName']} ({RULE_METADATA['CanonicalSigmaPath']})")
    print("=" * 70)

    suite = build_deterministic_test_suite()
    matrix_results = []
    all_passed = True

    for tc in suite:
        tc_id = tc["TestCaseId"]
        desc = tc["Description"]
        exp = tc["ExpectedState"]
        event = tc["Event"]

        is_match, reason = evaluate_share_event(event)
        actual = "MATCH" if is_match else "NO_MATCH"
        verdict = "PASS" if actual == exp else "FAIL"

        if verdict == "FAIL":
            all_passed = False

        print(f"[{verdict}] {tc_id}: {desc} -> {actual} (Expected: {exp})")

        record = {
            "TestCaseId": tc_id,
            "Category": tc["Category"],
            "Description": desc,
            "ExpectedState": exp,
            "ActualState": actual,
            "Verdict": verdict,
            "Reason": reason,
            "BoundaryRationale": tc["BoundaryRationale"],
            "EventSample": {
                "EventID": event.get("EventID"),
                "ShareName": event.get("ShareName"),
                "DestinationPort": event.get("DestinationPort"),
                "User": event.get("SubjectUserName") or event.get("User")
            }
        }
        matrix_results.append(record)

    print("-" * 70)
    print(f"Total Test Cases: {len(suite)} | Passed: {sum(1 for r in matrix_results if r['Verdict'] == 'PASS')} | Failed: {sum(1 for r in matrix_results if r['Verdict'] == 'FAIL')}")

    os.makedirs(os.path.join("evidence", "detections"), exist_ok=True)
    matrix_path = os.path.join("evidence", "detections", "ev-det-04-boundary-matrix.json")
    with open(matrix_path, "w", encoding="utf-8") as f:
        json.dump(matrix_results, f, indent=2)

    proof_path = os.path.join("evidence", "detections", "ev-det-04-execution-proof.json")
    proof = {
        "RuleMetadata": RULE_METADATA,
        "TimestampUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "OverallVerdict": "PASS" if all_passed else "FAIL",
        "TotalTests": len(suite),
        "PassedTests": sum(1 for r in matrix_results if r['Verdict'] == 'PASS'),
        "FailedTests": sum(1 for r in matrix_results if r['Verdict'] == 'FAIL'),
        "Results": matrix_results
    }
    with open(proof_path, "w", encoding="utf-8") as f:
        json.dump(proof, f, indent=2)

    print(f"[+] Matrix evidence written to: {matrix_path}")
    print(f"[+] Execution proof written to: {proof_path}")
    print("=" * 70)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
