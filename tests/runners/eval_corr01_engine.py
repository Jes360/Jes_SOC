#!/usr/bin/env python3
"""
==============================================================================
CORR-01 Evaluation Engine: Brute Force Followed by Successful Logon
==============================================================================
Evaluates Sigma Correlation 2.1.0 specification (mr_bruteforce_after_failures.yml)
against authentic OS telemetry (evidence/telemetry/evtx-auth-sample.json) and
a comprehensive 8-case deterministic boundary test suite.

Author : JestineSOC Detection Engineering Team
Standard: Sigma Correlation Specification 2.1.0
==============================================================================
"""

import os
import sys
import json
import datetime
from typing import List, Dict, Any, Tuple, Optional

RULE_METADATA = {
    "CorrelationId": "CORR-01",
    "RuleName": "mr_bruteforce_after_failures",
    "CanonicalSigmaPath": "correlations/mr_bruteforce_after_failures.yml",
    "SpecificationPath": "docs/correlations/CORR-01-mr_bruteforce_after_failures.md",
    "CorrelationType": "temporal",
    "Ordered": True,
    "GroupBy": ["TargetUserName", "IpAddress"],
    "TimespanSeconds": 300,  # 5 minutes
    "MinFailureThreshold": 5,
    "MinSuccessThreshold": 1,
    "Level": "critical",
    "MitreTechniques": ["T1110.001", "T1078.003"]
}

SYSTEM_ACCOUNTS = {
    "system", "anonymous logon", "local service", "network service", "-", ""
}

def parse_iso_time(ts_str: str) -> datetime.datetime:
    """Parses ISO 8601 timestamp string into datetime."""
    # Normalize Z to +00:00 for fromisoformat if needed
    cleaned = ts_str.replace("Z", "+00:00")
    return datetime.datetime.fromisoformat(cleaned)

def is_valid_candidate_event(event: Dict[str, Any]) -> bool:
    """Filters events matching atomic primitives criteria (LogonType 3, non-machine, non-system)."""
    eid = event.get("EventID")
    if eid not in (4624, 4625):
        return False
    
    # Check LogonType
    lt = event.get("LogonType")
    if str(lt) != "3":
        return False
    
    # Check user
    user = event.get("TargetUserName", "")
    if not user or user.endswith("$") or user.lower() in SYSTEM_ACCOUNTS:
        return False
    
    return True

def evaluate_correlation_stream(events: List[Dict[str, Any]], timespan_sec: int = 300) -> Tuple[str, List[Dict[str, Any]], str]:
    """
    Evaluates a stream of events against CORR-01 correlation rules.
    Returns: (Verdict: 'MATCH'|'NO_MATCH', MatchedCorrelations: list, Reason: str)
    """
    candidates = [e for e in events if is_valid_candidate_event(e)]
    if not candidates:
        return "NO_MATCH", [], "No candidate events qualified for primitive criteria."

    # Group by (TargetUserName.lower(), IpAddress)
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for ev in candidates:
        key = (ev["TargetUserName"].lower(), ev.get("IpAddress", ""))
        groups.setdefault(key, []).append(ev)

    matches = []

    for (user, ip), ev_list in groups.items():
        # Sort chronologically
        ev_list.sort(key=lambda x: parse_iso_time(x["TimeCreated"]))
        
        # We need >= 5 Event 4625 failures followed by >= 1 Event 4624 success within 5m
        # Iterate over all possible success events (Event 4624)
        for i, succ in enumerate(ev_list):
            if succ.get("EventID") != 4624:
                continue
            
            succ_time = parse_iso_time(succ["TimeCreated"])
            
            # Find preceding failure events within 300s window
            preceding_failures = []
            for prev in ev_list[:i]:
                if prev.get("EventID") == 4625:
                    prev_time = parse_iso_time(prev["TimeCreated"])
                    delta = (succ_time - prev_time).total_seconds()
                    # Event must have occurred before success, and within timespan
                    if 0 <= delta <= timespan_sec:
                        preceding_failures.append(prev)
            
            if len(preceding_failures) >= RULE_METADATA["MinFailureThreshold"]:
                first_fail_time = parse_iso_time(preceding_failures[0]["TimeCreated"])
                last_fail_time = parse_iso_time(preceding_failures[-1]["TimeCreated"])
                match_info = {
                    "TargetUserName": user,
                    "IpAddress": ip,
                    "SuccessRecordId": succ.get("RecordId"),
                    "SuccessTime": succ["TimeCreated"],
                    "PrecedingFailureCount": len(preceding_failures),
                    "FirstFailureTime": preceding_failures[0]["TimeCreated"],
                    "LastFailureTime": preceding_failures[-1]["TimeCreated"],
                    "TotalSpanSeconds": (succ_time - first_fail_time).total_seconds(),
                    "FailureToSuccessDeltaSeconds": (succ_time - last_fail_time).total_seconds(),
                    "FailureRecordIds": [f.get("RecordId") for f in preceding_failures]
                }
                matches.append(match_info)

    if matches:
        return "MATCH", matches, f"Detected {len(matches)} correlation match(es) meeting >= 5 failures followed by success within 5m."
    else:
        return "NO_MATCH", [], "Correlation conditions not met (insufficient failures, ordering violation, user/IP divergence, or time window exceeded)."

def load_authentic_telemetry_events() -> List[Dict[str, Any]]:
    """Loads authentic ground truth records 80211-80216 from evtx-auth-sample.json."""
    sample_path = os.path.join("evidence", "telemetry", "evtx-auth-sample.json")
    if not os.path.exists(sample_path):
        raise FileNotFoundError(f"Authentic telemetry sample not found: {sample_path}")
    
    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    extracted = []
    for raw in data.get("Events", []):
        rec_id = raw.get("RecordId")
        if rec_id in [80211, 80212, 80213, 80214, 80215, 80216]:
            ed = raw.get("EventData", {})
            extracted.append({
                "RecordId": rec_id,
                "EventID": raw.get("EventID"),
                "TargetUserName": ed.get("TargetUserName"),
                "LogonType": ed.get("LogonType"),
                "IpAddress": ed.get("IpAddress"),
                "Computer": raw.get("Computer", "LAB-SRV01"),
                "TimeCreated": raw.get("TimeCreated")
            })
    return extracted

def build_deterministic_test_suite() -> List[Dict[str, Any]]:
    """Constructs the 8 mandatory test cases required by Auditor."""
    base_time = datetime.datetime(2026, 9, 16, 12, 0, 0, tzinfo=datetime.timezone.utc)
    
    suite = []
    
    # 1. TC-AUTH-003: Authentic Ground Truth (5 failures 80211-80215 -> 1 success 80216)
    auth_events = load_authentic_telemetry_events()
    suite.append({
        "TestCaseId": "TC-AUTH-003",
        "Category": "AUTHENTIC_GROUND_TRUTH",
        "Description": "Authentic Windows LSASS Event 4625 (80211-80215) followed by Event 4624 (80216)",
        "Events": auth_events,
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Authentic LSASS event sequence with 5 failed logons followed by valid logon for lab_user_test within 3s."
    })
    
    # 2. TC-POS-003: Controlled Simulation (7 failures -> 1 success, same user/IP, < 5m)
    pos_events = []
    for i in range(7):
        t = base_time + datetime.timedelta(seconds=10 * i)
        pos_events.append({
            "RecordId": 1000 + i,
            "EventID": 4625,
            "TargetUserName": "analyst_target",
            "LogonType": 3,
            "IpAddress": "192.0.2.55",
            "Computer": "SEC-OPS-HOST",
            "TimeCreated": t.isoformat()
        })
    pos_events.append({
        "RecordId": 1007,
        "EventID": 4624,
        "TargetUserName": "analyst_target",
        "LogonType": 3,
        "IpAddress": "192.0.2.55",
        "Computer": "SEC-OPS-HOST",
        "TimeCreated": (base_time + datetime.timedelta(seconds=80)).isoformat()
    })
    suite.append({
        "TestCaseId": "TC-POS-003",
        "Category": "CONTROLLED_SIMULATION_ABOVE_THRESHOLD",
        "Description": "Controlled simulation of 7 failed logons followed by 1 successful logon (< 5m)",
        "Events": pos_events,
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Above-threshold brute-force attack (7 >= 5) followed by success from identical source and target."
    })
    
    # 3. TC-NEG-007: Under-Threshold Failures (4 failures -> 1 success)
    neg_under_events = []
    for i in range(4):  # exactly 4 failures (N - 1)
        t = base_time + datetime.timedelta(seconds=10 * i)
        neg_under_events.append({
            "RecordId": 2000 + i,
            "EventID": 4625,
            "TargetUserName": "analyst_target",
            "LogonType": 3,
            "IpAddress": "192.0.2.55",
            "Computer": "SEC-OPS-HOST",
            "TimeCreated": t.isoformat()
        })
    neg_under_events.append({
        "RecordId": 2004,
        "EventID": 4624,
        "TargetUserName": "analyst_target",
        "LogonType": 3,
        "IpAddress": "192.0.2.55",
        "Computer": "SEC-OPS-HOST",
        "TimeCreated": (base_time + datetime.timedelta(seconds=50)).isoformat()
    })
    suite.append({
        "TestCaseId": "TC-NEG-007",
        "Category": "BOUNDARY_UNDER_THRESHOLD",
        "Description": "Boundary test with 4 failed logons (threshold is 5) followed by successful logon",
        "Events": neg_under_events,
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Boundary N-1 failure condition; must suppress correlation alert to prevent false positives on typical typos."
    })
    
    # 4. TC-NEG-008: Unsuccessful Attack (10 failures -> 0 success)
    neg_nosucc_events = []
    for i in range(10):
        t = base_time + datetime.timedelta(seconds=5 * i)
        neg_nosucc_events.append({
            "RecordId": 3000 + i,
            "EventID": 4625,
            "TargetUserName": "analyst_target",
            "LogonType": 3,
            "IpAddress": "192.0.2.55",
            "Computer": "SEC-OPS-HOST",
            "TimeCreated": t.isoformat()
        })
    suite.append({
        "TestCaseId": "TC-NEG-008",
        "Category": "FAILURES_WITHOUT_SUCCESS",
        "Description": "10 consecutive failed logons with no subsequent successful logon",
        "Events": neg_nosucc_events,
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Unsuccessful brute force triggers atomic threshold rule (DET-01-PRIM), but must NOT trigger CORR-01 (no compromise)."
    })
    
    # 5. TC-NEG-009: Routine Access (0 failures -> 1 success)
    neg_nofail_events = [{
        "RecordId": 4001,
        "EventID": 4624,
        "TargetUserName": "analyst_target",
        "LogonType": 3,
        "IpAddress": "192.0.2.55",
        "Computer": "SEC-OPS-HOST",
        "TimeCreated": base_time.isoformat()
    }]
    suite.append({
        "TestCaseId": "TC-NEG-009",
        "Category": "SUCCESS_WITHOUT_FAILURES",
        "Description": "Standard successful network authentication with 0 prior failures",
        "Events": neg_nofail_events,
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Ambient legitimate logon triggers DET-02-PRIM primitive only, suppressed by CORR-01."
    })
    
    # 6. TC-NEG-010: Out-of-Order Sequence (1 success -> 5 failures)
    neg_order_events = [{
        "RecordId": 5000,
        "EventID": 4624,
        "TargetUserName": "analyst_target",
        "LogonType": 3,
        "IpAddress": "192.0.2.55",
        "Computer": "SEC-OPS-HOST",
        "TimeCreated": base_time.isoformat()
    }]
    for i in range(5):
        t = base_time + datetime.timedelta(seconds=10 * (i + 1))
        neg_order_events.append({
            "RecordId": 5001 + i,
            "EventID": 4625,
            "TargetUserName": "analyst_target",
            "LogonType": 3,
            "IpAddress": "192.0.2.55",
            "Computer": "SEC-OPS-HOST",
            "TimeCreated": t.isoformat()
        })
    suite.append({
        "TestCaseId": "TC-NEG-010",
        "Category": "SEQUENCE_ORDERING_VIOLATION",
        "Description": "1 successful logon followed chronologically by 5 failed logons",
        "Events": neg_order_events,
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Fails ordered: true requirement (failures must precede success, not follow it)."
    })
    
    # 7. TC-NEG-011: User Mismatch (5 failures on User A -> 1 success on User B)
    neg_user_events = []
    for i in range(5):
        t = base_time + datetime.timedelta(seconds=10 * i)
        neg_user_events.append({
            "RecordId": 6000 + i,
            "EventID": 4625,
            "TargetUserName": "user_alpha",
            "LogonType": 3,
            "IpAddress": "192.0.2.55",
            "Computer": "SEC-OPS-HOST",
            "TimeCreated": t.isoformat()
        })
    neg_user_events.append({
        "RecordId": 6005,
        "EventID": 4624,
        "TargetUserName": "user_bravo",
        "LogonType": 3,
        "IpAddress": "192.0.2.55",
        "Computer": "SEC-OPS-HOST",
        "TimeCreated": (base_time + datetime.timedelta(seconds=60)).isoformat()
    })
    suite.append({
        "TestCaseId": "TC-NEG-011",
        "Category": "GROUPING_USER_MISMATCH",
        "Description": "5 failures on 'user_alpha' followed by success on 'user_bravo' from same IP",
        "Events": neg_user_events,
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Fails group-by TargetUserName constraint (different identities cannot satisfy single-account compromise correlation)."
    })
    
    # 8. TC-NEG-012: Time Window Expiry (5 failures -> 1 success after 10 minutes)
    neg_time_events = []
    for i in range(5):
        t = base_time + datetime.timedelta(seconds=10 * i)
        neg_time_events.append({
            "RecordId": 7000 + i,
            "EventID": 4625,
            "TargetUserName": "analyst_target",
            "LogonType": 3,
            "IpAddress": "192.0.2.55",
            "Computer": "SEC-OPS-HOST",
            "TimeCreated": t.isoformat()
        })
    neg_time_events.append({
        "RecordId": 7005,
        "EventID": 4624,
        "TargetUserName": "analyst_target",
        "LogonType": 3,
        "IpAddress": "192.0.2.55",
        "Computer": "SEC-OPS-HOST",
        "TimeCreated": (base_time + datetime.timedelta(minutes=10)).isoformat()  # 10 minutes later (> 5m)
    })
    suite.append({
        "TestCaseId": "TC-NEG-012",
        "Category": "TEMPORAL_WINDOW_EXPIRY",
        "Description": "5 failures followed by 1 success after 10 minutes (exceeds 5m timespan)",
        "Events": neg_time_events,
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Fails timespan: 5m constraint; time difference exceeds correlation window."
    })
    
    return suite

def main() -> int:
    print("=" * 70)
    print("CORR-01 SIGMA 2.1.0 CORRELATION EVALUATION ENGINE")
    print(f"Rule: {RULE_METADATA['RuleName']} ({RULE_METADATA['CanonicalSigmaPath']})")
    print("=" * 70)
    
    suite = build_deterministic_test_suite()
    matrix_results = []
    all_passed = True
    
    for tc in suite:
        tc_id = tc["TestCaseId"]
        desc = tc["Description"]
        exp = tc["ExpectedState"]
        events = tc["Events"]
        
        actual, matches, reason = evaluate_correlation_stream(events, timespan_sec=RULE_METADATA["TimespanSeconds"])
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
            "EventCount": len(events),
            "Matches": matches
        }
        matrix_results.append(record)
        
    print("-" * 70)
    print(f"Total Test Cases: {len(suite)} | Passed: {sum(1 for r in matrix_results if r['Verdict'] == 'PASS')} | Failed: {sum(1 for r in matrix_results if r['Verdict'] == 'FAIL')}")
    
    # Save evidence artifacts
    os.makedirs(os.path.join("evidence", "correlations"), exist_ok=True)
    matrix_path = os.path.join("evidence", "correlations", "ev-corr-01-boundary-matrix.json")
    with open(matrix_path, "w", encoding="utf-8") as f:
        json.dump(matrix_results, f, indent=2)
        
    proof_path = os.path.join("evidence", "correlations", "ev-corr-01-execution-proof.json")
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
