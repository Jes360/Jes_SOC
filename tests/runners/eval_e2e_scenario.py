#!/usr/bin/env python3
"""
JestineSOC Integrated Threat Scenario Evaluation Engine (SCEN-01)
-----------------------------------------------------------------
Evaluates the end-to-end multi-stage intrusion lifecycle across 3 primary integration test cases:
  1. TC-E2E-001 (Full Attack Chain): True Positive sequential progression across Stages 1-4.
  2. TC-E2E-002 (Broken Chain): Credential brute-force without subsequent logon success.
  3. TC-E2E-003 (Benign Operational Noise): Unencoded PowerShell + standard user share access.

Outputs auditable artifacts:
  - evidence/scenarios/ev-scen-01-boundary-matrix.json
  - evidence/scenarios/ev-scen-01-execution-proof.json
  - evidence/scenarios/ev-scen-01-timeline.json
"""

import os
import re
import json
from datetime import datetime, timezone, timedelta

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# -----------------------------------------------------------------------------
# CANONICAL DETECTION PRIMITIVES
# -----------------------------------------------------------------------------

def evaluate_det01_primitive(event):
    """Event 4625: Windows Failed Network Logon"""
    if event.get("EventID") != 4625:
        return False
    if event.get("LogonType") != 3:
        return False
    user = event.get("TargetUserName", "")
    if user.endswith("$"):
        return False
    status = str(event.get("Status", "")).lower()
    sub_status = str(event.get("SubStatus", "")).lower()
    if status != "0xc000006d" or sub_status != "0xc000006a":
        return False
    return True

def evaluate_det02_primitive(event):
    """Event 4624: Windows Successful Network Logon"""
    if event.get("EventID") != 4624:
        return False
    if event.get("LogonType") != 3:
        return False
    user = event.get("TargetUserName", "")
    if user.endswith("$"):
        return False
    system_accounts = {"SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "-", ""}
    if user in system_accounts:
        return False
    return True

def evaluate_det03_primitive(event):
    """Sysmon Event 1 / Event 4688: Encoded PowerShell Execution"""
    event_id = event.get("EventID")
    if event_id not in (1, 4688):
        return False
    image = event.get("Image", "") or event.get("NewProcessName", "")
    exe = re.split(r"[\\/]", image)[-1].lower() if image else ""
    if not (exe.startswith("powershell") or exe.startswith("pwsh")):
        return False
    cmd = event.get("CommandLine", "") or ""
    encoded_pattern = r"(?i)(?:[-/](?:e|enc|encodedcommand)\b|[-/](?:e|enc|encodedcommand)\s*[:=])"
    return bool(re.search(encoded_pattern, cmd))

def evaluate_det04_primitive(event):
    """Security Event 5140/5145 or Sysmon Event 3: SMB Administrative Share Access"""
    event_id = event.get("EventID")
    if event_id in (5140, 5145):
        user = event.get("SubjectUserName", "") or event.get("TargetUserName", "")
        if user.endswith("$"):
            return False
        if user.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-"):
            return False
        share = (event.get("ShareName") or "").upper()
        if any(admin_share in share for admin_share in ("C$", "ADMIN$", "IPC$")):
            return True
        return False
    elif event_id == 3:
        port = str(event.get("DestinationPort", ""))
        user = event.get("User", "")
        if user.endswith("$"):
            return False
        if port == "445":
            return True
        return False
    return False

# -----------------------------------------------------------------------------
# CORRELATION RUNTIME (CORR-01)
# -----------------------------------------------------------------------------

def evaluate_corr01_stream(events, window_minutes=5):
    """
    Evaluates temporal correlation:
    >= 5 DET-01-PRIM events followed by >= 1 DET-02-PRIM event within window_minutes
    grouped by (TargetUserName, IpAddress).
    """
    window = timedelta(minutes=window_minutes)
    groups = {}
    
    # Sort events by TimeCreated
    sorted_events = sorted(events, key=lambda e: datetime.fromisoformat(e["TimeCreated"].replace("Z", "+00:00")))
    
    for ev in sorted_events:
        user = ev.get("TargetUserName") or ev.get("SubjectUserName")
        ip = ev.get("IpAddress") or ev.get("SourceIp")
        if not user or not ip:
            continue
        key = (user, ip)
        if key not in groups:
            groups[key] = []
        groups[key].append(ev)
        
    correlated_incidents = []
    
    for (user, ip), ev_list in groups.items():
        failures = []
        for ev in ev_list:
            t = datetime.fromisoformat(ev["TimeCreated"].replace("Z", "+00:00"))
            if evaluate_det01_primitive(ev):
                failures.append((t, ev))
            elif evaluate_det02_primitive(ev):
                # Check preceding failures within sliding window
                valid_failures = [f for f in failures if (t - f[0]) <= window and (t >= f[0])]
                if len(valid_failures) >= 5:
                    correlated_incidents.append({
                        "CorrelationId": "CORR-01",
                        "RuleName": "mr_bruteforce_after_failures",
                        "Severity": "CRITICAL",
                        "TargetUserName": user,
                        "IpAddress": ip,
                        "PrecedingFailures": len(valid_failures),
                        "FirstFailureTime": valid_failures[0][0].isoformat(),
                        "LastFailureTime": valid_failures[-1][0].isoformat(),
                        "SuccessTime": t.isoformat(),
                        "SlidingWindowDeltaSeconds": (t - valid_failures[0][0]).total_seconds()
                    })
    return correlated_incidents

# -----------------------------------------------------------------------------
# TEST VECTORS
# -----------------------------------------------------------------------------

def build_e2e_scenarios():
    t0 = datetime(2026, 9, 16, 2, 0, 0, tzinfo=timezone.utc)
    
    # TC-E2E-001: Full True Positive Intrusion Sequence
    tc1_events = []
    # 5 Failures (Stage 1)
    for i in range(5):
        tc1_events.append({
            "RecordId": 90001 + i,
            "EventID": 4625,
            "TimeCreated": (t0 + timedelta(seconds=i * 5)).isoformat(),
            "TargetUserName": "lab_user_test",
            "TargetDomainName": "LAB",
            "LogonType": 3,
            "IpAddress": "198.51.100.55",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a"
        })
    # 1 Success (Stage 2)
    tc1_events.append({
        "RecordId": 90010,
        "EventID": 4624,
        "TimeCreated": (t0 + timedelta(seconds=35)).isoformat(),
        "TargetUserName": "lab_user_test",
        "TargetDomainName": "LAB",
        "LogonType": 3,
        "IpAddress": "198.51.100.55"
    })
    # 1 Encoded PowerShell (Stage 3)
    tc1_events.append({
        "RecordId": 90020,
        "EventID": 1,
        "TimeCreated": (t0 + timedelta(seconds=60)).isoformat(),
        "User": "LAB\\lab_user_test",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMAdABhAGcAZQAgADMAIABEAGkAcwBjAG8AdgBlAHIAeQAnADsAIABoAG8AcwB0AG4AYQBtAGUA"
    })
    # 1 SMB Admin Share Access (Stage 4)
    tc1_events.append({
        "RecordId": 90030,
        "EventID": 5140,
        "TimeCreated": (t0 + timedelta(seconds=95)).isoformat(),
        "SubjectUserName": "lab_user_test",
        "SubjectDomainName": "LAB",
        "IpAddress": "198.51.100.55",
        "ShareName": "\\\\*\\ADMIN$",
        "AccessMask": "0x1"
    })
    tc1_events.append({
        "RecordId": 90031,
        "EventID": 3,
        "TimeCreated": (t0 + timedelta(seconds=110)).isoformat(),
        "User": "LAB\\lab_user_test",
        "DestinationPort": 445,
        "SourceIp": "198.51.100.55",
        "DestinationIp": "192.0.2.100"
    })

    # TC-E2E-002: Broken Chain (Brute Force Without Success)
    tc2_events = []
    for i in range(5):
        tc2_events.append({
            "RecordId": 91001 + i,
            "EventID": 4625,
            "TimeCreated": (t0 + timedelta(seconds=i * 5)).isoformat(),
            "TargetUserName": "locked_analyst",
            "TargetDomainName": "LAB",
            "LogonType": 3,
            "IpAddress": "198.51.100.77",
            "Status": "0xc000006d",
            "SubStatus": "0xc000006a"
        })

    # TC-E2E-003: Benign Operational Noise (Unencoded PowerShell + Standard User Share)
    tc3_events = [
        {
            "RecordId": 92001,
            "EventID": 1,
            "TimeCreated": (t0 + timedelta(seconds=10)).isoformat(),
            "User": "LAB\\admin_legit",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\BackupDaily.ps1"
        },
        {
            "RecordId": 92002,
            "EventID": 5140,
            "TimeCreated": (t0 + timedelta(seconds=25)).isoformat(),
            "SubjectUserName": "admin_legit",
            "SubjectDomainName": "LAB",
            "IpAddress": "192.0.2.50",
            "ShareName": "\\\\*\\PublicReports",
            "AccessMask": "0x1"
        }
    ]

    return {
        "TC-E2E-001": {
            "Description": "Full True Positive 4-Stage Intrusion Sequence",
            "Events": tc1_events,
            "Expected": {
                "DET-01-PRIM": True,
                "DET-02-PRIM": True,
                "CORR-01": True,
                "DET-03": True,
                "DET-04": True,
                "SequenceOrdered": True
            }
        },
        "TC-E2E-002": {
            "Description": "Broken Attack Chain (Brute Force Only, Zero Logon Success)",
            "Events": tc2_events,
            "Expected": {
                "DET-01-PRIM": True,
                "DET-02-PRIM": False,
                "CORR-01": False,
                "DET-03": False,
                "DET-04": False,
                "SequenceOrdered": True
            }
        },
        "TC-E2E-003": {
            "Description": "Benign Operational Noise (Unencoded PowerShell + Non-Admin Share)",
            "Events": tc3_events,
            "Expected": {
                "DET-01-PRIM": False,
                "DET-02-PRIM": False,
                "CORR-01": False,
                "DET-03": False,
                "DET-04": False,
                "SequenceOrdered": True
            }
        }
    }

def run_evaluation():
    scenarios = build_e2e_scenarios()
    matrix_results = []
    execution_proofs = []
    timeline_records = []
    
    print("=" * 70)
    print("JestineSOC END-TO-END SCENARIO EVALUATION ENGINE (SCEN-01)")
    print("Scenario: SCEN-01 (Credential Brute-Force to Administrative Lateral Movement)")
    print("=" * 70)
    
    all_passed = True
    
    for case_id, case_data in scenarios.items():
        events = case_data["Events"]
        expected = case_data["Expected"]
        
        # Track detection fires and timestamps
        fires = {
            "DET-01-PRIM": False,
            "DET-02-PRIM": False,
            "CORR-01": False,
            "DET-03": False,
            "DET-04": False
        }
        fire_timestamps = {
            "DET-01-PRIM": [],
            "DET-02-PRIM": [],
            "CORR-01": [],
            "DET-03": [],
            "DET-04": []
        }
        
        for ev in events:
            t = ev.get("TimeCreated")
            rec_id = ev.get("RecordId")
            if evaluate_det01_primitive(ev):
                fires["DET-01-PRIM"] = True
                fire_timestamps["DET-01-PRIM"].append(t)
                timeline_records.append({
                    "TestCaseId": case_id,
                    "RecordId": rec_id,
                    "TimeCreated": t,
                    "EventID": ev.get("EventID"),
                    "Detection": "DET-01-PRIM",
                    "Severity": "low"
                })
            if evaluate_det02_primitive(ev):
                fires["DET-02-PRIM"] = True
                fire_timestamps["DET-02-PRIM"].append(t)
                timeline_records.append({
                    "TestCaseId": case_id,
                    "RecordId": rec_id,
                    "TimeCreated": t,
                    "EventID": ev.get("EventID"),
                    "Detection": "DET-02-PRIM",
                    "Severity": "low"
                })
            if evaluate_det03_primitive(ev):
                fires["DET-03"] = True
                fire_timestamps["DET-03"].append(t)
                timeline_records.append({
                    "TestCaseId": case_id,
                    "RecordId": rec_id,
                    "TimeCreated": t,
                    "EventID": ev.get("EventID"),
                    "Detection": "DET-03",
                    "Severity": "high"
                })
            if evaluate_det04_primitive(ev):
                fires["DET-04"] = True
                fire_timestamps["DET-04"].append(t)
                timeline_records.append({
                    "TestCaseId": case_id,
                    "RecordId": rec_id,
                    "TimeCreated": t,
                    "EventID": ev.get("EventID"),
                    "Detection": "DET-04",
                    "Severity": "high"
                })
                
        # Evaluate Correlation
        corr_results = evaluate_corr01_stream(events)
        if corr_results:
            fires["CORR-01"] = True
            fire_timestamps["CORR-01"].append(corr_results[0]["SuccessTime"])
            timeline_records.append({
                "TestCaseId": case_id,
                "RecordId": "CORR-01-COMPOSITE",
                "TimeCreated": corr_results[0]["SuccessTime"],
                "EventID": "CORRELATION_COMPOSITE",
                "Detection": "CORR-01",
                "Severity": "critical"
            })
            
        # Verify temporal ordering for True Positive scenario
        sequence_ordered = True
        if case_id == "TC-E2E-001":
            t_stage1 = fire_timestamps["DET-01-PRIM"][0]
            t_stage2 = fire_timestamps["CORR-01"][0]
            t_stage3 = fire_timestamps["DET-03"][0]
            t_stage4 = fire_timestamps["DET-04"][0]
            sequence_ordered = (t_stage1 <= t_stage2 <= t_stage3 <= t_stage4)
            
        # Match against expected
        actual = {
            "DET-01-PRIM": fires["DET-01-PRIM"],
            "DET-02-PRIM": fires["DET-02-PRIM"],
            "CORR-01": fires["CORR-01"],
            "DET-03": fires["DET-03"],
            "DET-04": fires["DET-04"],
            "SequenceOrdered": sequence_ordered
        }
        
        passed = (actual == expected)
        if not passed:
            all_passed = False
            verdict = "FAIL"
        else:
            verdict = "PASS"
            
        print(f"[{verdict}] {case_id}: {case_data['Description']}")
        print(f"       Expected: {expected}")
        print(f"       Actual  : {actual}")
        
        matrix_results.append({
            "TestCaseId": case_id,
            "Description": case_data["Description"],
            "TotalEvents": len(events),
            "Expected": expected,
            "Actual": actual,
            "Verdict": verdict
        })
        
        execution_proofs.append({
            "TestCaseId": case_id,
            "Verdict": verdict,
            "FireTimestamps": fire_timestamps,
            "CorrelatedIncidents": corr_results
        })

    print("-" * 70)
    print(f"Total Integrated Scenarios: {len(scenarios)} | Passed: {sum(1 for m in matrix_results if m['Verdict'] == 'PASS')} | Failed: {sum(1 for m in matrix_results if m['Verdict'] == 'FAIL')}")
    
    # Save evidence
    evidence_dir = os.path.join(REPO_ROOT, "evidence", "scenarios")
    os.makedirs(evidence_dir, exist_ok=True)
    
    matrix_path = os.path.join(evidence_dir, "ev-scen-01-boundary-matrix.json")
    with open(matrix_path, "w", encoding="utf-8") as f:
        json.dump(matrix_results, f, indent=2)
        
    proof_path = os.path.join(evidence_dir, "ev-scen-01-execution-proof.json")
    proof_data = {
        "Engine": "JestineSOC End-to-End Scenario Evaluation Engine v1.0",
        "EvaluatedAt": datetime.now(timezone.utc).isoformat(),
        "Scenario": "SCEN-01",
        "OverallVerdict": "PASS" if all_passed else "FAIL",
        "Cases": execution_proofs
    }
    with open(proof_path, "w", encoding="utf-8") as f:
        json.dump(proof_data, f, indent=2)
        
    timeline_path = os.path.join(evidence_dir, "ev-scen-01-timeline.json")
    with open(timeline_path, "w", encoding="utf-8") as f:
        json.dump(timeline_records, f, indent=2)
        
    print(f"[+] Matrix evidence written to: {matrix_path}")
    print(f"[+] Execution proof written to: {proof_path}")
    print(f"[+] Timeline evidence written to: {timeline_path}")
    print("=" * 70)
    
    return all_passed

if __name__ == "__main__":
    import sys
    success = run_evaluation()
    sys.exit(0 if success else 1)
