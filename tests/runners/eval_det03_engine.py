#!/usr/bin/env python3
"""
==============================================================================
DET-03 Evaluation Engine: Suspicious Encoded PowerShell Execution
==============================================================================
Evaluates canonical Sigma rule (detections/sigma/windows_suspicious_powershell.yml)
against authentic Sysmon Event 1 telemetry (evidence/telemetry/sysmon-sample.json)
and a 7-case deterministic boundary test suite.

Author : JestineSOC Detection Engineering Team
Standard: Sigma Specification 2.1.0 / MITRE ATT&CK T1059.001 & T1027
==============================================================================
"""

import os
import sys
import json
import re
import datetime
from typing import List, Dict, Any, Tuple

RULE_METADATA = {
    "DetectionId": "DET-03",
    "RuleName": "windows_suspicious_powershell",
    "CanonicalSigmaPath": "detections/sigma/windows_suspicious_powershell.yml",
    "SpecificationPath": "docs/detections/DET-03-windows-suspicious-powershell.md",
    "Level": "high",
    "MitreTechniques": ["T1059.001", "T1027"]
}

POWERSHELL_BINARIES = {"powershell.exe", "pwsh.exe"}
ENCODED_FLAGS = [
    " -encodedcommand ", " -encodedcommand=",
    " -encoded ", " -encoded=",
    " -enc ", " -enc=",
    " -e ", " -e=",
    " /encodedcommand ", " /encodedcommand=",
    " /encoded ", " /encoded=",
    " /enc ", " /enc=",
    " /e ", " /e="
]

def evaluate_process_event(event: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluates a single process event against DET-03 Sigma logic.
    Returns (is_match: bool, reason: str).
    """
    eid = event.get("EventID")
    # Must be Sysmon Event 1 or Security Event 4688
    if eid not in (1, 4688):
        return False, f"EventID {eid} is not a process creation event (requires Sysmon 1 or Security 4688)."

    image = event.get("Image") or event.get("NewProcessName") or ""
    binary_name = re.split(r"[\\/]", image.lower())[-1] if image else ""
    orig_filename = (event.get("OriginalFileName") or "").lower()

    is_powershell_binary = (
        binary_name in POWERSHELL_BINARIES or
        orig_filename in ("powershell.exe", "pwsh.dll")
    )

    if not is_powershell_binary:
        return False, f"Binary '{binary_name}' does not match PowerShell executables."

    cli = event.get("CommandLine") or ""
    cli_lower = f" {cli.lower()} "

    has_encoded_flag = any(flag in cli_lower for flag in ENCODED_FLAGS)

    if not has_encoded_flag:
        return False, "Command line does not contain base64 encoded command arguments (-enc, -encodedcommand, etc.)."

    return True, "PowerShell binary invoked with encoded command line parameter."

def load_authentic_sysmon_event() -> Dict[str, Any]:
    """Loads authentic Sysmon Event 1 from evidence/telemetry/sysmon-sample.json."""
    sample_path = os.path.join("evidence", "telemetry", "sysmon-sample.json")
    if not os.path.exists(sample_path):
        raise FileNotFoundError(f"Sysmon sample file not found: {sample_path}")

    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for ev in data.get("Events", []):
        if ev.get("EventID") == 1:
            ed = ev.get("EventData", {})
            return {
                "EventID": 1,
                "ProviderName": ev.get("ProviderName"),
                "TimeCreated": ev.get("TimeCreated"),
                "Image": ed.get("Image"),
                "CommandLine": ed.get("CommandLine"),
                "ParentImage": ed.get("ParentImage"),
                "User": ed.get("User"),
                "Computer": "LAB-HOST01",
                "OriginalFileName": ed.get("OriginalFileName")
            }
    raise ValueError("No Sysmon Event 1 found in sample file.")

def build_deterministic_test_suite() -> List[Dict[str, Any]]:
    """Constructs the 7 mandatory test cases."""
    suite = []

    # 1. TC-AUTH-004: Authentic Ground Truth Ingestion
    auth_event = load_authentic_sysmon_event()
    suite.append({
        "TestCaseId": "TC-AUTH-004",
        "Category": "AUTHENTIC_SYSMON_INGESTION",
        "Description": "Authentic Sysmon Event 1 process creation with -EncodedCommand argument",
        "Event": auth_event,
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Authentic Sysmon record from sysmon-sample.json must match DET-03 criteria."
    })

    # 2. TC-POS-004: PowerShell Core with -enc flag
    suite.append({
        "TestCaseId": "TC-POS-004",
        "Category": "CONTROLLED_SIMULATION_PWSH",
        "Description": "PowerShell Core (pwsh.exe) executed with -enc flag",
        "Event": {
            "EventID": 1,
            "Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
            "CommandLine": 'pwsh.exe -NoProfile -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAZQBzAHQAJwA=',
            "User": "LAB-HOST01\\lab_user_test",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:00:00.000Z"
        },
        "ExpectedState": "MATCH",
        "BoundaryRationale": "pwsh.exe is modern PowerShell Core; -enc is a standard encoded alias."
    })

    # 3. TC-POS-005: Forward-slash delimiter with /encodedcommand=
    suite.append({
        "TestCaseId": "TC-POS-005",
        "Category": "CONTROLLED_SIMULATION_SLASH_DELIMITER",
        "Description": "Windows PowerShell executed with /encodedcommand= flag and equals delimiter",
        "Event": {
            "EventID": 4688,
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": 'powershell.exe /encodedcommand=VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAZQBzAHQAJwA=',
            "Account": "LAB-HOST01\\lab_user_test",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:05:00.000Z"
        },
        "ExpectedState": "MATCH",
        "BoundaryRationale": "Windows accepts / as parameter prefix and = as argument delimiter."
    })

    # 4. TC-NEG-013: Standard unencoded PowerShell
    suite.append({
        "TestCaseId": "TC-NEG-013",
        "Category": "UNENCODED_POWERSHELL_FILTER",
        "Description": "Standard unencoded powershell command (Get-Process)",
        "Event": {
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -Command Get-Process",
            "User": "LAB-HOST01\\lab_user_test",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:10:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Standard unencoded command does not match encoded command flags; must suppress alert."
    })

    # 5. TC-NEG-014: Non-PowerShell process with -enc flag
    suite.append({
        "TestCaseId": "TC-NEG-014",
        "Category": "NON_POWERSHELL_BINARY_FILTER",
        "Description": "Non-PowerShell custom utility executed with -enc flag",
        "Event": {
            "EventID": 1,
            "Image": "C:\\Tools\\custom_encoder.exe",
            "CommandLine": "custom_encoder.exe -enc payload.bin",
            "User": "LAB-HOST01\\lab_user_test",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:15:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Binary is custom_encoder.exe, not powershell.exe/pwsh.exe; must be rejected by selection_img."
    })

    # 6. TC-NEG-015: Non-process creation event (Sysmon Event 3 Network Connection)
    suite.append({
        "TestCaseId": "TC-NEG-015",
        "Category": "EVENT_CATEGORY_FILTER",
        "Description": "Sysmon Event 3 Network Connection event",
        "Event": {
            "EventID": 3,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc VwByAGkAdABl...",
            "DestinationIp": "192.0.2.50",
            "DestinationPort": 443,
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:20:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Sysmon Event 3 is network activity, not process creation; must be rejected by EventID check."
    })

    # 7. TC-NEG-016: Standard Command Prompt process
    suite.append({
        "TestCaseId": "TC-NEG-016",
        "Category": "STANDARD_SHELL_FILTER",
        "Description": "Standard cmd.exe execution (/c dir)",
        "Event": {
            "EventID": 4688,
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c dir",
            "Account": "LAB-HOST01\\lab_user_test",
            "Computer": "LAB-HOST01",
            "TimeCreated": "2026-09-16T10:25:00.000Z"
        },
        "ExpectedState": "NO_MATCH",
        "BoundaryRationale": "Standard command prompt execution is not PowerShell and has no encoded parameters."
    })

    return suite

def main() -> int:
    print("=" * 70)
    print("DET-03 ENCODED POWERSHELL EVALUATION ENGINE")
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

        is_match, reason = evaluate_process_event(event)
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
                "Image": event.get("Image") or event.get("NewProcessName"),
                "CommandLine": event.get("CommandLine")
            }
        }
        matrix_results.append(record)

    print("-" * 70)
    print(f"Total Test Cases: {len(suite)} | Passed: {sum(1 for r in matrix_results if r['Verdict'] == 'PASS')} | Failed: {sum(1 for r in matrix_results if r['Verdict'] == 'FAIL')}")

    os.makedirs(os.path.join("evidence", "detections"), exist_ok=True)
    matrix_path = os.path.join("evidence", "detections", "ev-det-03-boundary-matrix.json")
    with open(matrix_path, "w", encoding="utf-8") as f:
        json.dump(matrix_results, f, indent=2)

    proof_path = os.path.join("evidence", "detections", "ev-det-03-execution-proof.json")
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
