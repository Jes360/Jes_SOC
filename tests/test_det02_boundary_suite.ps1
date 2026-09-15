<#
.SYNOPSIS
    JestineSOC DET-02 Comprehensive Boundary & Execution Test Suite
.DESCRIPTION
    Executes the 8 boundary test conditions and authentic OS telemetry ingestion
    via the Python evaluation engine (tests/runners/eval_det02_engine.py).
    Asserts primitive qualification, machine account suppression, system account exclusion,
    and LogonType boundaries:
      - AUTH-002: Ingests authentic LSASS Event 4624 (RecordId: 80216) -> MATCH
      - POS-002: Controlled valid network authentication -> MATCH
      - NEG-001: Event 4625 failed logon -> NO_MATCH
      - NEG-002: LogonType 2 (interactive console) -> NO_MATCH
      - NEG-003: Machine account ($ suffix) -> NO_MATCH
      - NEG-004: NT AUTHORITY\SYSTEM -> NO_MATCH
      - NEG-005: ANONYMOUS LOGON -> NO_MATCH
      - NEG-006: LOCAL SERVICE -> NO_MATCH
#>

[CmdletBinding()]
param()

$engineScript = Join-Path $PSScriptRoot "runners/eval_det02_engine.py"
if (-not (Test-Path $engineScript)) {
    Write-Error "Evaluation engine script not found: $engineScript"
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: DET-02 Boundary & Execution Test Suite       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$process = Start-Process python -ArgumentList "`"$engineScript`"" -NoNewWindow -PassThru -Wait
if ($process.ExitCode -eq 0) {
    Write-Host "`n[+] DET-02 Boundary & Execution Suite completed successfully (ALL 8 CASES PASSED)." -ForegroundColor Green
} else {
    Write-Error "DET-02 Boundary & Execution Suite FAILED with exit code: $($process.ExitCode)"
    exit $process.ExitCode
}
