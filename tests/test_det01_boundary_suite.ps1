<#
.SYNOPSIS
    JestineSOC DET-01 Comprehensive Boundary & Execution Test Suite
.DESCRIPTION
    Executes the 5 mandatory boundary test conditions plus control cases
    via the Python evaluation engine (tests/runners/eval_det01_engine.py).
    Asserts exact threshold breach, sub-threshold suppression, and sliding window behavior:
      - NEG-001: 1 failure / 5m   -> NO ALERT (isolated typo)
      - NEG-002: 4 failures / 5m  -> NO ALERT (boundary N-1)
      - POS-001: 5 failures / 5m  -> ALERT (exact threshold breach)
      - POS-002: 6 failures / 5m  -> ALERT (above threshold)
      - NEG-003: 5 failures / >5m -> NO ALERT (temporal sliding window enforcement)
      - NEG-004: Machine account filter -> NO ALERT
      - NEG-005: Account variance (spraying) -> NO ALERT
#>

[CmdletBinding()]
param()

$engineScript = Join-Path $PSScriptRoot "runners/eval_det01_engine.py"
if (-not (Test-Path $engineScript)) {
    Write-Error "Evaluation engine script not found: $engineScript"
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "  JestineSOC: DET-01 Boundary & Execution Test Suite       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$process = Start-Process python -ArgumentList "`"$engineScript`"" -NoNewWindow -PassThru -Wait
if ($process.ExitCode -eq 0) {
    Write-Host "`n[+] DET-01 Boundary & Execution Suite completed successfully (ALL CASES PASSED)." -ForegroundColor Green
} else {
    Write-Error "DET-01 Boundary & Execution Suite FAILED with exit code: $($process.ExitCode)"
    exit $process.ExitCode
}
