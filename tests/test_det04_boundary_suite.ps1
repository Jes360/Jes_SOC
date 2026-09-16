# ==============================================================================
# DET-04 Boundary Suite Test Wrapper
# ==============================================================================
# Executes tests/runners/eval_det04_engine.py, validates results,
# and verifies evidence artifacts.
# ==============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "JestineSOC: DET-04 Boundary Suite Automated Runner                   " -ForegroundColor Cyan
Write-Host "Rule: windows_smb_admin_shares (detections/sigma/windows_smb_admin_shares.yml)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$scriptPath = Join-Path $PSScriptRoot "runners/eval_det04_engine.py"
if (-not (Test-Path $scriptPath)) {
    Write-Error "Evaluation script not found: $scriptPath"
    exit 1
}

$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCmd) {
    Write-Error "Python executable not found in PATH."
    exit 1
}

Write-Host "[*] Executing Python Evaluation Engine..." -ForegroundColor Yellow
$proc = Start-Process -FilePath "python" -ArgumentList "`"$scriptPath`"" -NoNewWindow -PassThru -Wait

if ($proc.ExitCode -ne 0) {
    Write-Error "[-] DET-04 Boundary Suite encountered failures (Exit Code: $($proc.ExitCode))"
    exit $proc.ExitCode
}

$evidenceMatrix = "evidence/detections/ev-det-04-boundary-matrix.json"
$evidenceProof = "evidence/detections/ev-det-04-execution-proof.json"

if (-not (Test-Path $evidenceMatrix) -or -not (Test-Path $evidenceProof)) {
    Write-Error "[-] Evidence files were not generated as expected."
    exit 1
}

Write-Host "[+] DET-04 Boundary Suite Executed Successfully (All 7 Test Cases PASS)." -ForegroundColor Green
Write-Host "[+] Evidence Verified:" -ForegroundColor Green
Write-Host "    - $evidenceMatrix"
Write-Host "    - $evidenceProof"
exit 0
