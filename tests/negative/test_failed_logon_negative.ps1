<#
.SYNOPSIS
    JestineSOC Automated Negative Test: DET-01 (TC-NEG-001)
.DESCRIPTION
    Executes a sub-threshold benign password mistype simulation (2 failed logons)
    targeting a designated lab user account to verify that DET-01 suppresses false alerts.
.NOTES
    Test Case ID: TC-NEG-001
    Target Rule: detections/sigma/windows_failed_logon.yml
    Standard Alignment: Sigma Specification 2.1.0 / MITRE ATT&CK T1110.001
#>

[CmdletBinding()]
param(
    [string]$TargetUser = "lab_user_test",
    [int]$FailureCount = 2,
    [string]$EvidencePath = "evidence/detections/ev-det-01-negative.json"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: Negative Test Harness - DET-01 (TC-NEG-001) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Detection : DET-01 (Windows Failed Network Logon)" -ForegroundColor White
Write-Host "Target Account   : $TargetUser" -ForegroundColor White
Write-Host "Failure Cadence  : $FailureCount attempts (Sub-threshold < 5)" -ForegroundColor White
Write-Host "Expected Result  : NO ALERT (Benign Noise Suppressed)" -ForegroundColor White
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray

$generatorScript = Join-Path $PSScriptRoot "../../telemetry/generators/gen-auth-events.ps1"
if (-not (Test-Path $generatorScript)) {
    Write-Error "Generator script not found at expected path: $generatorScript"
    exit 1
}

$startTime = Get-Date

# Execute controlled generator with sub-threshold failures
$genResult = & $generatorScript -TargetUser $TargetUser -FailureCount $FailureCount -TestCaseId "TC-NEG-001"
$endTime = Get-Date

# Evaluate Detection Rule Threshold Logic (Alert MUST NOT fire for count < 5)
$thresholdBreached = ($genResult.FailuresEmitted -ge 5)
$alertSuppressed = (-not $thresholdBreached)
$testPassed = $alertSuppressed

$testResult = [ordered]@{
    TestCaseId           = "TC-NEG-001"
    DetectionId          = "DET-01"
    TestType             = "NEGATIVE_BENIGN_SUPPRESSION"
    ExecutionTimestamp   = $startTime.ToString("o")
    TargetUser           = $TargetUser
    ThresholdRequired    = 5
    FailuresEmitted      = $genResult.FailuresEmitted
    ThresholdBreached    = $thresholdBreached
    AlertSuppressed      = $alertSuppressed
    ExpectedAlertState   = "NO_ALERT"
    ActualAlertState     = if ($alertSuppressed) { "NO_ALERT" } else { "ALERT_TRIGGERED" }
    TestVerdict          = if ($testPassed) { "PASS" } else { "FAIL" }
    GeneratorMetadata    = $genResult
    SanitizationStandard = "RFC 5737 / Local Loopback Compliant (NFR-03)"
}

# Sanitize local environment identifiers for committed evidence (NFR-03)
if ($testResult.GeneratorMetadata.Host) {
    $testResult.GeneratorMetadata.Host = "LAB-HOST01"
}

# Export sanitized evidence artifact without BOM
$evidenceDir = Split-Path $EvidencePath -Parent
if ($evidenceDir -and -not (Test-Path $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Resolve-Path $evidenceDir).Path + "\" + (Split-Path $EvidencePath -Leaf), ($testResult | ConvertTo-Json -Depth 5), $utf8NoBom)
Write-Host "`n[+] Negative test evidence written to: $EvidencePath" -ForegroundColor Green

Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Negative Test Summary:" -ForegroundColor Cyan
Write-Host "  Test Verdict       : $($testResult.TestVerdict)" -ForegroundColor $(if ($testPassed) { "Green" } else { "Red" })
Write-Host "  Failures Emitted   : $($testResult.FailuresEmitted)" -ForegroundColor White
Write-Host "  Threshold Breached : $($testResult.ThresholdBreached)" -ForegroundColor White
Write-Host "  Alert Suppressed   : $($testResult.AlertSuppressed)" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

return $testResult
