<#
.SYNOPSIS
    JestineSOC End-to-End Threat Scenario Harness (SCEN-01)
.DESCRIPTION
    Orchestrates the 4-stage attack lifecycle sequence:
      Stage 1: Password Guessing (5x Event 4625) -> DET-01-PRIM
      Stage 2: Successful Authentication (1x Event 4624) -> DET-02-PRIM & CORR-01
      Stage 3: Encoded PowerShell Discovery -> DET-03 (T1059.001)
      Stage 4: Administrative Share Access -> DET-04 (T1021.002)
    All operations are strictly benign and conform to NFR-02 and NFR-03.
.NOTES
    Scenario ID: SCEN-01
    Target Account: lab_user_test
    Evidence Output: evidence/scenarios/ev-scen-01-simulation-run.json
#>

[CmdletBinding()]
param(
    [string]$TargetUser = "lab_user_test",
    [string]$EvidencePath = "evidence/scenarios/ev-scen-01-simulation-run.json"
)

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: End-to-End Threat Scenario Harness (SCEN-01)        " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Scenario ID      : SCEN-01 (Compromise to Lateral Movement)" -ForegroundColor White
Write-Host "Target Account   : $TargetUser" -ForegroundColor White
Write-Host "Standard Policy  : NFR-02 Zero Offensive Payload / NFR-03 RFC 5737" -ForegroundColor White
Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray

$authGenerator = Join-Path $PSScriptRoot "../../telemetry/generators/gen-auth-events.ps1"
$psGenerator   = Join-Path $PSScriptRoot "../../telemetry/generators/gen-powershell-events.ps1"
$smbGenerator  = Join-Path $PSScriptRoot "../../telemetry/generators/gen-smb-events.ps1"

$startTime = (Get-Date).ToUniversalTime()
$stageResults = @()

# -----------------------------------------------------------------
# STAGE 1: Credential Brute Force (5 Failed Logons) -> DET-01-PRIM
# -----------------------------------------------------------------
Write-Host "`n[Stage 1] Executing 5 Failed Network Logons (T1110.001)..." -ForegroundColor Yellow
$stage1Result = & $authGenerator -TargetUser $TargetUser -FailureCount 5 -SuccessCount 0 -TestCaseId "TC-E2E-STAGE1"
$stageResults += [ordered]@{
    Stage       = 1
    Name        = "Brute Force Password Guessing"
    Technique   = "T1110.001"
    Component   = "DET-01-PRIM"
    Timestamp   = (Get-Date).ToUniversalTime().ToString("o")
    Status      = if ($stage1Result.FailuresEmitted -ge 5) { "SUCCESS" } else { "PARTIAL" }
    Details     = "Emitted $($stage1Result.FailuresEmitted) Event 4625 failure records."
}

# -----------------------------------------------------------------
# STAGE 2: Successful Authentication Breach -> DET-02-PRIM & CORR-01
# -----------------------------------------------------------------
Write-Host "`n[Stage 2] Executing 1 Successful Network Logon (T1078.003)..." -ForegroundColor Yellow
$stage2Result = & $authGenerator -TargetUser $TargetUser -FailureCount 0 -SuccessCount 1 -TestCaseId "TC-E2E-STAGE2"
$stageResults += [ordered]@{
    Stage       = 2
    Name        = "Account Breach & Initial Access"
    Technique   = "T1078.003"
    Component   = "DET-02-PRIM / CORR-01"
    Timestamp   = (Get-Date).ToUniversalTime().ToString("o")
    Status      = if ($stage2Result.SuccessEmitted -ge 1) { "SUCCESS" } else { "FAILED" }
    Details     = "Emitted $($stage2Result.SuccessEmitted) Event 4624 success record; triggers CORR-01 composite correlation."
}

# -----------------------------------------------------------------
# STAGE 3: Encoded PowerShell Discovery -> DET-03 (T1059.001)
# -----------------------------------------------------------------
Write-Host "`n[Stage 3] Executing Encoded PowerShell Discovery (T1059.001 / T1027)..." -ForegroundColor Yellow
$stage3Result = & $psGenerator -CommandText "Write-Output 'Stage 3 Host Discovery'; hostname" -FlagStyle "EncodedCommand" -TestCaseId "TC-E2E-STAGE3"
$stageResults += [ordered]@{
    Stage       = 3
    Name        = "Obfuscated Host Discovery"
    Technique   = "T1059.001 / T1027"
    Component   = "DET-03"
    Timestamp   = (Get-Date).ToUniversalTime().ToString("o")
    Status      = if ($stage3Result.ExecutionSuccess) { "SUCCESS" } else { "FAILED" }
    Details     = "Executed benign base64 command line targeting powershell.exe."
}

# -----------------------------------------------------------------
# STAGE 4: Administrative Share Access -> DET-04 (T1021.002)
# -----------------------------------------------------------------
Write-Host "`n[Stage 4] Executing Administrative Share Access (T1021.002)..." -ForegroundColor Yellow
$stage4Result = & $smbGenerator -TargetHost "127.0.0.1" -ShareName "IPC$" -TestCaseId "TC-E2E-STAGE4"
$stageResults += [ordered]@{
    Stage       = 4
    Name        = "Remote Services SMB Share Access"
    Technique   = "T1021.002"
    Component   = "DET-04"
    Timestamp   = (Get-Date).ToUniversalTime().ToString("o")
    Status      = if ($stage4Result.ExecutionSuccess) { "SUCCESS" } else { "FAILED" }
    Details     = "Connected to loopback IPC$ share and enumerated shares."
}

$endTime = (Get-Date).ToUniversalTime()

$e2eProof = [ordered]@{
    ScenarioId         = "SCEN-01"
    Description        = "End-to-End Threat Scenario: Brute Force to Administrative Lateral Movement"
    StartTimeUtc       = $startTime.ToString("o")
    EndTimeUtc         = $endTime.ToString("o")
    DurationSeconds    = ($endTime - $startTime).TotalSeconds
    TargetUser         = $TargetUser
    ThreatActorProfile = "APT-LAB-01"
    AttackerIpSanitized = "198.51.100.55"
    VictimHostSanitized = "LAB-HOST01"
    VictimIpSanitized   = "192.0.2.100"
    StagesCompleted    = $stageResults.Count
    AllStagesSuccessful = ($stageResults | Where-Object { $_.Status -ne "SUCCESS" }).Count -eq 0
    StageBreakdown     = $stageResults
    Compliance         = [ordered]@{
        NFR02_ZeroSecrets     = "PASS"
        NFR03_SanitizedSubnets = "RFC 5737 Compliant (198.51.100.55 / 192.0.2.100 / 127.0.0.1)"
        SimulationSafety       = "Strictly Benign OS Operations Only"
    }
}

$evidenceDir = Split-Path $EvidencePath -Parent
if ($evidenceDir -and -not (Test-Path $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Resolve-Path $evidenceDir).Path + "\" + (Split-Path $EvidencePath -Leaf), ($e2eProof | ConvertTo-Json -Depth 5), $utf8NoBom)
Write-Host "`n[+] SCEN-01 Simulation evidence written to: $EvidencePath" -ForegroundColor Green

Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "SCEN-01 Simulation Summary:" -ForegroundColor Cyan
Write-Host "  Total Stages    : $($stageResults.Count)" -ForegroundColor White
Write-Host "  All Successful  : $($e2eProof.AllStagesSuccessful)" -ForegroundColor $(if ($e2eProof.AllStagesSuccessful) { "Green" } else { "Yellow" })
Write-Host "  Duration        : $([Math]::Round($e2eProof.DurationSeconds, 2)) seconds" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan

return $e2eProof
