<#
.SYNOPSIS
    JestineSOC Controlled Telemetry Generator: Encoded PowerShell Simulation
.DESCRIPTION
    Executes a strictly benign base64-encoded PowerShell command to produce authentic
    Process Creation telemetry (Sysmon Event ID 1 / Windows Security Event ID 4688)
    for DET-03 validation.
.NOTES
    Safety Policy: STRICT BENIGN EXECUTION ONLY.
    Under no circumstances does this generator construct or execute live payloads,
    network beacons, credential dumps, or download cradles.
    Standard Alignment: MITRE ATT&CK T1059.001 / NIST CSF 2.0 DE.CM-01
#>

[CmdletBinding()]
param(
    [string]$TestCaseId = "TC-POS-004",
    [string]$EvidencePath = "evidence/telemetry/ev-powershell-execution.json",
    [switch]$DryRun
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: Encoded PowerShell Telemetry Generator      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Test Case ID     : $TestCaseId" -ForegroundColor White
Write-Host "Safety Policy    : Strictly Benign Discovery Commands Only" -ForegroundColor Green
Write-Host "Target Telemetry : Process Creation (Sysmon 1 / Security 4688)" -ForegroundColor White
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray

# Construct strictly benign PowerShell script
$benignCommand = "Write-Output 'JestineSOC Controlled Telemetry Test: Host Discovery'; Get-Date; hostname"
$unicodeBytes = [System.Text.Encoding]::Unicode.GetBytes($benignCommand)
$base64Encoded = [System.Convert]::ToBase64String($unicodeBytes)

$powershellExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$argumentList = "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $base64Encoded"

$startTime = Get-Date

if ($DryRun) {
    Write-Host "[*] Dry-run enabled. Simulated execution:" -ForegroundColor Yellow
    Write-Host "    Executable: $powershellExe" -ForegroundColor Yellow
    Write-Host "    Arguments : $argumentList" -ForegroundColor Yellow
    $exitCode = 0
} else {
    Write-Host "[*] Executing benign encoded command..." -ForegroundColor Yellow
    $proc = Start-Process -FilePath $powershellExe -ArgumentList $argumentList -NoNewWindow -PassThru -Wait
    $exitCode = $proc.ExitCode
    Write-Host "[+] Execution completed with exit code: $exitCode" -ForegroundColor Green
}

$endTime = Get-Date

$metadata = [ordered]@{
    TestCaseId           = $TestCaseId
    Generator            = "gen-powershell-events.ps1"
    ExecutionTimestamp   = $startTime.ToString("o")
    TargetImage          = $powershellExe
    CommandLine          = "$powershellExe $argumentList"
    DecodedPayload       = $benignCommand
    EncodedPayload       = $base64Encoded
    ExitCode             = $exitCode
    Host                 = "LAB-HOST01"
    SafetyStandard       = "Strictly Benign Lab Simulation (No Malicious Payloads)"
    SanitizationStandard = "RFC 5737 / Local Loopback Compliant (NFR-03)"
}

if ($EvidencePath) {
    $evidenceDir = Split-Path $EvidencePath -Parent
    if ($evidenceDir -and -not (Test-Path $evidenceDir)) {
        New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($EvidencePath, ($metadata | ConvertTo-Json -Depth 4), $utf8NoBom)
    Write-Host "[+] Generator metadata written to: $EvidencePath" -ForegroundColor Green
}

Write-Host "==========================================================" -ForegroundColor Cyan
return $metadata
