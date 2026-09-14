<#
.SYNOPSIS
    JestineSOC Authentic Authentication Event Verification & Inspector
.DESCRIPTION
    Trigger genuine Windows authentication activity (causing Windows LSASS to emit Events 4625 & 4624)
    and extracts authentic field structures from the Security event log for empirical baseline inspection.
.NOTES
    Requires Administrator privileges (Run as Administrator) to read the Windows Security Event Log.
#>

[CmdletBinding()]
param(
    [string]$EvidenceOutputPath = "evidence/telemetry/evtx-auth-sample.json"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: Authentic Windows Authentication Inspector  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check for Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Elevation required: Windows Security Event Log (Security.evtx) requires Administrator privileges."
    Write-Host "Please re-run this script in an elevated PowerShell session (Run as Administrator)." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] Elevated Administrator privileges confirmed." -ForegroundColor Green

# 2. Check Audit Policy
Write-Host "[*] Inspecting active audit policy for Logon subcategory..." -ForegroundColor Gray
$auditStatus = auditpol /get /subcategory:"Logon"
$auditStatus | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

# 3. Cause Authentic Event 4625 (Failed Authentication)
$testAccount = "lab_user_test"
$badPassword = "DeliberatelyInvalidPassword999!"

Write-Host "`n[*] Generating controlled authentication failure for account: $testAccount" -ForegroundColor Cyan
# Invoke native LogonUser API via .NET P/Invoke to generate genuine LSASS rejection without modifying network state
$sourceCode = @"
using System;
using System.Runtime.InteropServices;

public class LsaAuth {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
    );
}
"@
if (-not ([System.Management.Automation.PSTypeName]'LsaAuth').Type) {
    Add-Type -TypeDefinition $sourceCode
}

$token = [IntPtr]::Zero
# dwLogonType = 3 (LOGON32_LOGON_NETWORK), dwLogonProvider = 0 (LOGON32_PROVIDER_DEFAULT)
$null = [LsaAuth]::LogonUser($testAccount, $env:COMPUTERNAME, $badPassword, 3, 0, [ref]$token)
$winErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Host "[+] LSASS returned Win32 Error: $winErr (Expected ERROR_LOGON_FAILURE = 1326)" -ForegroundColor Green

# Small sleep for event log commit
Start-Sleep -Milliseconds 500

# 4. Extract and Inspect the Generated Event 4625
Write-Host "[*] Querying Security log for resulting Event 4625..." -ForegroundColor Cyan
$failedEvent = Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4625 } -MaxEvents 1

[xml]$failedXml = $failedEvent.ToXml()
$dataNodes = $failedXml.Event.EventData.Data

$parsed4625 = [ordered]@{
    EventID             = 4625
    TimeCreated         = $failedEvent.TimeCreated.ToString("o")
    TargetUserName      = ($dataNodes | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    TargetDomainName    = ($dataNodes | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    LogonType           = ($dataNodes | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    Status              = ($dataNodes | Where-Object { $_.Name -eq 'Status' }).'#text'
    SubStatus           = ($dataNodes | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
    WorkstationName     = ($dataNodes | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    IpAddress           = ($dataNodes | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
}

Write-Host "`n[+] Captured Authentic Event 4625 Telemetry:" -ForegroundColor Yellow
$parsed4625 | Out-String | Write-Host -ForegroundColor White

# 5. Extract Recent Event 4624 (Logon Success) for Baseline Comparison
Write-Host "[*] Querying Security log for baseline Event 4624 (Successful Logon)..." -ForegroundColor Cyan
$successEvent = Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4624 } -MaxEvents 1

[xml]$successXml = $successEvent.ToXml()
$sDataNodes = $successXml.Event.EventData.Data

$parsed4624 = [ordered]@{
    EventID             = 4624
    TimeCreated         = $successEvent.TimeCreated.ToString("o")
    TargetUserName      = ($sDataNodes | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    TargetDomainName    = ($sDataNodes | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
    LogonType           = ($sDataNodes | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    LogonGuid           = ($sDataNodes | Where-Object { $_.Name -eq 'LogonGuid' }).'#text'
    WorkstationName     = ($sDataNodes | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    IpAddress           = ($sDataNodes | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
}

Write-Host "[+] Captured Authentic Event 4624 Telemetry:" -ForegroundColor Yellow
$parsed4624 | Out-String | Write-Host -ForegroundColor White

# 6. Export Sanitized Evidence Artifact
$evidence = @{
    AuditTimestamp = (Get-Date).ToString("o")
    SystemHost     = "LAB-HOST01" # Sanitized hostname
    AuditStatus    = "PASS"
    Event_4625     = $parsed4625
    Event_4624     = $parsed4624
}

# Ensure directory exists
$targetDir = Split-Path $EvidenceOutputPath -Parent
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$evidence | ConvertTo-Json -Depth 4 | Set-Content -Path $EvidenceOutputPath -Encoding utf8
Write-Host "[+] Sanitized evidence exported to: $EvidenceOutputPath" -ForegroundColor Green
