<#
.SYNOPSIS
    JestineSOC Controlled PowerShell Telemetry Generator
.DESCRIPTION
    Executes controlled, benign PowerShell commands utilizing common adversary evasion techniques
    (Base64 encoding, stealth CLI flags) to cause the operating system and Sysmon to emit Event 1
    (Process Creation) records for detection rule validation.
.PARAMETER Technique
    The specific simulation profile to execute. Options: 'EncodedCommand', 'BypassFlag', 'Discovery'.
.EXAMPLE
    .\gen-powershell-events.ps1 -Technique EncodedCommand
#>

[CmdletBinding()]
param(
    [ValidateSet("EncodedCommand", "BypassFlag", "Discovery")]
    [string]$Technique = "EncodedCommand"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: Controlled Process Telemetry Generator        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Selected Technique: $Technique" -ForegroundColor White
Write-Host "MITRE Technique   : T1059.001 (Command and Scripting: PowerShell)" -ForegroundColor White
Write-Host "Expected Telemetry: Sysmon Event 1 (Process Creation) / Win 4688" -ForegroundColor White
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray

$timestamp = (Get-Date).ToString("o")

switch ($Technique) {
    "EncodedCommand" {
        # Benign discovery payload encoded in UTF-16LE Base64 (Standard Windows command format)
        $payload = "Write-Output 'JestineSOC Controlled Telemetry Test: Host Discovery'; hostname"
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($payload)
        $encoded = [Convert]::ToBase64String($bytes)
        
        Write-Host "[*] Launching benign EncodedCommand execution..." -ForegroundColor Yellow
        Write-Host "    Decoded: $payload" -ForegroundColor DarkGray
        Write-Host "    Encoded: $encoded" -ForegroundColor DarkGray
        
        # Execute in non-interactive, hidden sub-process
        $p = Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded" -Wait -PassThru
        Write-Host "[+] Process completed with Exit Code: $($p.ExitCode)" -ForegroundColor Green
    }
    
    "BypassFlag" {
        Write-Host "[*] Launching ExecutionPolicy Bypass simulation..." -ForegroundColor Yellow
        $p = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command 'Get-Process -Id $PID'" -Wait -PassThru
        Write-Host "[+] Process completed with Exit Code: $($p.ExitCode)" -ForegroundColor Green
    }
    
    "Discovery" {
        Write-Host "[*] Launching benign system discovery sequence..." -ForegroundColor Yellow
        $p = Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'whoami; net user lab_user_test'" -Wait -PassThru
        Write-Host "[+] Process completed with Exit Code: $($p.ExitCode)" -ForegroundColor Green
    }
}

Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Simulation complete at $timestamp. Telemetry recorded by OS." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
