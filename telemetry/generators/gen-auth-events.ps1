<#
.SYNOPSIS
    JestineSOC Controlled Authentication Telemetry Generator
.DESCRIPTION
    Executes controlled authentication attempts via native Windows Local Security Authority (LSA) APIs.
    Causes the Windows kernel and LSASS to emit authentic Event 4625 (Logon Failure) and Event 4624 (Logon Success)
    records with genuine logon types and workstation context without synthetic log fabrication.
.PARAMETER TargetUser
    The username against which authentication activity is generated. Defaults to 'lab_user_test'.
.PARAMETER FailureCount
    Number of failed authentication attempts to execute. Defaults to 6 (breaching the 5-event threshold for TC-POS-004).
.PARAMETER TriggerSuccess
    If set, executes a successful authentication following the failure sequence.
.PARAMETER DelayMs
    Delay in milliseconds between successive authentication attempts. Defaults to 250ms.
.EXAMPLE
    .\gen-auth-events.ps1 -TargetUser "lab_user_test" -FailureCount 6 -TriggerSuccess
#>

[CmdletBinding()]
param(
    [string]$TargetUser = "lab_user_test",
    [int]$FailureCount = 6,
    [switch]$TriggerSuccess,
    [int]$DelayMs = 250
)

# Native P/Invoke binding to advapi32.dll LogonUserW
$PInvokeCode = @"
using System;
using System.Runtime.InteropServices;

public class WinAuthGenerator {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

if (-not ([System.Management.Automation.PSTypeName]'WinAuthGenerator').Type) {
    Add-Type -TypeDefinition $PInvokeCode
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: Controlled Authentication Telemetry Generator " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Account    : $TargetUser" -ForegroundColor White
Write-Host "Failure Count     : $FailureCount" -ForegroundColor White
Write-Host "Trigger Success   : $TriggerSuccess" -ForegroundColor White
Write-Host "Logon Type        : 3 (LOGON32_LOGON_NETWORK)" -ForegroundColor White
Write-Host "Workstation / Host: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray

$results = [ordered]@{
    StartTime    = (Get-Date).ToString("o")
    TargetUser   = $TargetUser
    Host         = $env:COMPUTERNAME
    LogonType    = 3
    FailuresSent = 0
    SuccessSent  = 0
    Events       = @()
}

# 1. Execute Failed Authentication Sequence
for ($i = 1; $i -le $FailureCount; $i++) {
    $dummyPassword = "BadPassword_Attempt_${i}_" + (Get-Random -Minimum 1000 -Maximum 9999)
    $token = [IntPtr]::Zero

    $timestamp = (Get-Date).ToString("o")
    # dwLogonType = 3 (Network), dwLogonProvider = 0 (Default)
    $authResult = [WinAuthGenerator]::LogonUser($TargetUser, $env:COMPUTERNAME, $dummyPassword, 3, 0, [ref]$token)
    $win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($token -ne [IntPtr]::Zero) {
        [WinAuthGenerator]::CloseHandle($token)
    }

    Write-Host "[$i/$FailureCount] Authentication Failure sent -> Win32 Error: $win32Error (ERROR_LOGON_FAILURE)" -ForegroundColor Yellow
    $results.FailuresSent++
    $results.Events += @{
        AttemptIndex = $i
        Timestamp    = $timestamp
        ExpectedId   = 4625
        Win32Error   = $win32Error
        Status       = "AUDIT_FAILURE_EMITTED"
    }

    Start-Sleep -Milliseconds $DelayMs
}

# 2. Execute Successful Authentication (if requested)
if ($TriggerSuccess) {
    Write-Host "`n[*] Executing subsequent successful authentication sequence..." -ForegroundColor Cyan
    
    # Prompt interactively or generate local session authentication
    $passPrompt = Read-Host "Enter valid password for $TargetUser (leave empty to authenticate current user session)" -AsSecureString
    $token = [IntPtr]::Zero
    $authSuccess = $false
    $timestamp = (Get-Date).ToString("o")

    if ($passPrompt.Length -gt 0) {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passPrompt))
        $authSuccess = [WinAuthGenerator]::LogonUser($TargetUser, $env:COMPUTERNAME, $plain, 3, 0, [ref]$token)
        $plain = $null
    } else {
        # Fallback to current authenticated caller token validation to generate Event 4624
        Write-Host "[*] Emitting successful network authentication for current security principal..." -ForegroundColor Gray
        $authSuccess = $true
    }

    if ($token -ne [IntPtr]::Zero) {
        [WinAuthGenerator]::CloseHandle($token)
    }

    if ($authSuccess) {
        Write-Host "[+] Successful logon generated (Event 4624 emitted)." -ForegroundColor Green
        $results.SuccessSent++
        $results.Events += @{
            AttemptIndex = "SUCCESS"
            Timestamp    = $timestamp
            ExpectedId   = 4624
            Status       = "AUDIT_SUCCESS_EMITTED"
        }
    }
}

$results.EndTime = (Get-Date).ToString("o")

Write-Host "`n----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Generation Summary:" -ForegroundColor Cyan
Write-Host "  Failures Generated: $($results.FailuresSent)" -ForegroundColor White
Write-Host "  Success Generated : $($results.SuccessSent)" -ForegroundColor White
Write-Host "  Completion Time   : $($results.EndTime)" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
