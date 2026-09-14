<#
.SYNOPSIS
    JestineSOC Controlled Authentication Telemetry Generator & Verifier
.DESCRIPTION
    Executes controlled authentication attempts via native Windows Local Security Authority (LSA) APIs.
    Causes the Windows kernel and LSASS to emit authentic Event 4625 (Logon Failure) and Event 4624 (Logon Success)
    records with genuine logon types and workstation context without synthetic log fabrication.
    Includes programmatic verification against the Windows Security log when run with appropriate privileges.
.PARAMETER TargetUser
    The username against which authentication activity is generated. Defaults to 'lab_user_test'.
.PARAMETER FailureCount
    Number of failed authentication attempts to execute. Defaults to 5 (threshold for TC-POS-004).
.PARAMETER TriggerSuccess
    If set, executes a genuine successful authentication following the failure sequence.
.PARAMETER ValidPassword
    SecureString containing the valid password for TargetUser. Required if -TriggerSuccess is specified.
.PARAMETER DelayMs
    Delay in milliseconds between successive authentication attempts. Defaults to 250ms.
.PARAMETER TestCaseId
    Identifier for the test case being verified. Defaults to 'TC-TEL-001'.
.EXAMPLE
    .\gen-auth-events.ps1 -TargetUser "lab_user_test" -FailureCount 5
.EXAMPLE
    $secPass = Read-Host "Password" -AsSecureString
    .\gen-auth-events.ps1 -TargetUser "lab_user_test" -FailureCount 5 -TriggerSuccess -ValidPassword $secPass
#>

[CmdletBinding()]
param(
    [string]$TargetUser = "lab_user_test",
    [int]$FailureCount = 5,
    [switch]$TriggerSuccess,
    [Security.SecureString]$ValidPassword,
    [int]$DelayMs = 250,
    [string]$TestCaseId = "TC-TEL-001",
    [switch]$ExportEvidence,
    [string]$EvidenceOutputPath = "evidence/telemetry/evtx-auth-sample.json"
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

$RunId = "RUN-" + (Get-Date -Format "yyyyMMdd-HHmmss")
$StartTime = Get-Date

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  JestineSOC: Controlled Authentication Telemetry Generator " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Run ID            : $RunId" -ForegroundColor White
Write-Host "Test Case ID      : $TestCaseId" -ForegroundColor White
Write-Host "Target Account    : $TargetUser" -ForegroundColor White
Write-Host "Failure Count     : $FailureCount" -ForegroundColor White
Write-Host "Trigger Success   : $TriggerSuccess" -ForegroundColor White
Write-Host "Logon Type        : 3 (LOGON32_LOGON_NETWORK)" -ForegroundColor White
Write-Host "Workstation / Host: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Start Time        : $($StartTime.ToString('o'))" -ForegroundColor White
Write-Host "----------------------------------------------------------" -ForegroundColor DarkGray

$runMetadata = [ordered]@{
    RunId             = $RunId
    TestCaseId        = $TestCaseId
    Command           = "gen-auth-events.ps1 -TargetUser $TargetUser -FailureCount $FailureCount -TriggerSuccess:$TriggerSuccess"
    StartTime         = $StartTime.ToString("o")
    TargetUser        = $TargetUser
    Host              = $env:COMPUTERNAME
    LogonType         = 3
    FailuresRequested = $FailureCount
    FailuresEmitted   = 0
    FailuresObserved  = 0
    SuccessRequested  = $(if ($TriggerSuccess) { 1 } else { 0 })
    SuccessEmitted    = 0
    SuccessObserved   = 0
    VerificationState = "PENDING"
    ObservedEvents    = @()
}

# 1. Execute Authentic Failed Authentication Sequence
for ($i = 1; $i -le $FailureCount; $i++) {
    $dummyPassword = "BadPassword_Attempt_${i}_" + (Get-Random -Minimum 1000 -Maximum 9999)
    $token = [IntPtr]::Zero

    # dwLogonType = 3 (Network), dwLogonProvider = 0 (Default)
    $authResult = [WinAuthGenerator]::LogonUser($TargetUser, $env:COMPUTERNAME, $dummyPassword, 3, 0, [ref]$token)
    $win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($token -ne [IntPtr]::Zero) {
        [WinAuthGenerator]::CloseHandle($token)
    }

    if ($win32Error -eq 1326 -or $win32Error -eq 1327 -or $win32Error -eq 1331) {
        Write-Host "[$i/$FailureCount] Authentication Failure emitted -> Win32 Error: $win32Error (ERROR_LOGON_FAILURE)" -ForegroundColor Yellow
        $runMetadata.FailuresEmitted++
    } else {
        Write-Warning "[$i/$FailureCount] Unexpected Win32 error code: $win32Error"
    }

    Start-Sleep -Milliseconds $DelayMs
}

# 2. Execute Genuine Successful Authentication (if requested)
if ($TriggerSuccess) {
    Write-Host "`n[*] Executing genuine successful authentication sequence..." -ForegroundColor Cyan
    
    # Require actual valid password - NO fake success fallbacks permitted
    if (-not $ValidPassword -or $ValidPassword.Length -eq 0) {
        $ValidPassword = Read-Host "Enter genuine password for '$TargetUser' to trigger authentic Event 4624" -AsSecureString
    }

    if ($ValidPassword.Length -eq 0) {
        Write-Error "TriggerSuccess was requested, but no valid password was provided. Halting without emitting Event 4624."
        $runMetadata.SuccessEmitted = 0
    } else {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ValidPassword))
        $token = [IntPtr]::Zero
        
        $authSuccess = [WinAuthGenerator]::LogonUser($TargetUser, $env:COMPUTERNAME, $plain, 3, 0, [ref]$token)
        $win32SuccessError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $plain = $null

        if ($token -ne [IntPtr]::Zero) {
            [WinAuthGenerator]::CloseHandle($token)
        }

        if ($authSuccess) {
            Write-Host "[+] A successful native Windows authentication was performed, causing Windows Security auditing to record Event 4624." -ForegroundColor Green
            $runMetadata.SuccessEmitted = 1
        } else {
            Write-Warning "LogonUser failed for '$TargetUser' with Win32 Error: $win32SuccessError. Event 4624 NOT recorded."
            $runMetadata.SuccessEmitted = 0
        }
    }
}

$EndTime = Get-Date
$runMetadata["EndTime"] = $EndTime.ToString("o")

# Allow short delay for Windows Event Log subsystem buffer flushing
Start-Sleep -Milliseconds 750

# 3. Programmatic Event Log Verification (P1-07)
Write-Host "`n[*] Performing programmatic event log verification..." -ForegroundColor Gray
try {
    # Query boundaries: StartTime <= event.TimeCreated <= EndTime (with buffer margins)
    $queryStartTime = $StartTime.AddSeconds(-1)
    $queryEndTime = $EndTime.AddSeconds(3)

    $detectedFailures = @(Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625
        StartTime = $queryStartTime
        EndTime   = $queryEndTime
    } -ErrorAction Stop | Where-Object {
        $_.TimeCreated -ge $StartTime.AddMilliseconds(-500) -and
        $_.TimeCreated -le $EndTime.AddSeconds(2) -and
        ($_.Properties[5].Value -eq $TargetUser -or $_.Message -match $TargetUser)
    })

    $runMetadata.FailuresObserved = $detectedFailures.Count
    Write-Host "[+] Programmatic Verification: Found $($detectedFailures.Count) matching Event 4625 records in Security.evtx within execution window." -ForegroundColor Green

    if ($TriggerSuccess) {
        $detectedSuccess = @(Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4624
            StartTime = $queryStartTime
            EndTime   = $queryEndTime
        } -ErrorAction Stop | Where-Object {
            $_.TimeCreated -ge $StartTime.AddMilliseconds(-500) -and
            $_.TimeCreated -le $EndTime.AddSeconds(2) -and
            ($_.Properties[5].Value -eq $TargetUser -or $_.Message -match $TargetUser)
        })
        $runMetadata.SuccessObserved = $detectedSuccess.Count
        Write-Host "[+] Programmatic Verification: Found $($detectedSuccess.Count) matching Event 4624 records in Security.evtx within execution window." -ForegroundColor Green
    } else {
        $detectedSuccess = @()
        $runMetadata.SuccessObserved = 0
    }

    # Extract event attributes including RecordId for auditable evidence provenance
    $observedRecords = @()
    foreach ($evt in ($detectedFailures + $detectedSuccess)) {
        [xml]$evtXml = $evt.ToXml()
        $dataNodes = $evtXml.Event.EventData.Data
        $extractedUser = ($dataNodes | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $extractedLogonType = ($dataNodes | Where-Object { $_.Name -eq 'LogonType' }).'#text'

        $observedRecords += [ordered]@{
            RecordId       = $evt.RecordId
            EventID        = $evt.Id
            TimeCreated    = $evt.TimeCreated.ToString("o")
            TargetUserName = $extractedUser
            LogonType      = $extractedLogonType
        }
    }
    $runMetadata.ObservedEvents = $observedRecords

    # Strict multi-factor verification asserting requested == emitted == observed for both failure and success
    $failuresMatch = ($runMetadata.FailuresRequested -eq $runMetadata.FailuresEmitted) -and 
                     ($runMetadata.FailuresEmitted -eq $runMetadata.FailuresObserved)

    if ($TriggerSuccess) {
        $successMatch = ($runMetadata.SuccessRequested -eq 1) -and 
                        ($runMetadata.SuccessEmitted -eq 1) -and 
                        ($runMetadata.SuccessObserved -eq 1)
    } else {
        $successMatch = ($runMetadata.SuccessRequested -eq 0) -and 
                        ($runMetadata.SuccessEmitted -eq 0) -and 
                        ($runMetadata.SuccessObserved -eq 0)
    }

    if ($failuresMatch -and $successMatch) {
        $runMetadata.VerificationState = "VERIFIED_ACCURATE"
    } else {
        $runMetadata.VerificationState = "DISCREPANCY_DETECTED"
    }
} catch {
    if (($_.Exception -is [System.UnauthorizedAccessException]) -or ($_.Exception.Message -match "unauthorized")) {
        Write-Host "[!] Notice: Security.evtx read access requires Administrator privilege." -ForegroundColor Yellow
        Write-Host "    Telemetry generation executed at LSASS API boundary (Win32 Error 1326 observed)." -ForegroundColor DarkGray
        Write-Host "    Run in elevated session or execute inspect-auth-events.ps1 to verify raw event records." -ForegroundColor DarkGray
        $runMetadata.VerificationState = "API_EMITTED_LOG_READ_RESTRICTED"
    } elseif ($_.Exception.Message -match "No events were found") {
        $runMetadata.FailuresObserved = 0
        $runMetadata.SuccessObserved = 0
        $runMetadata.VerificationState = "NO_EVENTS_FOUND_IN_WINDOW"
        Write-Warning "No matching events found in Security.evtx within the query time window."
    } else {
        Write-Warning "Event query encountered exception: $($_.Exception.Message)"
        $runMetadata.VerificationState = "QUERY_EXCEPTION"
    }
}

Write-Host "`n----------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Execution Summary:" -ForegroundColor Cyan
Write-Host "  Run ID             : $($runMetadata.RunId)" -ForegroundColor White
Write-Host "  Test Case ID       : $($runMetadata.TestCaseId)" -ForegroundColor White
Write-Host "  Failures Requested : $($runMetadata.FailuresRequested)" -ForegroundColor White
Write-Host "  Failures Emitted   : $($runMetadata.FailuresEmitted)" -ForegroundColor White
Write-Host "  Failures Observed  : $($runMetadata.FailuresObserved)" -ForegroundColor White
Write-Host "  Success Requested  : $($runMetadata.SuccessRequested)" -ForegroundColor White
Write-Host "  Success Emitted    : $($runMetadata.SuccessEmitted)" -ForegroundColor White
Write-Host "  Success Observed   : $($runMetadata.SuccessObserved)" -ForegroundColor White
Write-Host "  Verification State : $($runMetadata.VerificationState)" -ForegroundColor White
if ($runMetadata.ObservedEvents.Count -gt 0) {
    $ids = ($runMetadata.ObservedEvents | ForEach-Object { "$($_.EventID)(Record#$($_.RecordId))" }) -join ', '
    Write-Host "  Observed Records   : $ids" -ForegroundColor White
}
Write-Host "==========================================================" -ForegroundColor Cyan

return $runMetadata
