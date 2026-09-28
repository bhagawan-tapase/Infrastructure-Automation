<#
Script Name : Remove_InactivityTimeoutSecs.ps1

Description :
This PowerShell script automates the removal of the InactivityTimeoutSecs registry value from remote Windows servers using PsExec. The script reads a list of target servers, remotely deletes the registry setting under the system security policies path, verifies the operation result, captures success or failure status for each server, and exports the results to a CSV report for auditing and compliance tracking.

Key Features:
✅ Bulk processing of multiple servers
✅ Remote registry modification using PsExec
✅ Removal of InactivityTimeoutSecs policy setting
✅ Success, Not Found, Access Denied, and Error tracking
✅ Automated CSV reporting
✅ Exception handling for unreachable or failed systems
✅ Useful for security policy rollback and configuration remediation

Output:
- CSV report containing server name and operation status.
#>

$PsExecPath = "C:\Temp\PsExec.exe"
$Servers = Get-Content "C:\Temp\servers.txt"  # Or use your CSV if needed
$Results = @()

foreach ($Server in $Servers) {
    Write-Host "Deleting InactivityTimeoutSecs on $Server..."
    try {
        $Output = & $PsExecPath "\\$Server" -s reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /f 2>&1

        if ($Output -match "The operation completed successfully") {
            $Value = "Deleted"
        } elseif ($Output -match "The system cannot find the file specified") {
            $Value = "Not Found"
        } elseif ($Output -match "Access is denied") {
            $Value = "Access Denied"
        } else {
            $Value = "Error"
        }

        $Results += [PSCustomObject]@{
            ComputerName = $Server
            Status       = $Value
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            ComputerName = $Server
            Status       = "Error"
        }
    }
}

$Results | Export-Csv "C:\Temp\Pending12.csv" -NoTypeInformation
