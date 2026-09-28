<#
Script Name : Remove_InactivityTimeoutSecs_Reboot.ps1

Description :
This PowerShell script automates the removal of the InactivityTimeoutSecs registry value from multiple remote Windows servers using PsExec. The script reads a list of target servers, deletes the specified registry value under the local security policy registry path, verifies the operation result, and initiates an immediate reboot only on servers where the registry value was successfully removed. All execution results, including deletion and reboot status, are captured and exported to a CSV report for auditing, compliance tracking, and change management purposes.

Key Features:
✅ Bulk server processing
✅ Remote registry deletion using PsExec
✅ Removes InactivityTimeoutSecs security policy setting
✅ Automatic reboot after successful registry removal
✅ Skips reboot when registry value is not found
✅ Tracks Deleted, Not Found, Access Denied, and Error states
✅ Captures reboot status for each server
✅ Generates CSV audit report
✅ Exception handling and logging

Output:
- CSV report containing Computer Name, Registry Removal Status, and Reboot Status.
#>
$PsExecPath = "C:\Temp\PsExec.exe"
$Servers = Get-Content "C:\Temp\servers.txt"
$Results = @()

foreach ($Server in $Servers) {
    Write-Host "Deleting InactivityTimeoutSecs on $Server..."
    try {
        # Delete registry value
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

        # If deleted successfully, reboot the machine
        if ($Value -eq "Deleted") {
            Write-Host "Rebooting $Server..."
            $RebootOutput = & $PsExecPath "\\$Server" -s shutdown /r /t 0 2>&1
            if ($RebootOutput -match "shutdown") {
                $RebootStatus = "Reboot Initiated"
            } else {
                $RebootStatus = "Reboot Failed"
            }
        } else {
            $RebootStatus = "Skipped"
        }

        $Results += [PSCustomObject]@{
            ComputerName = $Server
            Status       = $Value
            Reboot       = $RebootStatus
        }
    }
    catch {
        $Results += [PSCustomObject]@{
            ComputerName = $Server
            Status       = "Error"
            Reboot       = "Error"
        }
    }
}

$Results | Export-Csv "C:\Temp\new1.csv" -NoTypeInformation

