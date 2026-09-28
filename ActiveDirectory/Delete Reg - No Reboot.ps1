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
