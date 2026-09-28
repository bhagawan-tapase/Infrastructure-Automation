$results = @()

Import-Csv "D:\Users.csv" | ForEach-Object {
    $userResult = [PSCustomObject]@{
        SamAccountName = $_.SamAccountName
        Status         = ""
        ErrorMessage   = ""
    }

    try {
        Disable-ADAccount -Identity $_.SamAccountName -ErrorAction Stop
        $user = Get-ADUser -Identity $_.SamAccountName
        if ($user.Enabled -eq $false) {
            $userResult.Status = "Disabled"
        } else {
            $userResult.Status = "Still Enabled"
        }
        Write-Host "Disabled: $($_.SamAccountName)" -ForegroundColor Green
    } catch {
        $userResult.Status = "Error"
        $userResult.ErrorMessage = $_.Exception.Message
        Write-Host "Error disabling: $($_.SamAccountName) - $_" -ForegroundColor Red
    }

    $results += $userResult
}

$results | Export-Csv "D:\Report\AD_Disable_Report1612.csv" -NoTypeInformation
Write-Host "Report exported to D:\AD_Disable_Report1612.csv" -ForegroundColor Cyan
