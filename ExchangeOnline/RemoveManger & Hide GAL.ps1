<#
AD Disabled User Cleanup and GAL Management

.DESCRIPTION
This script identifies disabled Active Directory user accounts within a specified OU,
creates a backup of user and manager information, removes manager assignments,
hides accounts from the Global Address List (GAL), and generates detailed logs
for auditing and compliance purposes.

.FEATURES
- Disabled user discovery
- CSV backup generation
- Manager attribute removal
- Hide users from GAL
- Detailed logging
- Execution summary reporting

.AUTHOR
Bhagawan Tapase
#>

Import-Module ActiveDirectory

#=========================================================
# CONFIGURATION
#=========================================================
$OU = "OU=Users,OU=Test OU,DC=Domain,DC=com"

$Date = Get-Date -Format "yyyyMMdd_HHmmss"

$ReportPath = "D:\Report-Manager"

$BackupFile = "$ReportPath\DisabledUsers_Backup_$Date.csv"
$LogFile = "$ReportPath\DisabledUsers_Log_$Date.txt"

#=========================================================
# CREATE FOLDER IF NOT EXISTS
#=========================================================
if (!(Test-Path $ReportPath))
{
    New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
}

#=========================================================
# GET DISABLED USERS
#=========================================================
$DisabledUsers = Get-ADUser `
    -SearchBase $OU `
    -SearchScope Subtree `
    -Filter 'Enabled -eq $False' `
    -Properties *

Write-Host "Disabled users found: $($DisabledUsers.Count)" -ForegroundColor Yellow

if (!$DisabledUsers)
{
    Write-Host "No disabled users found in the specified OU." -ForegroundColor Red
    exit
}

#=========================================================
# BACKUP USER DETAILS
#=========================================================
$BackupData = foreach ($User in $DisabledUsers)
{
    $ManagerDisplayName = $null
    $ManagerSamAccountName = $null

    if ($User.Manager)
    {
        try
        {
            $Manager = Get-ADUser $User.Manager -Properties DisplayName

            $ManagerDisplayName = $Manager.DisplayName
            $ManagerSamAccountName = $Manager.SamAccountName
        }
        catch
        {
            $ManagerDisplayName = "Unable to Retrieve"
            $ManagerSamAccountName = "Unable to Retrieve"
        }
    }

[PSCustomObject]@{
    SamAccountName        = $User.SamAccountName
    DisplayName           = $User.DisplayName
    EmailAddress          = $User.Mail
    EmployeeNumber        = $User.EmployeeNumber
    AccountStatus         = if ($User.Enabled) { "Enabled" } else { "Disabled" }
    ManagerDisplayName    = $ManagerDisplayName
    ManagerSamAccountName = $ManagerSamAccountName
    GALStatus             = if ($User.msExchHideFromAddressLists) { "Hidden" } else { "Visible" }
}
}

$BackupData | Export-Csv $BackupFile -NoTypeInformation -Encoding UTF8

Write-Host "Backup completed: $BackupFile" -ForegroundColor Green

#=========================================================
# LOG START
#=========================================================
Add-Content $LogFile "================================================="
Add-Content $LogFile "Script Started : $(Get-Date)"
Add-Content $LogFile "OU : $OU"
Add-Content $LogFile "Users Found : $($DisabledUsers.Count)"
Add-Content $LogFile "Backup File : $BackupFile"
Add-Content $LogFile "================================================="

#=========================================================
# REMOVE MANAGER & HIDE FROM GAL
#=========================================================
foreach ($User in $DisabledUsers)
{
    try
    {
        # Remove Manager
        Set-ADUser -Identity $User.SamAccountName -Clear Manager

        # Hide From GAL
        Set-ADUser -Identity $User.SamAccountName -Replace @{
            msExchHideFromAddressLists = $true
        }

        Add-Content $LogFile "$(Get-Date) SUCCESS : $($User.SamAccountName) - Manager Removed and Hidden from GAL"

        Write-Host "SUCCESS : $($User.SamAccountName)" -ForegroundColor Green
    }
    catch
    {
        Add-Content $LogFile "$(Get-Date) ERROR : $($User.SamAccountName) - $($_.Exception.Message)"

        Write-Host "ERROR : $($User.SamAccountName) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

#=========================================================
# SUMMARY
#=========================================================
$ProcessedCount = $DisabledUsers.Count

Add-Content $LogFile "================================================="
Add-Content $LogFile "Script Completed : $(Get-Date)"
Add-Content $LogFile "Users Processed : $ProcessedCount"
Add-Content $LogFile "================================================="

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "SCRIPT COMPLETED SUCCESSFULLY" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Users Processed : $ProcessedCount" -ForegroundColor Yellow
Write-Host "Backup File     : $BackupFile" -ForegroundColor Yellow
Write-Host "Log File        : $LogFile" -ForegroundColor Yellow
