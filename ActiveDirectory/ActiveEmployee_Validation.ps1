<#
Script Name : AD_Employee_Lifecycle_Management.ps1
 
Description :
This script automates Active Directory employee lifecycle management by
validating employee records from a CSV source, updating user attributes,
managing account enable/disable actions based on employee status, and
generating an audit report of all changes and account activities.
 
Author : Bhagawan Tapase
Version : 1.0
#>

Import-Module ActiveDirectory

# ------------------------------------------------
# FILE PATHS
# ------------------------------------------------
$csvPath = "D:\ActiveEmployees_Validation.csv"

$currentDate = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFolder = "D:\Report_Employees_Validation"
$reportPath = "$reportFolder\AD_Change_Report_$currentDate.csv"

# Ensure report folder exists
if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

# Report data holder
$report = @()

# ------------------------------------------------
# PROCESS CSV
# ------------------------------------------------
Import-Csv $csvPath | ForEach-Object {

    $sam = $_.SamAccountName

    $user = Get-ADUser $sam -Properties * -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "❌ User not found: $sam" -ForegroundColor Red
        return
    }

    # ------------------------------------------------
    # CAPTURE OLD VALUES
    # ------------------------------------------------
    $old = @{
        Title       = $user.Title
        Department  = $user.Department
        Mobile      = $user.mobile
        OfficePhone = $user.telephoneNumber
        Office      = $user.physicalDeliveryOfficeName
        Country     = $user.co
        Manager     = $user.Manager
        Enabled     = $user.Enabled
    }

    # ------------------------------------------------
    # RESOLVE MANAGER DN
    # ------------------------------------------------
    $managerDN = $null
    if ($_.ManagerSamAccountName -and $_.ManagerSamAccountName.Trim() -ne "") {
        $mgr = Get-ADUser $_.ManagerSamAccountName -ErrorAction SilentlyContinue
        if ($mgr -and $mgr.DistinguishedName -ne $user.DistinguishedName) {
            $managerDN = $mgr.DistinguishedName
        }
    }

    # ------------------------------------------------
    # UPDATE ATTRIBUTES (ALL USERS)
    # ------------------------------------------------
    try {
        Set-ADUser $sam `
            -Title $_.JobTitle `
            -Department $_.Department `
            -OfficePhone $_.OfficePhone `
            -MobilePhone $_.Mobile `
            -Office $_.OfficeLocation `
            -Manager $managerDN `
            -Replace @{ co = $_.Country }
    }
    catch {
        Write-Host "❌ Attribute update failed: $sam - $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # ------------------------------------------------
    # READ UPDATED VALUES
    # ------------------------------------------------
    $newUser = Get-ADUser $sam -Properties *

    # ------------------------------------------------
    # COMPARE CHANGES FOR REPORT
    # ------------------------------------------------
    $map = @{
        Title       = @($old.Title,      $newUser.Title)
        Department  = @($old.Department, $newUser.Department)
        Mobile      = @($old.Mobile,     $newUser.mobile)
        OfficePhone = @($old.OfficePhone,$newUser.telephoneNumber)
        Office      = @($old.Office,     $newUser.physicalDeliveryOfficeName)
        Country     = @($old.Country,    $newUser.co)
        Manager     = @($old.Manager,    $newUser.Manager)
    }

    foreach ($attr in $map.Keys) {
        if ($map[$attr][0] -ne $map[$attr][1]) {
            $report += [PSCustomObject]@{
                SamAccountName = $sam
                Action         = "Update"
                Attribute      = $attr
                OldValue       = $map[$attr][0]
                NewValue       = $map[$attr][1]
            }
        }
    }

    # ------------------------------------------------
    # NORMALIZE STATUS
    # ------------------------------------------------
    $statusRaw = $_.Status
    $status = if ([string]::IsNullOrWhiteSpace($statusRaw)) {
        "notactive"
    }
    else {
        $statusRaw.Trim().ToLower()
    }

    Write-Host "DEBUG → User: $sam | Status: '$statusRaw'" -ForegroundColor Magenta

    # ------------------------------------------------
    # ENABLE / DISABLE LOGIC
    # ------------------------------------------------
    if ($status -eq "active") {

        if (-not $user.Enabled) {
            Enable-ADAccount $sam

            $report += [PSCustomObject]@{
                SamAccountName = $sam
                Action         = "EnableAccount"
                Attribute      = "AccountStatus"
                OldValue       = "Disabled"
                NewValue       = "Enabled"
            }

            Write-Host "✅ Account ENABLED: $sam" -ForegroundColor Green
        }
        else {
            Write-Host "ℹ Account already ACTIVE: $sam" -ForegroundColor Cyan
        }

    }
    else {

        if ($user.Enabled) {
            Disable-ADAccount $sam

            $report += [PSCustomObject]@{
                SamAccountName = $sam
                Action         = "DisableAccount"
                Attribute      = "AccountStatus"
                OldValue       = "Enabled"
                NewValue       = "Disabled"
            }

            Write-Host "⛔ Account DISABLED: $sam (Status: $statusRaw)" -ForegroundColor Yellow
        }
        else {
            Write-Host "ℹ Account already DISABLED: $sam" -ForegroundColor DarkYellow
        }
    }
}

# ------------------------------------------------
# EXPORT REPORT
# ------------------------------------------------
$report | Export-Csv $reportPath -NoTypeInformation

Write-Host "`n📄 Change report generated at: $reportPath" -ForegroundColor Cyan
