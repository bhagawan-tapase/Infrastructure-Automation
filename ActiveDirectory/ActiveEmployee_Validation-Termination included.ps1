<#
Script Name : AD_Employee_Validation_and_Lifecycle_Management.ps1

Description :
This script automates Active Directory employee validation and lifecycle
management by comparing user information from a CSV source against existing
AD records. It updates user attributes such as Job Title, Department,
Mobile Number, Office Phone, Office Location, Manager, and Country,
disables accounts for non-active employees, and generates a detailed
audit report of all changes, actions, and processing results.

Key Features :
- Validates Active Directory user accounts against CSV data
- Updates user attributes when discrepancies are identified
- Updates manager relationships and country information
- Disables accounts marked as inactive or non-active
- Tracks all changes and exceptions for audit purposes
- Generates timestamped CSV reports for compliance and reporting

Author  : Bhagawan Tapase
Version : 1.0
#>

Import-Module ActiveDirectory

# --------------------------------------------------
# PATH CONFIGURATION
# --------------------------------------------------
$csvPath = "D:\ActiveEmployees_Validation.csv"

$currentDate  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFolder = "D:\Report_Employees_Validation"
$reportPath   = "$reportFolder\AD_Change_Report_$currentDate.csv"

if (-not (Test-Path $reportFolder)) {
    New-Item -ItemType Directory -Path $reportFolder | Out-Null
}

# --------------------------------------------------
# REPORT HOLDER
# --------------------------------------------------
$report = @()

# --------------------------------------------------
# READ CSV
# --------------------------------------------------
$users = Import-Csv $csvPath

# --------------------------------------------------
# PROCESS USERS (SAFE FOREACH LOOP)
# --------------------------------------------------
foreach ($row in $users) {

    $sam        = $row.SamAccountName
    $changeMade = $false

    Write-Host "`n➡ Processing user: $sam" -ForegroundColor Cyan

    try {
        # --------------------------------------------------
        # GET USER
        # --------------------------------------------------
        $user = Get-ADUser $sam -Properties `
            Title,Department,Mobile,telephoneNumber,
            physicalDeliveryOfficeName,Manager,Enabled,c `
            -ErrorAction Stop

        # --------------------------------------------------
        # CAPTURE OLD VALUES
        # --------------------------------------------------
        $old = @{
            Title       = $user.Title
            Department  = $user.Department
            Mobile      = $user.Mobile
            OfficePhone = $user.telephoneNumber
            Office      = $user.physicalDeliveryOfficeName
            Country     = $user.c
            Manager     = $user.Manager
            Enabled     = $user.Enabled
        }

        # --------------------------------------------------
        # RESOLVE MANAGER DN
        # --------------------------------------------------
        $managerDN = $null
        if ($row.ManagerSamAccountName) {
            $mgr = Get-ADUser $row.ManagerSamAccountName -ErrorAction Stop
            if ($mgr.DistinguishedName -ne $user.DistinguishedName) {
                $managerDN = $mgr.DistinguishedName
            }
        }

        # --------------------------------------------------
        # ATTRIBUTE UPDATES
        # --------------------------------------------------
        $setParams = @{}
        $changes   = @()

        if ($row.JobTitle -and $row.JobTitle -ne $old.Title) {
            $setParams.Title = $row.JobTitle
            $changes += @{ A="Title"; O=$old.Title; N=$row.JobTitle }
        }

        if ($row.Department -and $row.Department -ne $old.Department) {
            $setParams.Department = $row.Department
            $changes += @{ A="Department"; O=$old.Department; N=$row.Department }
        }

        if ($row.Mobile -and $row.Mobile -ne $old.Mobile) {
            $setParams.Mobile = $row.Mobile
            $changes += @{ A="Mobile"; O=$old.Mobile; N=$row.Mobile }
        }

        if ($row.OfficePhone -and $row.OfficePhone -ne $old.OfficePhone) {
            $setParams.Replace = @{ telephoneNumber = $row.OfficePhone }
            $changes += @{ A="OfficePhone"; O=$old.OfficePhone; N=$row.OfficePhone }
        }

        if ($row.OfficeLocation -and $row.OfficeLocation -ne $old.Office) {
            $setParams.Office = $row.OfficeLocation
            $changes += @{ A="Office"; O=$old.Office; N=$row.OfficeLocation }
        }

        if ($managerDN -and $managerDN -ne $old.Manager) {
            $setParams.Manager = $managerDN
            $changes += @{ A="Manager"; O=$old.Manager; N=$managerDN }
        }

        if ($setParams.Count -gt 0) {
            Set-ADUser $sam @setParams -ErrorAction Stop
            $changeMade = $true

            foreach ($c in $changes) {
                $report += [PSCustomObject]@{
                    SamAccountName = $sam
                    Action         = "Update"
                    Attribute      = $c.A
                    OldValue       = $c.O
                    NewValue       = $c.N
                }
            }

            Write-Host "✏ Attributes updated" -ForegroundColor Green
        }

        # --------------------------------------------------
        # COUNTRY UPDATE
        # --------------------------------------------------
        if ($row.Country) {
            $csvCountry = $row.Country.Trim().ToUpper()
            if ($csvCountry -ne $old.Country) {
                Set-ADUser $sam -Replace @{ c = $csvCountry } -ErrorAction Stop
                $changeMade = $true

                $report += [PSCustomObject]@{
                    SamAccountName = $sam
                    Action         = "Update"
                    Attribute      = "Country"
                    OldValue       = $old.Country
                    NewValue       = $csvCountry
                }

                Write-Host "🌍 Country updated" -ForegroundColor Green
            }
        }

        # --------------------------------------------------
        # ACCOUNT STATUS HANDLING (FIXED SYNTAX)
        # --------------------------------------------------
        $status = if ([string]::IsNullOrWhiteSpace($row.Status)) {
            "notactive"
        } else {
            $row.Status.Trim().ToLower()
        }

        if ($status -ne "active" -and $old.Enabled) {
            Disable-ADAccount $sam -ErrorAction Stop
            $changeMade = $true

            $report += [PSCustomObject]@{
                SamAccountName = $sam
                Action         = "DisableAccount"
                Attribute      = "AccountStatus"
                OldValue       = "Enabled"
                NewValue       = "Disabled"
            }

            Write-Host "⛔ Account disabled" -ForegroundColor Yellow
        }

        # --------------------------------------------------
        # NO CHANGE
        # --------------------------------------------------
        if (-not $changeMade) {
            $report += [PSCustomObject]@{
                SamAccountName = $sam
                Action         = "NoChange"
                Attribute      = "-"
                OldValue       = "-"
                NewValue       = "-"
            }

            Write-Host "ℹ No changes required" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "❌ Error processing $sam" -ForegroundColor Red

        $report += [PSCustomObject]@{
            SamAccountName = $sam
            Action         = "Error"
            Attribute      = "Processing"
            OldValue       = "-"
            NewValue       = $_.Exception.Message
        }

        continue
    }
}

# --------------------------------------------------
# EXPORT REPORT
# --------------------------------------------------
$report | Export-Csv $reportPath -NoTypeInformation

Write-Host "`n📄 AD Change report generated at:" -ForegroundColor Cyan
Write-Host $reportPath -ForegroundColor Cyan
