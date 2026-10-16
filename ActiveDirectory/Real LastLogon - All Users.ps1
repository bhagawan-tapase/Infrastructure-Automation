#requires -Version 5.1
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Generates an optimized Active Directory enabled-user report.

.DESCRIPTION
    - Retrieves enabled users from one writable domain controller.
    - Queries enabled users in bulk from every writable domain controller.
    - Calculates the most recent non-replicated lastLogon value.
    - Resolves each unique manager only once.
    - Formats all dates as DD/MM/YYYY.
    - Exports the final report to CSV.
    - Identifies whether exact lastLogon coverage is complete or partial.

.NOTES
    PowerShell 5.1 compatible.

    Important:
    - lastLogon is not replicated between domain controllers.
      When exact last logon is enabled, this script queries every
      writable domain controller and selects the highest value.

    - badPwdCount and logonCount are maintained separately by each
      domain controller. Their values are collected from the primary
      query DC and are labeled accordingly.

.EXAMPLE
    .\Get-ADEnabledUserReport.ps1

.EXAMPLE
    .\Get-ADEnabledUserReport.ps1 `
        -OutputFile "D:\Reports\AD_User_Report.csv"

.EXAMPLE
    .\Get-ADEnabledUserReport.ps1 `
        -SearchBase "OU=Users,DC=contoso,DC=com" `
        -OutputFile "D:\Reports\AD_User_Report.csv"

.EXAMPLE
    .\Get-ADEnabledUserReport.ps1 `
        -GetExactLastLogon $false
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFile = "D:\AD_User_Report.csv",

    # Optional OU restriction.
    # Example:
    # "OU=Users,DC=contoso,DC=com"
    [Parameter()]
    [string]$SearchBase,

    # Set to $false to use replicated LastLogonTimestamp.
    [Parameter()]
    [bool]$GetExactLastLogon = $true
)

Import-Module ActiveDirectory -ErrorAction Stop

$ErrorActionPreference = "Stop"

# All report dates use DD/MM/YYYY.
$DateFormat = "dd/MM/yyyy"

# ============================================================
# Helper functions
# ============================================================

function Convert-ADDate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowNull()]
        [object]$Date,

        [Parameter()]
        [string]$NullValue = ""
    )

    if ($null -eq $Date) {
        return $NullValue
    }

    try {
        return ([datetime]$Date).ToString($DateFormat)
    }
    catch {
        return $NullValue
    }
}

function Convert-ADFileTime {
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowNull()]
        [object]$FileTime,

        [Parameter()]
        [string]$NullValue = "Never"
    )

    if ($null -eq $FileTime) {
        return $NullValue
    }

    try {
        $FileTimeValue = [int64]$FileTime

        if ($FileTimeValue -le 0) {
            return $NullValue
        }

        return (
            [datetime]::FromFileTime($FileTimeValue)
        ).ToString($DateFormat)
    }
    catch {
        return $NullValue
    }
}

# ============================================================
# Validate and prepare output directory
# ============================================================

$OutputDirectory = Split-Path -Path $OutputFile -Parent

if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        Write-Host (
            "Creating output directory: {0}" -f
            $OutputDirectory
        ) -ForegroundColor Yellow

        New-Item `
            -Path $OutputDirectory `
            -ItemType Directory `
            -Force `
            -ErrorAction Stop |
            Out-Null
    }
}

# ============================================================
# Discover writable domain controllers
# ============================================================

Write-Host "`nDiscovering writable Domain Controllers..." `
    -ForegroundColor Cyan

$DomainControllers = @(
    Get-ADDomainController `
        -Filter * `
        -ErrorAction Stop |
        Where-Object {
            -not $_.IsReadOnly -and $_.Enabled
        } |
        Sort-Object HostName
)

if ($DomainControllers.Count -eq 0) {
    throw "No writable Domain Controllers were found."
}

Write-Host (
    "Writable DCs found: {0}" -f
    $DomainControllers.Count
) -ForegroundColor Green

foreach ($DC in $DomainControllers) {
    Write-Host (
        "  {0}" -f
        $DC.HostName
    ) -ForegroundColor Gray
}

# Use the first writable DC for replicated account properties.
$PrimaryDC = $DomainControllers[0].HostName

Write-Host (
    "Primary query DC: {0}" -f
    $PrimaryDC
) -ForegroundColor Cyan

# ============================================================
# Validate optional SearchBase against the primary DC
# ============================================================

if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    Write-Host (
        "`nValidating SearchBase: {0}" -f
        $SearchBase
    ) -ForegroundColor Cyan

    try {
        Get-ADObject `
            -Identity $SearchBase `
            -Server $PrimaryDC `
            -ErrorAction Stop |
            Out-Null
    }
    catch {
        throw (
            "The specified SearchBase could not be found or accessed: " +
            "'$SearchBase'. Error: $($_.Exception.Message)"
        )
    }
}

# ============================================================
# Properties required for the main report
# ============================================================

$UserProperties = @(
    "DisplayName"
    "GivenName"
    "Surname"
    "UserPrincipalName"
    "mail"
    "Enabled"
    "Created"
    "Modified"
    "PasswordLastSet"
    "PasswordNeverExpires"
    "PasswordExpired"
    "CannotChangePassword"
    "LockedOut"
    "AccountExpirationDate"
    "LastBadPasswordAttempt"
    "badPwdCount"
    "logonCount"
    "Department"
    "Title"
    "Company"
    "Manager"
    "Office"
    "OfficePhone"
    "MobilePhone"
    "Description"
    "LastLogonTimestamp"
)

# ============================================================
# Retrieve enabled users
# ============================================================

$BaseUserParameters = @{
    Filter         = { Enabled -eq $true }
    Server         = $PrimaryDC
    Properties     = $UserProperties
    ResultPageSize = 1000
    ResultSetSize  = $null
    ErrorAction    = "Stop"
}

if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    $BaseUserParameters["SearchBase"] = $SearchBase
    $BaseUserParameters["SearchScope"] = "Subtree"
}

Write-Host (
    "`nRetrieving enabled users from {0}..." -f
    $PrimaryDC
) -ForegroundColor Cyan

$Users = @(
    Get-ADUser @BaseUserParameters
)

$TotalUsers = $Users.Count

Write-Host (
    "Enabled users found: {0}" -f
    $TotalUsers
) -ForegroundColor Green

if ($TotalUsers -eq 0) {
    throw "No enabled users were found."
}

# ============================================================
# Build manager lookup cache
#
# Each unique manager is queried only once.
# ============================================================

Write-Host "`nBuilding manager lookup cache..." `
    -ForegroundColor Cyan

$ManagerCache = @{}

$ManagerDNs = @(
    $Users |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.Manager)
        } |
        Select-Object -ExpandProperty Manager -Unique
)

$ManagerCounter = 0
$TotalManagers = $ManagerDNs.Count

foreach ($ManagerDN in $ManagerDNs) {
    $ManagerCounter++

    if ($TotalManagers -gt 0) {
        Write-Progress `
            -Id 1 `
            -Activity "Building manager lookup cache" `
            -Status (
                "{0} of {1}" -f
                $ManagerCounter,
                $TotalManagers
            ) `
            -PercentComplete (
                ($ManagerCounter / $TotalManagers) * 100
            )
    }

    try {
        $ManagerObject = Get-ADUser `
            -Identity $ManagerDN `
            -Server $PrimaryDC `
            -Properties DisplayName `
            -ErrorAction Stop

        if (
            [string]::IsNullOrWhiteSpace(
                $ManagerObject.DisplayName
            )
        ) {
            $ManagerCache[$ManagerDN] =
                $ManagerObject.SamAccountName
        }
        else {
            $ManagerCache[$ManagerDN] =
                $ManagerObject.DisplayName
        }
    }
    catch {
        # Retain the manager DN if the manager cannot be resolved.
        $ManagerCache[$ManagerDN] = $ManagerDN
    }
}

Write-Progress `
    -Id 1 `
    -Activity "Building manager lookup cache" `
    -Completed

Write-Host (
    "Unique managers cached: {0}" -f
    $ManagerCache.Count
) -ForegroundColor Green

# ============================================================
# Build exact lastLogon lookup
#
# The script performs one bulk query against each writable DC
# instead of querying every user individually against every DC.
# ============================================================

$LastLogonLookup = @{}

$FailedDomainControllers = New-Object `
    System.Collections.Generic.List[string]

if ($GetExactLastLogon) {
    Write-Host `
        "`nCollecting exact lastLogon from writable DCs..." `
        -ForegroundColor Cyan

    $DCCounter = 0

    foreach ($DCObject in $DomainControllers) {
        $DCCounter++
        $DCName = $DCObject.HostName

        Write-Progress `
            -Id 2 `
            -Activity "Collecting exact lastLogon information" `
            -Status (
                "Querying {0} ({1} of {2})" -f
                $DCName,
                $DCCounter,
                $DomainControllers.Count
            ) `
            -PercentComplete (
                ($DCCounter / $DomainControllers.Count) * 100
            )

        Write-Host (
            "Querying {0}..." -f
            $DCName
        ) -ForegroundColor Gray

        $DCQueryParameters = @{
            Filter         = { Enabled -eq $true }
            Server         = $DCName
            Properties     = "lastLogon"
            ResultPageSize = 1000
            ResultSetSize  = $null
            ErrorAction    = "Stop"
        }

        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $DCQueryParameters["SearchBase"] = $SearchBase
            $DCQueryParameters["SearchScope"] = "Subtree"
        }

        try {
            Get-ADUser @DCQueryParameters |
                ForEach-Object {
                    $UserKey = $_.ObjectGUID.Guid
                    $CurrentLastLogon = [int64]$_.lastLogon

                    if (
                        -not $LastLogonLookup.ContainsKey($UserKey)
                    ) {
                        $LastLogonLookup[$UserKey] =
                            [PSCustomObject]@{
                                LastLogon = [int64]0
                                DC        = $null
                            }
                    }

                    if (
                        $CurrentLastLogon -gt
                        $LastLogonLookup[$UserKey].LastLogon
                    ) {
                        $LastLogonLookup[$UserKey].LastLogon =
                            $CurrentLastLogon

                        $LastLogonLookup[$UserKey].DC =
                            $DCName
                    }
                }
        }
        catch {
            $FailedDomainControllers.Add($DCName)

            Write-Warning (
                "Unable to query {0}. Error: {1}" -f
                $DCName,
                $_.Exception.Message
            )
        }
    }

    Write-Progress `
        -Id 2 `
        -Activity "Collecting exact lastLogon information" `
        -Completed

    Write-Host (
        "Exact lastLogon entries collected: {0}" -f
        $LastLogonLookup.Count
    ) -ForegroundColor Green
}
else {
    Write-Warning (
        "Exact lastLogon lookup is disabled. " +
        "Replicated LastLogonTimestamp will be used."
    )
}

# ============================================================
# Determine lastLogon coverage status
# ============================================================

if ($GetExactLastLogon) {
    if ($FailedDomainControllers.Count -eq 0) {
        $ExactLastLogonCoverage =
            "Complete - all writable DCs queried"
    }
    else {
        $ExactLastLogonCoverage =
            "Partial - one or more writable DCs unavailable"
    }
}
else {
    $ExactLastLogonCoverage =
        "Not applicable - using lastLogonTimestamp"
}

# ============================================================
# Generate report
# ============================================================

Write-Host "`nGenerating report objects..." `
    -ForegroundColor Cyan

$Report = New-Object System.Collections.Generic.List[object]

$Counter = 0

foreach ($User in $Users) {
    $Counter++

    # Refresh progress periodically to reduce console overhead.
    if (
        ($Counter -eq 1) -or
        (($Counter % 100) -eq 0) -or
        ($Counter -eq $TotalUsers)
    ) {
        Write-Progress `
            -Id 3 `
            -Activity "Generating Active Directory User Report" `
            -Status (
                "Processing {0} ({1} of {2})" -f
                $User.SamAccountName,
                $Counter,
                $TotalUsers
            ) `
            -PercentComplete (
                ($Counter / $TotalUsers) * 100
            )
    }

    # --------------------------------------------------------
    # Calculate last logon
    # --------------------------------------------------------

    $UserKey = $User.ObjectGUID.Guid
    $RealLastLogon = "Never"
    $LastLogonDC = $null

    if ($GetExactLastLogon) {
        if ($FailedDomainControllers.Count -eq 0) {
            $LastLogonSource = "lastLogon - all writable DCs"
        }
        else {
            $LastLogonSource = "lastLogon - partial DC coverage"
        }

        if ($LastLogonLookup.ContainsKey($UserKey)) {
            $LastLogonValue = [int64]$LastLogonLookup[$UserKey].LastLogon

            $RealLastLogon = Convert-ADFileTime `
                -FileTime $LastLogonValue `
                -NullValue "Never"

            $LastLogonDC = $LastLogonLookup[$UserKey].DC
        }
    }
    else {
        $LastLogonSource = "lastLogonTimestamp"

        if ($null -ne $User.LastLogonTimestamp) {
            $RealLastLogon = Convert-ADFileTime `
                -FileTime $User.LastLogonTimestamp `
                -NullValue "Never"
        }
    }

    # --------------------------------------------------------
    # Resolve manager
    # --------------------------------------------------------

    $ManagerName = $null

    if (-not [string]::IsNullOrWhiteSpace($User.Manager)) {
        if ($ManagerCache.ContainsKey($User.Manager)) {
            $ManagerName = $ManagerCache[$User.Manager]
        }
        else {
            $ManagerName = $User.Manager
        }
    }

    # --------------------------------------------------------
    # Create output object
    # --------------------------------------------------------

    $ReportObject = [PSCustomObject][ordered]@{
        SamAccountName              = $User.SamAccountName
        DisplayName                 = $User.DisplayName
        GivenName                   = $User.GivenName
        Surname                     = $User.Surname
        UserPrincipalName           = $User.UserPrincipalName
        EmailAddress                = $User.mail
        Enabled                     = $User.Enabled
        LockedOut                   = $User.LockedOut

        RealLastLogon               = $RealLastLogon
        LastLogonDC                 = $LastLogonDC
        LastLogonSource             = $LastLogonSource
        LastLogonCoverage           = $ExactLastLogonCoverage

        PasswordLastSet             = Convert-ADDate `
            -Date $User.PasswordLastSet `
            -NullValue "Never"

        PasswordNeverExpires        = $User.PasswordNeverExpires
        PasswordExpired             = $User.PasswordExpired
        CannotChangePassword        = $User.CannotChangePassword

        LastBadPasswordAttempt      = Convert-ADDate `
            -Date $User.LastBadPasswordAttempt `
            -NullValue ""

        BadPasswordCountOnPrimaryDC = $User.badPwdCount
        LogonCountOnPrimaryDC       = $User.logonCount
        PrimaryQueryDC              = $PrimaryDC

        AccountExpirationDate       = Convert-ADDate `
            -Date $User.AccountExpirationDate `
            -NullValue "Never"

        Created                     = Convert-ADDate `
            -Date $User.Created `
            -NullValue ""

        Modified                    = Convert-ADDate `
            -Date $User.Modified `
            -NullValue ""

        Department                  = $User.Department
        Title                       = $User.Title
        Company                     = $User.Company
        Manager                     = $ManagerName
        Office                      = $User.Office
        OfficePhone                 = $User.OfficePhone
        MobilePhone                 = $User.MobilePhone
        Description                 = $User.Description
        DistinguishedName           = $User.DistinguishedName
    }

    $Report.Add($ReportObject)
}

Write-Progress `
    -Id 3 `
    -Activity "Generating Active Directory User Report" `
    -Completed

# ============================================================
# Export CSV
# ============================================================

Write-Host "`nSorting and exporting report..." `
    -ForegroundColor Cyan

try {
    $Report |
        Sort-Object DisplayName, SamAccountName |
        Export-Csv `
            -Path $OutputFile `
            -NoTypeInformation `
            -Encoding UTF8 `
            -Force `
            -ErrorAction Stop
}
catch {
    throw (
        "Unable to export the report to '{0}'. Error: {1}" -f
        $OutputFile,
        $_.Exception.Message
    )
}

# ============================================================
# Final summary
# ============================================================

Write-Host "`nReport successfully exported." `
    -ForegroundColor Green

Write-Host (
    "Output file: {0}" -f
    $OutputFile
) -ForegroundColor Green

Write-Host (
    "Users exported: {0}" -f
    $Report.Count
) -ForegroundColor Green

Write-Host (
    "Primary query DC: {0}" -f
    $PrimaryDC
) -ForegroundColor Green

Write-Host (
    "Date format: DD/MM/YYYY"
) -ForegroundColor Green

if ($GetExactLastLogon) {
    if ($FailedDomainControllers.Count -gt 0) {
        Write-Warning (
            "Exact lastLogon data may be incomplete because the " +
            "following Domain Controllers could not be queried:"
        )

        foreach ($FailedDC in $FailedDomainControllers) {
            Write-Warning (
                "  {0}" -f
                $FailedDC
            )
        }
    }
    else {
        Write-Host (
            "All writable Domain Controllers were queried successfully."
        ) -ForegroundColor Green
    }
}
else {
    Write-Host (
        "Replicated LastLogonTimestamp was used instead of " +
        "exact lastLogon."
    ) -ForegroundColor Yellow
}

Write-Host "`nCompleted." -ForegroundColor Cyan
