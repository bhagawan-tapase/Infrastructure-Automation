Import-Module ActiveDirectory -ErrorAction Stop

# ============================================================
# Configuration
# ============================================================

$ExportPath = 'D:\AD_Computers_Report-Latest.csv'
$DateFormat = 'dd/MM/yyyy'

# ============================================================
# Functions
# ============================================================

function Format-ADDate {
    param (
        [AllowNull()]
        $DateValue
    )

    if ($null -eq $DateValue) {
        return $null
    }

    try {
        return ([datetime]$DateValue).ToString('dd/MM/yyyy')
    }
    catch {
        return $null
    }
}

function Convert-ADFileTime {
    param (
        [AllowNull()]
        [object]$FileTimeValue
    )

    if ($null -eq $FileTimeValue) {
        return $null
    }

    try {
        $FileTime = [Int64]$FileTimeValue

        if ($FileTime -le 0) {
            return $null
        }

        $ConvertedDate = [System.DateTime]::FromFileTimeUtc($FileTime)

        return $ConvertedDate.ToLocalTime().ToString($DateFormat)
    }
    catch {
        Write-Warning "FILETIME conversion failed for value '$FileTimeValue'. Error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# Validate export location
# ============================================================

$ExportFolder = Split-Path -Path $ExportPath -Parent

if (-not (Test-Path -Path $ExportFolder)) {
    New-Item -Path $ExportFolder -ItemType Directory -Force |
        Out-Null
}

# ============================================================
# Get all domain controllers
# ============================================================

$DomainControllers = @(
    Get-ADDomainController -Filter * |
        Sort-Object HostName
)

if ($DomainControllers.Count -eq 0) {
    throw 'No domain controllers were found.'
}

Write-Host ''
Write-Host "Domain controllers found: $($DomainControllers.Count)" -ForegroundColor Cyan

foreach ($DC in $DomainControllers) {
    Write-Host "  $($DC.HostName)"
}

# ============================================================
# Define computer properties
# ============================================================

$ComputerProperties = @(
    'CanonicalName'
    'CN'
    'Created'
    'createTimeStamp'
    'Description'
    'DisplayName'
    'DNSHostName'
    'Enabled'
    'LastLogonDate'
    'lastLogonTimestamp'
    'ManagedBy'
    'Modified'
    'modifyTimeStamp'
    'OperatingSystem'
    'OperatingSystemVersion'
    'whenChanged'
    'PasswordLastSet'
    'whenCreated'
)

# ============================================================
# Retrieve main computer properties from the first DC
# ============================================================

$ReferenceDC = $DomainControllers[0].HostName

Write-Host ''
Write-Host "Retrieving computer accounts from $ReferenceDC..." -ForegroundColor Cyan

$ComputerQuery = @{
    Server      = $ReferenceDC
    Filter      = '*'
    Properties  = $ComputerProperties
    ErrorAction = 'Stop'
}

$Computers = @(
    Get-ADComputer @ComputerQuery
)

Write-Host "Computer accounts found: $($Computers.Count)" -ForegroundColor Green

# ============================================================
# Initialize the real lastLogon lookup table
# ============================================================

$LastLogonMap = @{}

foreach ($Computer in $Computers) {
    $ComputerKey = $Computer.ObjectGUID.ToString()

    $LastLogonMap[$ComputerKey] = @{
        LastLogonValue   = [int64]0
        DomainController = $null
    }
}

$SuccessfulDomainControllers = @()
$FailedDomainControllers = @()

# ============================================================
# Query lastLogon from every domain controller
# ============================================================

for ($Index = 0; $Index -lt $DomainControllers.Count; $Index++) {
    $DC = $DomainControllers[$Index]

    $PercentComplete = (
        (($Index + 1) / $DomainControllers.Count) * 100
    )

    Write-Progress `
        -Activity 'Checking lastLogon on all domain controllers' `
        -Status "Querying $($DC.HostName)" `
        -PercentComplete $PercentComplete

    Write-Host ''
    Write-Host "Querying lastLogon from $($DC.HostName)..." -ForegroundColor Yellow

    try {
        $DCQuery = @{
            Server      = $DC.HostName
            Filter      = '*'
            Properties  = 'lastLogon'
            ErrorAction = 'Stop'
        }

        $DCComputers = @(
            Get-ADComputer @DCQuery
        )

        foreach ($DCComputer in $DCComputers) {
            $ComputerKey = $DCComputer.ObjectGUID.ToString()
            $CurrentLastLogon = [int64]$DCComputer.lastLogon

            if ($LastLogonMap.ContainsKey($ComputerKey)) {
                $SavedLastLogon = [int64]$LastLogonMap[$ComputerKey].LastLogonValue

                if ($CurrentLastLogon -gt $SavedLastLogon) {
                    $LastLogonMap[$ComputerKey].LastLogonValue = $CurrentLastLogon
                    $LastLogonMap[$ComputerKey].DomainController = $DC.HostName
                }
            }
        }

        $SuccessfulDomainControllers += $DC.HostName

        Write-Host "Successfully queried $($DC.HostName)." -ForegroundColor Green
    }
    catch {
        $FailedDomainControllers += $DC.HostName

        Write-Warning (
            "Failed to query {0}. Error: {1}" -f
            $DC.HostName,
            $_.Exception.Message
        )
    }
}

Write-Progress `
    -Activity 'Checking lastLogon on all domain controllers' `
    -Completed

# ============================================================
# Build final report
# ============================================================

Write-Host ''
Write-Host 'Building the final report...' -ForegroundColor Cyan

$Results = foreach ($Computer in $Computers) {
    $ComputerKey = $Computer.ObjectGUID.ToString()

    $RealLastLogonValue = [int64]0
    $RealLastLogonDC = $null

    if ($LastLogonMap.ContainsKey($ComputerKey)) {
        $RealLastLogonValue = [int64]$LastLogonMap[$ComputerKey].LastLogonValue
        $RealLastLogonDC = $LastLogonMap[$ComputerKey].DomainController
    }

    [PSCustomObject][ordered]@{
        CanonicalName               = $Computer.CanonicalName
        CN                          = $Computer.CN
        Created                     = Format-ADDate $Computer.Created
        createTimeStamp             = Format-ADDate $Computer.createTimeStamp
        Description                 = $Computer.Description
        DisplayName                 = $Computer.DisplayName
        DistinguishedName           = $Computer.DistinguishedName
        DNSHostName                 = $Computer.DNSHostName
        Enabled                     = $Computer.Enabled
        lastLogon                   = Convert-ADFileTime $RealLastLogonValue
        lastLogonDomainController   = $RealLastLogonDC
        LastLogonDate               = Format-ADDate $Computer.LastLogonDate
        RawLastLogon                = $RealLastLogonValue
        RawLastLogonTimestamp       = $Computer.lastLogonTimestamp
        lastLogonTimestamp          = Convert-ADFileTime $Computer.lastLogonTimestamp
  
        ManagedBy                   = $Computer.ManagedBy
        Modified                    = Format-ADDate $Computer.Modified
        modifyTimeStamp             = Format-ADDate $Computer.modifyTimeStamp
        Name                        = $Computer.Name
        OperatingSystem             = $Computer.OperatingSystem
        OperatingSystemVersion      = $Computer.OperatingSystemVersion
        SamAccountName              = $Computer.SamAccountName
        whenChanged                 = Format-ADDate $Computer.whenChanged
        PasswordLastSet = Format-ADDate $Computer.PasswordLastSet
        whenCreated                 = Format-ADDate $Computer.whenCreated
    }
}

# ============================================================
# Export report
# ============================================================

$Results |
    Sort-Object Name |
    Export-Csv `
        -Path $ExportPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# Display completion status
# ============================================================

Write-Host ''
Write-Host "Report exported successfully: $ExportPath" -ForegroundColor Green
Write-Host "Total computers exported: $($Results.Count)" -ForegroundColor Green
Write-Host "DCs successfully queried: $($SuccessfulDomainControllers.Count)" -ForegroundColor Green

if ($FailedDomainControllers.Count -eq 0) {
    Write-Host ''
    Write-Host 'All domain controllers were queried successfully.' -ForegroundColor Green
    Write-Host 'The lastLogon column contains the highest value found across all DCs.' -ForegroundColor Green
}
else {
    Write-Host ''
    Write-Warning 'The following domain controllers could not be queried:'

    foreach ($FailedDC in $FailedDomainControllers) {
        Write-Warning "  $FailedDC"
    }

    Write-Warning 'The lastLogon result may not be fully accurate because one or more DCs were unavailable.'
}
