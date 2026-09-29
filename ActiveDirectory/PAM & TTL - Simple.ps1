<#
.SYNOPSIS
    Grants temporary Active Directory group membership using TTL.

.DESCRIPTION
    This script grants a user temporary membership in an approved
    Active Directory security group using Time-To-Live membership.

    Only an operator who is a member of the Domain Admins group
    is authorized to run this script.

    The script performs the following operations:

    - Validates the Active Directory PowerShell module
    - Validates Windows Server 2016 Forest Functional Level
    - Validates the PAM optional feature
    - Authorizes only Domain Admin operators
    - Validates the ticket number and business reason
    - Validates the target user and group
    - Prevents protected and service accounts
    - Restricts assignments to approved groups
    - Prevents overwriting existing direct memberships
    - Grants temporary TTL membership
    - Verifies that TTL was assigned
    - Records successful and failed operations in CSV
    - Supports WhatIf and Confirm

.PARAMETER User
    The target user's sAMAccountName, distinguished name, SID or GUID.

.PARAMETER Group
    The approved Active Directory group receiving temporary membership.

.PARAMETER TicketNumber
    Approved request, incident or change number.

.PARAMETER Reason
    Business justification for temporary privileged access.

.PARAMETER Days
    Duration in days. Valid range is 1 through 30.

.PARAMETER Hours
    Duration in hours. Valid range is 1 through 720.

.PARAMETER Server
    Optional writable Domain Controller used for all AD operations.

.EXAMPLE
    .\AD_TTL_Access_Manager.ps1 `
        -User "btapase" `
        -Group "Domain Admins" `
        -Days 10 `
        -TicketNumber "CHG1234567" `
        -Reason "Approved Active Directory migration activity"

.EXAMPLE
    .\AD_TTL_Access_Manager.ps1 `
        -User "btapase" `
        -Group "Schema Admins" `
        -Hours 4 `
        -TicketNumber "CHG1234567" `
        -Reason "Approved schema extension activity"

.EXAMPLE
    .\AD_TTL_Access_Manager.ps1 `
        -User "btapase" `
        -Group "Domain Admins" `
        -Hours 1 `
        -TicketNumber "CHG1234567" `
        -Reason "Testing approved TTL membership process" `
        -WhatIf

.NOTES
    Script Name : AD_TTL_Access_Manager.ps1
    Version     : 2.1.0
    Author      : Bhagawan Tapase

    Important:
    The script grants temporary group membership only.
    It does not disable the user when TTL expires.
#>

[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = 'High',
    DefaultParameterSetName = 'Days'
)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$User,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Group,

    [Parameter(Mandatory = $true)]
    [string]$TicketNumber,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    #[ValidateLength(10, 500)]
    [string]$Reason,

    [Parameter(
        Mandatory = $false,
        ParameterSetName = 'Days'
    )]
    [ValidateRange(1, 30)]
    [int]$Days = 1,

    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'Hours'
    )]
    [ValidateRange(1, 720)]
    [int]$Hours,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Server
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================
# Configuration
# ============================================================

$ScriptVersion = '2.1.0'

# Only these groups can receive TTL assignments.
$AllowedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Server Admins'
)

# Only members of Domain Admins may execute the script.
$AuthorizedOperatorGroup = 'Domain Admins'

# Accounts that must never be processed.
$ProtectedSamAccountNames = @(
    'Administrator',
    'krbtgt',
    'Guest'
)

# Service account prefixes blocked from temporary privilege assignment.
$BlockedAccountPrefixes = @(
    'svc_',
    'sa_',
    'sql_'
)

$LogFolder = 'D:\Logs\AD-TTL'
$LogPath   = Join-Path -Path $LogFolder -ChildPath 'TTL_Access_Log.csv'

# ============================================================
# Functions
# ============================================================

function Write-Status {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    Write-Host "[$($Level.ToUpper())] $Message" -ForegroundColor $Color
}

function Get-CommonADParameters {
    $Parameters = @{
        ErrorAction = 'Stop'
    }

    if ($Server) {
        $Parameters['Server'] = $Server
    }

    return $Parameters
}

function Protect-CsvValue {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $CleanValue = $Value.Trim()
    $CleanValue = $CleanValue -replace '[\r\n]+', ' '

    # Prevent spreadsheet formula injection.
    if ($CleanValue -match '^[=\+\-@]') {
        $CleanValue = "'" + $CleanValue
    }

    return $CleanValue
}

function Initialize-AuditLog {
    if (-not (Test-Path -LiteralPath $LogFolder)) {
        New-Item `
            -Path $LogFolder `
            -ItemType Directory `
            -Force `
            -ErrorAction Stop |
            Out-Null
    }
}

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Record
    )

    Initialize-AuditLog

    $Record |
    Export-Csv `
    -LiteralPath $LogPath `
    -Append `
    -NoTypeInformation `
    -Encoding UTF8 `
    -Force
}

function Test-ForestRequirement {
    $ADParameters = Get-CommonADParameters
    $Forest = Get-ADForest @ADParameters

    # Windows2016Forest has enum value 7.
    if ([int]$Forest.ForestMode -lt 7) {
        throw "Forest Functional Level must be Windows Server 2016."
    }

    return $Forest
}

function Test-PamRequirement {
    $ADParameters = Get-CommonADParameters

    $PamFeature = Get-ADOptionalFeature `
        -Identity 'Privileged Access Management Feature' `
        @ADParameters

    if (
        -not $PamFeature.EnabledScopes -or
        $PamFeature.EnabledScopes.Count -eq 0
    ) {
        throw 'Privileged Access Management optional feature is not enabled.'
    }

    return $PamFeature
}

function Get-CurrentADOperator {
    $ADParameters = Get-CommonADParameters

    $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    if (-not $WindowsIdentity.User) {
        throw 'Unable to determine the current operator SID.'
    }

    $CurrentSid = $WindowsIdentity.User.Value

    try {
        $Operator = Get-ADUser `
            -Identity $CurrentSid `
            -Properties Enabled, SamAccountName, SID, DisplayName `
            @ADParameters
    }
    catch {
        throw "Current Windows account could not be resolved as an AD user. $($_.Exception.Message)"
    }

    if (-not $Operator.Enabled) {
        throw "Operator account [$($Operator.SamAccountName)] is disabled."
    }

    return $Operator
}

function Test-DomainAdminAuthorization {
    param(
        [Parameter(Mandatory = $true)]
        $Operator
    )

    $ADParameters = Get-CommonADParameters

    try {
        $DomainAdminsGroup = Get-ADGroup `
            -Identity $AuthorizedOperatorGroup `
            -Properties SID `
            @ADParameters

        $DomainAdminMembers = Get-ADGroupMember `
            -Identity $DomainAdminsGroup `
            -Recursive `
            @ADParameters

        $Authorized = $DomainAdminMembers |
            Where-Object {
                $_.SID -and $_.SID.Value -eq $Operator.SID.Value
            } |
            Select-Object -First 1

        if (-not $Authorized) {
            throw (
                "Operator [$($Operator.SamAccountName)] is not a member " +
                "of [$AuthorizedOperatorGroup]."
            )
        }

        return $true
    }
    catch {
        throw "Domain Admin authorization failed. $($_.Exception.Message)"
    }
}

function Resolve-TargetUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserIdentity
    )

    $ADParameters = Get-CommonADParameters

    try {
        $ResolvedUser = Get-ADUser `
            -Identity $UserIdentity `
            -Properties Enabled, DisplayName, SamAccountName, SID, `
                        DistinguishedName, UserPrincipalName `
            @ADParameters
    }
    catch {
        throw "User [$UserIdentity] was not found. $($_.Exception.Message)"
    }

    if (-not $ResolvedUser.Enabled) {
        throw "User [$($ResolvedUser.SamAccountName)] is disabled."
    }

    if ($ResolvedUser.SamAccountName -in $ProtectedSamAccountNames) {
        throw "Protected account [$($ResolvedUser.SamAccountName)] cannot be processed."
    }

    foreach ($Prefix in $BlockedAccountPrefixes) {
        if (
            $ResolvedUser.SamAccountName.StartsWith(
                $Prefix,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw (
                "Account [$($ResolvedUser.SamAccountName)] matches " +
                "blocked service-account prefix [$Prefix]."
            )
        }
    }

    return $ResolvedUser
}

function Resolve-TargetGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupIdentity
    )

    $ApprovedName = $AllowedGroups |
        Where-Object {
            $_ -eq $GroupIdentity
        } |
        Select-Object -First 1

    if (-not $ApprovedName) {
        throw (
            "Group [$GroupIdentity] is not approved. Approved groups: " +
            ($AllowedGroups -join ', ')
        )
    }

    $ADParameters = Get-CommonADParameters

    try {
        $ResolvedGroup = Get-ADGroup `
            -Identity $ApprovedName `
            -Properties GroupCategory, GroupScope, SID, DistinguishedName `
            @ADParameters
    }
    catch {
        throw "Group [$GroupIdentity] was not found. $($_.Exception.Message)"
    }

    if ($ResolvedGroup.GroupCategory -ne 'Security') {
        throw "Group [$($ResolvedGroup.Name)] is not a security group."
    }

    return $ResolvedGroup
}

function Test-ExistingDirectMembership {
    param(
        [Parameter(Mandatory = $true)]
        $TargetUser,

        [Parameter(Mandatory = $true)]
        $TargetGroup
    )

    $ADParameters = Get-CommonADParameters

    $ExistingMember = Get-ADGroupMember `
        -Identity $TargetGroup `
        @ADParameters |
        Where-Object {
            $_.DistinguishedName -eq $TargetUser.DistinguishedName
        } |
        Select-Object -First 1

    return [bool]$ExistingMember
}

function Get-TtlMembershipVerification {
    param(
        [Parameter(Mandatory = $true)]
        $TargetUser,

        [Parameter(Mandatory = $true)]
        $TargetGroup
    )

    $ADParameters = Get-CommonADParameters

    $GroupWithTtl = Get-ADGroup `
        -Identity $TargetGroup.DistinguishedName `
        -Properties member `
        -ShowMemberTimeToLive `
        @ADParameters

    $TtlEntry = @($GroupWithTtl.member) |
        Where-Object {
            $_ -and $_.EndsWith(
                $TargetUser.DistinguishedName,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        } |
        Select-Object -First 1

    if ($null -eq $TtlEntry) {
        return $null
    }

    $RemainingSeconds = $null
    $RemainingTime = $null

    if ($TtlEntry -match '^<TTL=(\d+)>,') {
        $RemainingSeconds = [int64]$Matches[1]
        $RemainingTime = New-TimeSpan -Seconds $RemainingSeconds
    }

    return [PSCustomObject]@{
        RawEntry         = $TtlEntry
        RemainingSeconds = $RemainingSeconds
        RemainingTime    = $RemainingTime
    }
}

# ============================================================
# Main Execution
# ============================================================

$OperationId = (New-Guid).Guid
$StartTime   = Get-Date

$Forest      = $null
$Operator    = $null
$TargetUser  = $null
$TargetGroup = $null
$TTL         = $null
$ExpiryDate  = $null
$Duration    = $null
$Verification = $null
$ChangeAttempted = $false

try {
    Write-Host ''
    Write-Host '============================================================' `
        -ForegroundColor Cyan
    Write-Host ' ACTIVE DIRECTORY TTL ACCESS MANAGER' `
        -ForegroundColor Cyan
    Write-Host '============================================================' `
        -ForegroundColor Cyan
    Write-Host ''

    Write-Status -Level Info -Message 'Checking Active Directory module.'

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw (
            'Active Directory PowerShell module is not installed. ' +
            'Install the AD DS or RSAT Active Directory tools.'
        )
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Status -Level Info -Message 'Validating Forest Functional Level.'
    $Forest = Test-ForestRequirement

    Write-Status -Level Info -Message 'Validating PAM optional feature.'
    $null = Test-PamRequirement

    Write-Status -Level Info -Message 'Resolving current operator.'
    $Operator = Get-CurrentADOperator

    Write-Status -Level Info -Message (
        "Checking Domain Admin authorization for [$($Operator.SamAccountName)]."
    )

    $null = Test-DomainAdminAuthorization -Operator $Operator

    Write-Status -Level Success -Message (
        "Operator [$($Operator.SamAccountName)] is authorized."
    )

    Write-Status -Level Info -Message "Resolving user [$User]."
    $TargetUser = Resolve-TargetUser -UserIdentity $User

    Write-Status -Level Info -Message "Resolving group [$Group]."
    $TargetGroup = Resolve-TargetGroup -GroupIdentity $Group
    $ExistingTtlMembership = Get-TtlMembershipVerification `
    -TargetUser $TargetUser `
    -TargetGroup $TargetGroup

if (
    $ExistingTtlMembership -and
    $null -ne $ExistingTtlMembership.RemainingSeconds
) {
Write-Warning (
    "User [$($TargetUser.SamAccountName)] already has active TTL membership. " +
    "Remaining TTL: $($ExistingTtlMembership.RemainingTime)"
)

$ContinueChoice = Read-Host "Replace existing TTL membership? (Y/N)"

if ($ContinueChoice -notmatch '^(Y|YES)$') {
    return
}
}
    Write-Status -Level Info -Message 'Checking existing direct membership.'

    if (
        Test-ExistingDirectMembership `
            -TargetUser $TargetUser `
            -TargetGroup $TargetGroup
    ) {
       Write-Warning (
    "User [$($TargetUser.SamAccountName)] is already a direct member of [$($TargetGroup.Name)]."
)

$ContinueChoice = Read-Host "Convert existing membership to TTL? (Y/N)"

if ($ContinueChoice -eq "Y") {

    $RemovalDescription = (
    "Remove permanent membership of user " +
    "[$($TargetUser.SamAccountName)] from group " +
    "[$($TargetGroup.Name)]"
)

if (
    -not $PSCmdlet.ShouldProcess(
        $RemovalDescription,
        'Remove permanent Active Directory group membership'
    )
) {
    return
}

Remove-ADGroupMember `
    -Identity $TargetGroup `
    -Members $TargetUser `
    -Confirm:$false `
    -ErrorAction Stop

    Start-Sleep -Seconds 5

    Write-Host "Permanent membership removed." -ForegroundColor Yellow
}
else {

    Write-Host "Operation cancelled by administrator." -ForegroundColor Yellow
    return
}
    }
    # Validate Reason

while ($true) {

    if ($Reason.Length -ge 10) {
        break
    }

    Write-Warning "Reason must be at least 10 characters."

    $Reason = Read-Host "Re-enter Reason"
}

# Ask until valid Duration Type entered

do {

    $DurationType = Read-Host "Enter Duration Type (Days/Hours)"

    if ($DurationType.ToUpper() -notin @(
        "DAY",
        "DAYS",
        "HOUR",
        "HOURS"
    )) {

        Write-Warning "Invalid selection. Please enter Days, Hours."

    }

}
until (
    $DurationType.ToUpper() -in @(
        "DAY",
        "DAYS",
        "HOUR",
        "HOURS"
    )
)

switch ($DurationType.ToUpper()) {

    "DAY" {

        $Days = Read-Host "Enter number of days"

        $TTL = New-TimeSpan -Days ([int]$Days)
        $Duration = "$Days Day(s)"
    }

    "DAYS" {

        $Days = Read-Host "Enter number of days"

        $TTL = New-TimeSpan -Days ([int]$Days)
        $Duration = "$Days Day(s)"
    }

    "HOUR" {

        $Hours = Read-Host "Enter number of hours"

        $TTL = New-TimeSpan -Hours ([int]$Hours)
        $Duration = "$Hours Hour(s)"
    }

    "HOURS" {

        $Hours = Read-Host "Enter number of hours"

        $TTL = New-TimeSpan -Hours ([int]$Hours)
        $Duration = "$Hours Hour(s)"
    }
}

    $GrantTime = Get-Date
    $ExpiryDate = $GrantTime.Add($TTL)

    Write-Host ''
    Write-Host 'Requested Temporary Access' -ForegroundColor White
    Write-Host '------------------------------------------------------------'
    Write-Host "Operation ID : $OperationId"
    Write-Host "User         : $($TargetUser.SamAccountName)"
    Write-Host "Display Name : $($TargetUser.DisplayName)"
    Write-Host "Group        : $($TargetGroup.Name)"
    Write-Host "Duration     : $Duration"
    Write-Host "Expires      : $($ExpiryDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "Ticket       : $TicketNumber"
    Write-Host "Reason       : $Reason"
    Write-Host "Operator     : $($Operator.SamAccountName)"
    Write-Host "Forest       : $($Forest.Name)"
    Write-Host "Forest Mode  : $($Forest.ForestMode)"
    Write-Host '------------------------------------------------------------'
    Write-Host ''

    $TargetDescription = (
        "User [$($TargetUser.SamAccountName)] to " +
        "group [$($TargetGroup.Name)] for [$Duration]"
    )

   # $ChangeAttempted = $true

    Write-Status -Level Info -Message 'Granting temporary TTL membership.'

$AddParameters = @{
    Identity         = $TargetGroup
    Members          = $TargetUser
    MemberTimeToLive = $TTL
    ErrorAction      = 'Stop'
    Confirm          = $false
}

if ($null -ne $Server -and $Server.Trim().Length -gt 0) {
    $AddParameters['Server'] = $Server
}
if (
    -not $PSCmdlet.ShouldProcess(
        $TargetDescription,
        'Grant temporary Active Directory group membership'
    )
) {
    Write-Status -Level Warning -Message 'Operation cancelled or simulated.'
    return
}
$ChangeAttempted = $true
Add-ADGroupMember @AddParameters

Write-Status -Level Info -Message 'Verifying temporary membership.'

try {

   for ($i = 1; $i -le 5; $i++) {

    $Verification = Get-TtlMembershipVerification `
        -TargetUser $TargetUser `
        -TargetGroup $TargetGroup

    if (
        $Verification -and
        $null -ne $Verification.RemainingSeconds
    ) {
        break
    }

    Start-Sleep -Seconds 2
}
}
catch {

    throw "TTL verification failed. $($_.Exception.Message)"
}

if ($null -eq $Verification) {

    throw 'TTL membership could not be verified.'
}

if ($null -eq $Verification.RemainingSeconds) {

    throw (
        'The user was found in the group, but no TTL value was returned.'
    )
}

    $SuccessAudit = [PSCustomObject][ordered]@{
        OperationId         = $OperationId
        Status              = 'Success'
        DateGranted = $GrantTime.ToString('yyyy-MM-dd HH:mm:ss')
        UserSamAccountName  = Protect-CsvValue $TargetUser.SamAccountName
        UserDisplayName     = Protect-CsvValue $TargetUser.DisplayName
        UserPrincipalName   = Protect-CsvValue $TargetUser.UserPrincipalName
        UserSID             = $TargetUser.SID.Value
        GroupName           = Protect-CsvValue $TargetGroup.Name
        GroupSID            = $TargetGroup.SID.Value
        Duration            = $Duration
        RequestedTTLSeconds = [int64]$TTL.TotalSeconds
        VerifiedTTLSeconds  = $Verification.RemainingSeconds
        Expires             = $ExpiryDate.ToString('yyyy-MM-dd HH:mm:ss')
        TicketNumber        = Protect-CsvValue $TicketNumber
        Reason              = Protect-CsvValue $Reason
        GrantedBy           = Protect-CsvValue $Operator.SamAccountName
        OperatorSID         = $Operator.SID.Value
        Computer            = $env:COMPUTERNAME
        DomainController    = if ($Server) { $Server } else { 'Automatic' }
        Forest              = $Forest.Name
        ForestMode          = $Forest.ForestMode.ToString()
        ScriptVersion       = $ScriptVersion
        ErrorMessage        = $null
    }

    Write-AuditLog -Record $SuccessAudit

    Write-Host ''
    Write-Host '============================================================' `
        -ForegroundColor Green
  # Verify TTL Membership

Write-Host ""
Write-Host "Checking TTL Membership..." -ForegroundColor Cyan
$ADParameters = Get-CommonADParameters
$TTLMembership = Get-ADGroup `
    -Identity $TargetGroup.DistinguishedName `
    -Properties member `
    -ShowMemberTimeToLive `
    @ADParameters |
    Select-Object -ExpandProperty member |
    Where-Object {
        $_ -like "*$($TargetUser.DistinguishedName)*"
    }

if ($TTLMembership) {

    Write-Host "TTL Membership Verified:" -ForegroundColor Green
    Write-Host $TTLMembership -ForegroundColor Green

}
else {

    Write-Warning "TTL Membership not found."

}
 
    Write-Host '============================================================' `
        -ForegroundColor Green
    Write-Host "Status        : SUCCESS"
    Write-Host "Operation ID  : $OperationId"
    Write-Host "User          : $($TargetUser.SamAccountName)"
    Write-Host "Display Name  : $($TargetUser.DisplayName)"
    Write-Host "Group         : $($TargetGroup.Name)"
    Write-Host "Duration      : $Duration"
   Write-Host ("TTL Remaining : {0}" -f $Verification.RemainingTime)
    Write-Host "Expiration    : $($ExpiryDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "Ticket        : $TicketNumber"
    Write-Host "Granted By    : $($Operator.SamAccountName)"
    Write-Host "Audit Log     : $LogPath"
    Write-Host '------------------------------------------------------------'
    Write-Host 'The membership will expire automatically through AD TTL.' `
        -ForegroundColor Green
    Write-Host (
        'The user should sign out and sign in again to obtain a new ' +
        'Kerberos access token.'
    ) -ForegroundColor Yellow
    Write-Host '============================================================'
    Write-Host ''

    [PSCustomObject]@{
        Status             = 'Success'
        OperationId        = $OperationId
        User               = $TargetUser.SamAccountName
        DisplayName        = $TargetUser.DisplayName
        Group              = $TargetGroup.Name
        Duration           = $Duration
        Expiration         = $ExpiryDate
        RemainingTTL       = $Verification.RemainingTime
        TicketNumber       = $TicketNumber
        GrantedBy          = $Operator.SamAccountName
        AuditLog           = $LogPath
    }
}
catch {
    $ErrorMessage = $_.Exception.Message

    Write-Host ''
    Write-Host '============================================================' `
        -ForegroundColor Red
    Write-Host ' TEMPORARY ACCESS ASSIGNMENT FAILED' `
        -ForegroundColor Red
    Write-Host '============================================================' `
        -ForegroundColor Red
    Write-Host "Operation ID : $OperationId"
    Write-Host "Error        : $ErrorMessage"
    Write-Host "Audit Log    : $LogPath"
    Write-Host '============================================================'
    Write-Host ''

    try {
        $FailureAudit = [PSCustomObject][ordered]@{
            OperationId         = $OperationId
            Status              = 'Failed'
            DateGranted         = $StartTime.ToString('yyyy-MM-dd HH:mm:ss')
            UserSamAccountName  = if ($TargetUser) {
                Protect-CsvValue $TargetUser.SamAccountName
            }
            else {
                Protect-CsvValue $User
            }
            UserDisplayName     = if ($TargetUser) {
                Protect-CsvValue $TargetUser.DisplayName
            }
            else {
                $null
            }
            UserPrincipalName   = if ($TargetUser) {
                Protect-CsvValue $TargetUser.UserPrincipalName
            }
            else {
                $null
            }
            UserSID             = if ($TargetUser) {
                $TargetUser.SID.Value
            }
            else {
                $null
            }
            GroupName           = if ($TargetGroup) {
                Protect-CsvValue $TargetGroup.Name
            }
            else {
                Protect-CsvValue $Group
            }
            GroupSID            = if ($TargetGroup) {
                $TargetGroup.SID.Value
            }
            else {
                $null
            }
            Duration            = $Duration
            RequestedTTLSeconds = if ($TTL) {
                [int64]$TTL.TotalSeconds
            }
            else {
                $null
            }
            VerifiedTTLSeconds  = if ($Verification) {
                $Verification.RemainingSeconds
            }
            else {
                $null
            }
            Expires             = if ($ExpiryDate) {
                $ExpiryDate.ToString('yyyy-MM-dd HH:mm:ss')
            }
            else {
                $null
            }
            TicketNumber        = Protect-CsvValue $TicketNumber
            Reason              = Protect-CsvValue $Reason
            GrantedBy           = if ($Operator) {
                Protect-CsvValue $Operator.SamAccountName
            }
            else {
                Protect-CsvValue $env:USERNAME
            }
            OperatorSID         = if ($Operator) {
                $Operator.SID.Value
            }
            else {
                $null
            }
            Computer            = $env:COMPUTERNAME
            DomainController    = if ($Server) { $Server } else { 'Automatic' }
            Forest              = if ($Forest) { $Forest.Name } else { $null }
            ForestMode          = if ($Forest) {
                $Forest.ForestMode.ToString()
            }
            else {
                $null
            }
            ScriptVersion       = $ScriptVersion
            ErrorMessage        = Protect-CsvValue $ErrorMessage
            ChangeAttempted     = $ChangeAttempted
        }

        Write-AuditLog -Record $FailureAudit
    }
    catch {
        Write-Warning (
            "The failure could not be recorded in the audit log. " +
            $_.Exception.Message
        )
    }

    throw
}
