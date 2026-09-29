# AD TTL Access Manager
# PowerShell WPF GUI for Active Directory Just-In-Time (JIT)
# privileged access management using PAM and TTL memberships.
# Includes user validation, TTL assignment, membership verification,
# audit logging, and automatic privilege expiration.
#
# Author  : Bhagawan Tapase
# Version : 3.0
#requires -Modules ActiveDirectory

#region Bootstrap: Windows + STA
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'Windows-only application.'
    return
}

function Restart-AsSTA {
    $exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' }
    Start-Process -FilePath $exe -ArgumentList @(
        '-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`""
    ) | Out-Null
    exit
}

if ($Host.Name -notlike '*ISE*' -and [Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Restart-AsSTA
}
#endregion

Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase,System.Xaml
Import-Module ActiveDirectory -ErrorAction Stop

$Theme = @{
    Bg='#1E2227'; Card='#24292F'; Field='#2C323A'; Text='#F0F0F0'
    Muted='#B8C0CC'; Accent='#0E7AC7'; Success='#49B06E'
    Warn='#D18A3B'; Error='#E05A5A'; Border='#3A424B'
}

$AllowedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Server Admins')
$AuthorizedOperatorGroup = 'Domain Admins'
$ProtectedAccounts = @('Administrator','krbtgt','Guest')
$BlockedPrefixes = @('svc_','sa_','sql_')
$LogFolder = 'D:\Logs\AD-TTL'
$LogPath = Join-Path $LogFolder 'TTL_Access_Log.csv'
$ScriptVersion = '3.0.0'
$script:ValidatedUser = $null

function Set-Status {
    param(
        [Parameter(Mandatory)]$Box,
        [ValidateSet('Info','Success','Warning','Error')][string]$Kind='Info',
        [Parameter(Mandatory)][string]$Text
    )
    $hex = switch ($Kind) {
        'Success' { $Theme.Success }
        'Warning' { $Theme.Warn }
        'Error'   { $Theme.Error }
        default   { $Theme.Text }
    }
    $Box.Text = $Text
    $Box.Foreground = New-Object Windows.Media.SolidColorBrush(
        [Windows.Media.ColorConverter]::ConvertFromString($hex)
    )
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
function Show-Confirm {

    param(
        [string]$Message,
        [string]$Title = 'Confirmation'
    )

[xml]$DialogXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
Title="$Title"
Width="420"
Height="350"
ResizeMode="NoResize"
WindowStartupLocation="CenterOwner"
Background="$($Theme.Bg)"
ShowInTaskbar="False">

    <Grid Margin="10">

        <Grid.RowDefinitions>
            <RowDefinition Height="*" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>

        <Border Grid.Row="0"
                Background="$($Theme.Card)"
                CornerRadius="6"
                Padding="12">

            <TextBlock x:Name="txtMessage"
                       Foreground="$($Theme.Text)"
                       TextWrapping="Wrap"
                       FontSize="12"/>
        </Border>

        <Grid Grid.Row="1" Margin="0,10,0,0">

            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="*" />
            </Grid.ColumnDefinitions>

            <Button x:Name="btnYes"
                    Grid.Column="0"
                    Content="Yes"
                    Margin="0,0,5,0"
                    Background="$($Theme.Accent)"
                    Foreground="White"
                    BorderThickness="0"
                    Height="30" />

            <Button x:Name="btnNo"
                    Grid.Column="1"
                    Content="No"
                    Margin="5,0,0,0"
                    Background="$($Theme.Card)"
                    Foreground="$($Theme.Text)"
                    BorderBrush="$($Theme.Accent)"
                    Height="30" />

        </Grid>

    </Grid>

</Window>
"@

    $Reader = New-Object System.Xml.XmlNodeReader $DialogXaml
    $Dialog = [Windows.Markup.XamlReader]::Load($Reader)

    $Dialog.FindName("txtMessage").Text = $Message

    $Result = $false

    $Dialog.FindName("btnYes").Add_Click({
        $script:DialogResult = $true
        $Dialog.Close()
    })

    $Dialog.FindName("btnNo").Add_Click({
        $script:DialogResult = $false
        $Dialog.Close()
    })

$script:DialogResult = $false

if ($null -ne $script:MainWindow) {
    $Dialog.Owner = $script:MainWindow
}

[void]$Dialog.ShowDialog()

    return $script:DialogResult
}

function Test-EnvironmentRequirements {
    $forest = Get-ADForest -ErrorAction Stop
    if ([int]$forest.ForestMode -lt 7) {
        throw 'Forest Functional Level must be Windows Server 2016 or later.'
    }

    $pam = Get-ADOptionalFeature -Identity 'Privileged Access Management Feature' -ErrorAction Stop
    if (-not $pam.EnabledScopes -or $pam.EnabledScopes.Count -eq 0) {
        throw 'Privileged Access Management optional feature is not enabled.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.User) { throw 'Unable to determine the current operator SID.' }

    $operator = Get-ADUser -Identity $identity.User.Value -Properties Enabled,SID,SamAccountName -ErrorAction Stop
    if (-not $operator.Enabled) { throw "Operator [$($operator.SamAccountName)] is disabled." }

    $authorized = Get-ADGroupMember -Identity $AuthorizedOperatorGroup -Recursive -ErrorAction Stop |
        Where-Object { $_.SID -and $_.SID.Value -eq $operator.SID.Value } |
        Select-Object -First 1

    if (-not $authorized) {
        throw "Operator [$($operator.SamAccountName)] is not a member of [$AuthorizedOperatorGroup]."
    }

    [pscustomobject]@{ Forest=$forest; Operator=$operator }
}

function Resolve-TtlUser {
    param([Parameter(Mandatory)][string]$Identity)

    $u = Get-ADUser -Identity $Identity -Properties Enabled,DisplayName,SamAccountName,SID,DistinguishedName,UserPrincipalName -ErrorAction Stop
    if (-not $u.Enabled) { throw "User [$($u.SamAccountName)] is disabled." }
    if ($u.SamAccountName -in $ProtectedAccounts) { throw "Protected account [$($u.SamAccountName)] cannot be processed." }

    foreach ($prefix in $BlockedPrefixes) {
        if ($u.SamAccountName.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw "Account [$($u.SamAccountName)] matches blocked prefix [$prefix]."
        }
    }
    return $u
}

function Resolve-TtlGroup {
    param([Parameter(Mandatory)][string]$Identity)

    if ($Identity -notin $AllowedGroups) { throw "Group [$Identity] is not approved." }
    $g = Get-ADGroup -Identity $Identity -Properties GroupCategory,SID,DistinguishedName -ErrorAction Stop
    if ($g.GroupCategory -ne 'Security') { throw "Group [$Identity] is not a security group." }
    return $g
}

function Get-TtlMembership {
    param($User,$Group)

    $g = Get-ADGroup -Identity $Group.DistinguishedName -Properties member -ShowMemberTimeToLive -ErrorAction Stop
    $entry = @($g.member) | Where-Object {
        $_ -and $_.EndsWith($User.DistinguishedName,[StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1

    if (-not $entry -or $entry -notmatch '^<TTL=(\d+)>,') {
return $null
}
    $seconds = [int64]$Matches[1]
    [pscustomobject]@{
        RawEntry=$entry
        RemainingSeconds=$seconds
        RemainingTime=(New-TimeSpan -Seconds $seconds)
    }
}

function Test-DirectMembership {
    param($User,$Group)
    return [bool](Get-ADGroupMember -Identity $Group -ErrorAction Stop |
        Where-Object { $_.DistinguishedName -eq $User.DistinguishedName } |
        Select-Object -First 1)
}

function Write-TtlAudit {
    param([Parameter(Mandatory)]$Record)
    if (-not (Test-Path -LiteralPath $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $Record | Export-Csv -LiteralPath $LogPath -Append -NoTypeInformation -Encoding UTF8 -Force
}

function Invoke-TtlGrant {
    param(
        [Parameter(Mandatory)]
        $User,

        [Parameter(Mandatory)]
        $Group,

        [Parameter(Mandatory)]
        [string]$Ticket,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter(Mandatory)]
        [ValidateSet('Days', 'Hours')]
        [string]$DurationType,

        [Parameter(Mandatory)]
        [int]$DurationValue,

        [Parameter(Mandatory)]
        $Environment
    )

    $OperationId = [guid]::Guid
    $ChangeAttempted = $false
    $MembershipRemoved = $false
    $RollbackStatus = 'NotRequired'

    $OriginalMembershipType = 'None'
    $OriginalTtlExpiry = $null
    $ExistingTtl = $null

    $TTL = if ($DurationType -eq 'Days') {
        New-TimeSpan -Days $DurationValue
    }
    else {
        New-TimeSpan -Hours $DurationValue
    }

    $Duration = "$DurationValue $DurationType"
    $GrantTime = Get-Date
    $Expiry = $GrantTime.Add($TTL)

    try {
        # ----------------------------------------------------
        # Determine current membership state
        # ----------------------------------------------------

        $ExistingTtl = Get-TtlMembership `
            -User $User `
            -Group $Group

        if ($ExistingTtl) {
            $OriginalMembershipType = 'TTL'

            $OriginalTtlExpiry = (Get-Date).AddSeconds(
                $ExistingTtl.RemainingSeconds
            )
        }
        elseif (
            Test-DirectMembership `
                -User $User `
                -Group $Group
        ) {
            $OriginalMembershipType = 'Permanent'
        }

        # ----------------------------------------------------
        # Build one final confirmation before any change
        # ----------------------------------------------------

        $ExistingAccessMessage = switch ($OriginalMembershipType) {
            'TTL' {
                (
                    "Existing access: TTL membership`n" +
                    "Current remaining TTL: " +
                    "$($ExistingTtl.RemainingTime)"
                )
            }

            'Permanent' {
                'Existing access: Permanent direct membership'
            }

            default {
                'Existing access: None'
            }
        }

        $ConfirmationMessage = @"
User: $($User.SamAccountName)
Display Name: $($User.DisplayName)

Group: $($Group.Name)

$ExistingAccessMessage

Requested duration: $Duration
Expiration: $($Expiry.ToString('yyyy-MM-dd HH:mm:ss'))

Ticket: $Ticket
Reason: $Reason

Continue with this TTL access operation?
"@

        if (
            -not (
                Show-Confirm `
                    -Message $ConfirmationMessage `
                    -Title 'Confirm TTL Access'
            )
        ) {
            return [pscustomobject]@{
                Status  = 'Cancelled'
                Message = 'TTL access operation was cancelled. No membership was changed.'
            }
        }

        # ----------------------------------------------------
        # Remove existing membership only after confirmation
        # ----------------------------------------------------

        if ($OriginalMembershipType -ne 'None') {
            Remove-ADGroupMember `
                -Identity $Group `
                -Members $User `
                -Confirm:$false `
                -ErrorAction Stop

            $MembershipRemoved = $true

            Start-Sleep -Seconds 2
        }

        # ----------------------------------------------------
        # Add requested TTL membership
        # ----------------------------------------------------

        $ChangeAttempted = $true

        Add-ADGroupMember `
            -Identity $Group `
            -Members $User `
            -MemberTimeToLive $TTL `
            -Confirm:$false `
            -ErrorAction Stop

        # ----------------------------------------------------
        # Verify TTL membership
        # ----------------------------------------------------

        $Verification = $null

        for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
            $Verification = Get-TtlMembership `
                -User $User `
                -Group $Group

            if (
                $Verification -and
                $null -ne $Verification.RemainingSeconds
            ) {
                break
            }

            if ($Attempt -lt 5) {
                Start-Sleep -Seconds 2
            }
        }

        if (
            -not $Verification -or
            $null -eq $Verification.RemainingSeconds
        ) {
            throw (
                'TTL membership could not be verified ' +
                'after five attempts.'
            )
        }

        # ----------------------------------------------------
        # Success Audit
        # ----------------------------------------------------

        Write-TtlAudit -Record (
            [pscustomobject][ordered]@{
                OperationId         = $OperationId
                Status              = 'Success'
                DateGranted         = $GrantTime.ToString(
                    'yyyy-MM-dd HH:mm:ss'
                )
                UserSamAccountName  = Protect-CsvValue $User.SamAccountName
                UserDisplayName     = Protect-CsvValue $User.DisplayName
                UserPrincipalName   = Protect-CsvValue $User.UserPrincipalName
                UserSID             = $User.SID.Value
                GroupName           = Protect-CsvValue $Group.Name
                GroupSID            = $Group.SID.Value
                PreviousMembership  = $OriginalMembershipType
                Duration            = $Duration
                RequestedTTLSeconds = [int64]$TTL.TotalSeconds
                VerifiedTTLSeconds  = $Verification.RemainingSeconds
                Expires             = $Expiry.ToString(
                    'yyyy-MM-dd HH:mm:ss'
                )
                TicketNumber        = Protect-CsvValue $Ticket
                Reason              = Protect-CsvValue $Reason
                GrantedBy           = Protect-CsvValue (
                    $Environment.Operator.SamAccountName
                )
                OperatorSID         = $Environment.Operator.SID.Value
                Computer            = $env:COMPUTERNAME
                Forest              = $Environment.Forest.Name
                ForestMode          = $Environment.Forest.ForestMode.ToString()
                ScriptVersion       = $ScriptVersion
                ChangeAttempted     = $ChangeAttempted
                RollbackStatus      = $RollbackStatus
                ErrorMessage        = $null
            }
        )

        return [pscustomobject]@{
            Status = 'Success'

            Message = (
                "TTL access granted and verified.`r`n`r`n" +
                "User: $($User.SamAccountName)`r`n" +
                "Group: $($Group.Name)`r`n" +
                "Remaining TTL: $($Verification.RemainingTime)`r`n" +
                "Expiration: $($Expiry.ToString('yyyy-MM-dd HH:mm:ss'))`r`n" +
                "Audit Log: $LogPath"
            )
        }
    }
    catch {
        $OriginalError = $_.Exception.Message

        # ----------------------------------------------------
        # Rollback existing membership when replacement fails
        # ----------------------------------------------------

        if ($MembershipRemoved) {
            try {
                # Remove any partially created replacement membership.
                if (
                    Test-DirectMembership `
                        -User $User `
                        -Group $Group
                ) {
                    Remove-ADGroupMember `
                        -Identity $Group `
                        -Members $User `
                        -Confirm:$false `
                        -ErrorAction Stop

                    Start-Sleep -Seconds 1
                }

                if ($OriginalMembershipType -eq 'Permanent') {
                    Add-ADGroupMember `
                        -Identity $Group `
                        -Members $User `
                        -Confirm:$false `
                        -ErrorAction Stop

                    $RollbackStatus = 'PermanentMembershipRestored'
                }
                elseif (
                    $OriginalMembershipType -eq 'TTL' -and
                    $null -ne $OriginalTtlExpiry
                ) {
                    $RollbackTtl = $OriginalTtlExpiry - (Get-Date)

                    if ($RollbackTtl.TotalSeconds -gt 1) {
                        Add-ADGroupMember `
                            -Identity $Group `
                            -Members $User `
                            -MemberTimeToLive $RollbackTtl `
                            -Confirm:$false `
                            -ErrorAction Stop

                        $RollbackStatus = 'TtlMembershipRestored'
                    }
                    else {
                        $RollbackStatus = 'OriginalTtlAlreadyExpired'
                    }
                }
            }
            catch {
                $RollbackStatus = (
                    'RollbackFailed: ' +
                    $_.Exception.Message
                )
            }
        }

        # ----------------------------------------------------
        # Failure Audit
        # ----------------------------------------------------

        try {
            Write-TtlAudit -Record (
                [pscustomobject][ordered]@{
                    OperationId         = $OperationId
                    Status              = 'Failed'
                    DateGranted         = $GrantTime.ToString(
                        'yyyy-MM-dd HH:mm:ss'
                    )
                    UserSamAccountName  = Protect-CsvValue $User.SamAccountName
                    UserDisplayName     = Protect-CsvValue $User.DisplayName
                    UserPrincipalName   = Protect-CsvValue $User.UserPrincipalName
                    UserSID             = $User.SID.Value
                    GroupName           = Protect-CsvValue $Group.Name
                    GroupSID            = $Group.SID.Value
                    PreviousMembership  = $OriginalMembershipType
                    Duration            = $Duration
                    RequestedTTLSeconds = [int64]$TTL.TotalSeconds
                    VerifiedTTLSeconds  = $null
                    Expires             = $Expiry.ToString(
                        'yyyy-MM-dd HH:mm:ss'
                    )
                    TicketNumber        = Protect-CsvValue $Ticket
                    Reason              = Protect-CsvValue $Reason
                    GrantedBy           = Protect-CsvValue (
                        $Environment.Operator.SamAccountName
                    )
                    OperatorSID         = $Environment.Operator.SID.Value
                    Computer            = $env:COMPUTERNAME
                    Forest              = $Environment.Forest.Name
                    ForestMode          = $Environment.Forest.ForestMode.ToString()
                    ScriptVersion       = $ScriptVersion
                    ChangeAttempted     = $ChangeAttempted
                    RollbackStatus      = Protect-CsvValue $RollbackStatus
                    ErrorMessage        = Protect-CsvValue $OriginalError
                }
            )
        }
        catch {
            # Preserve the original AD error.
        }

        throw (
            "$OriginalError Rollback status: $RollbackStatus"
        )
    }
}

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AD TTL Access Manager" Width="420" Height="590"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        Background="$($Theme.Bg)" SnapsToDevicePixels="True" UseLayoutRounding="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Card" Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text" Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <SolidColorBrush x:Key="Border" Color="$($Theme.Border)"/>
    <Style x:Key="Lbl" TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,4,0,2"/>
    </Style>
    <Style x:Key="Txt" TargetType="TextBox">
      <Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Border}"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="7,3"/><Setter Property="Height" Value="24"/><Setter Property="FontSize" Value="11"/>
    </Style>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Accent}"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Height" Value="28"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
    <Style x:Key="Secondary" TargetType="Button">
      <Setter Property="Background" Value="{StaticResource Card}"/><Setter Property="Foreground" Value="{StaticResource Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Accent}"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Height" Value="28"/><Setter Property="FontWeight" Value="SemiBold"/>
    </Style>
  </Window.Resources>
  <Grid Margin="7">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="7" Padding="7" Margin="0,0,0,6">
      <StackPanel><TextBlock Text="Active Directory TTL Access Manager" Foreground="{StaticResource Text}" FontSize="13" FontWeight="Bold"/>
      <TextBlock Text="Temporary privileged group membership" Foreground="{StaticResource Muted}" FontSize="10" Margin="0,3,0,0"/></StackPanel>
    </Border>
    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="7" Padding="8">
    <StackPanel>
        <TextBlock Text="User ID:" Style="{StaticResource Lbl}"/>
        <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="95"/></Grid.ColumnDefinitions>
          <TextBox x:Name="txtUser" Grid.Column="0" Style="{StaticResource Txt}"/>
          <Button x:Name="btnValidate" Grid.Column="1" Content="Validate User" Style="{StaticResource Secondary}" Margin="7,0,0,0"/>
        </Grid>
        <TextBlock Text="Display Name:" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="txtDisplay" Style="{StaticResource Txt}" IsReadOnly="True"/>
        <TextBlock Text="Group:" Style="{StaticResource Lbl}"/>
        <ComboBox x:Name="cmbGroup" Height="24" Background="{StaticResource Field}" Foreground="Black" BorderBrush="{StaticResource Border}"/>
        <TextBlock Text="Ticket Number:" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="txtTicket" Style="{StaticResource Txt}"/>
        <TextBlock Text="Business Reason:" Style="{StaticResource Lbl}"/>
        <TextBox x:Name="txtReason" Height="40" AcceptsReturn="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                 Background="{StaticResource Field}" Foreground="{StaticResource Text}" BorderBrush="{StaticResource Border}" Padding="7"/>
        <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0" Margin="0,0,5,0"><TextBlock Text="Duration Type:" Style="{StaticResource Lbl}"/>
            <ComboBox x:Name="cmbType" Height="24" Background="{StaticResource Field}" Foreground="Black" BorderBrush="{StaticResource Border}"/>
          </StackPanel>
          <StackPanel Grid.Column="1" Margin="5,0,0,0"><TextBlock Text="Duration Value:" Style="{StaticResource Lbl}"/>
            <TextBox x:Name="txtDuration" Style="{StaticResource Txt}" Text="1"/>
          </StackPanel>
        </Grid>
        <TextBlock Text="Status:" Style="{StaticResource Lbl}" Margin="0,6,0,2"/>
        <Border Height="75" Background="{StaticResource Field}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="4" Padding="7">
          <ScrollViewer VerticalScrollBarVisibility="Auto"><TextBlock x:Name="txtStatus" Text="Ready." Foreground="{StaticResource Text}" TextWrapping="Wrap"/></ScrollViewer>
        </Border>
        <Grid Margin="0,7,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <Button x:Name="btnClear" Grid.Column="0" Content="Clear" Style="{StaticResource Secondary}"/>
          <Button x:Name="btnGrant" Grid.Column="1" Content="Grant TTL Access" Style="{StaticResource Primary}" Margin="8,0,0,0"/>
        </Grid>
      </StackPanel>
    </Border>
    <Border Grid.Row="2" Background="{StaticResource Card}" CornerRadius="7" Padding="5" Margin="0,6,0,0">
      <TextBlock Text="Enter = Grant Access  |  Esc = Close" Foreground="{StaticResource Muted}" FontSize="10" HorizontalAlignment="Center"/>
    </Border>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$script:MainWindow = $window
function C([string]$Name) { $window.FindName($Name) }

$txtUser=C 'txtUser'; $btnValidate=C 'btnValidate'; $txtDisplay=C 'txtDisplay'
$cmbGroup=C 'cmbGroup'; $txtTicket=C 'txtTicket'; $txtReason=C 'txtReason'
$cmbType=C 'cmbType'; $txtDuration=C 'txtDuration'; $txtStatus=C 'txtStatus'
$btnClear=C 'btnClear'; $btnGrant=C 'btnGrant'

foreach ($g in $AllowedGroups) { [void]$cmbGroup.Items.Add($g) }
$cmbGroup.SelectedIndex=0
[void]$cmbType.Items.Add('Days'); [void]$cmbType.Items.Add('Hours'); $cmbType.SelectedIndex=0

try {
    $script:Environment = Test-EnvironmentRequirements
    Set-Status -Box $txtStatus -Kind Success -Text "Ready. Operator [$($script:Environment.Operator.SamAccountName)] is authorized."
} catch {
    Set-Status -Box $txtStatus -Kind Error -Text $_.Exception.Message
    $btnValidate.IsEnabled=$false; $btnGrant.IsEnabled=$false
}

$btnValidate.Add_Click({
    try {
        $id=$txtUser.Text.Trim()
        if (-not $id) { throw 'Enter a User ID.' }
        $script:ValidatedUser=Resolve-TtlUser -Identity $id
        $txtDisplay.Text="$($script:ValidatedUser.DisplayName) | $($script:ValidatedUser.UserPrincipalName)"
        $group=Resolve-TtlGroup -Identity ([string]$cmbGroup.SelectedItem)
        $ttl=Get-TtlMembership -User $script:ValidatedUser -Group $group
        if ($ttl) {
            Set-Status -Box $txtStatus -Kind Warning -Text "User validated. Existing TTL membership found in [$($group.Name)]. Remaining: $($ttl.RemainingTime)"
        } elseif (Test-DirectMembership -User $script:ValidatedUser -Group $group) {
            Set-Status -Box $txtStatus -Kind Warning -Text "User validated. Permanent direct membership found in [$($group.Name)]."
        } else {
            Set-Status -Box $txtStatus -Kind Success -Text 'User validated successfully. No existing direct membership found in the selected group.'
        }
    } catch {
        $script:ValidatedUser=$null; $txtDisplay.Clear()
        Set-Status -Box $txtStatus -Kind Error -Text $_.Exception.Message
    }
})
$txtUser.Add_TextChanged({
    if (
        $script:ValidatedUser -and
        $txtUser.Text.Trim() -ne
        $script:ValidatedUser.SamAccountName
    ) {
        $script:ValidatedUser = $null
        $txtDisplay.Clear()

        Set-Status `
            -Box $txtStatus `
            -Kind Info `
            -Text 'User ID changed. Validate the user again.'
    }
})

$btnClear.Add_Click({
    $script:ValidatedUser=$null; $txtUser.Clear(); $txtDisplay.Clear(); $txtTicket.Clear(); $txtReason.Clear()
    $txtDuration.Text='1'; $cmbGroup.SelectedIndex=0; $cmbType.SelectedIndex=0
    Set-Status -Box $txtStatus -Kind Info -Text 'Form cleared. Ready.'; $txtUser.Focus()
})

$btnGrant.Add_Click({
    try {
        $id=$txtUser.Text.Trim(); $ticket=$txtTicket.Text.Trim(); $reason=$txtReason.Text.Trim()
        $groupName=[string]$cmbGroup.SelectedItem; $type=[string]$cmbType.SelectedItem
        $value=0
        if (-not $id) { throw 'Enter a User ID.' }
        if (-not $ticket) { throw 'Enter a ticket number.' }
        if ($reason.Length -lt 10) { throw 'Business reason must contain at least 10 characters.' }
        if (-not [int]::TryParse($txtDuration.Text.Trim(),[ref]$value)) { throw 'Duration must be a whole number.' }
        if ($type -eq 'Days' -and ($value -lt 1 -or $value -gt 30)) { throw 'Days must be between 1 and 30.' }
        if ($type -eq 'Hours' -and ($value -lt 1 -or $value -gt 720)) { throw 'Hours must be between 1 and 720.' }

        if (-not $script:ValidatedUser -or $script:ValidatedUser.SamAccountName -ne $id) {
            $script:ValidatedUser=Resolve-TtlUser -Identity $id
            $txtDisplay.Text="$($script:ValidatedUser.DisplayName) | $($script:ValidatedUser.UserPrincipalName)"
        }
        $group=Resolve-TtlGroup -Identity $groupName
        $btnGrant.IsEnabled=$false; $btnValidate.IsEnabled=$false
        Set-Status -Box $txtStatus -Kind Info -Text 'Processing TTL access request...'
        $result=Invoke-TtlGrant -User $script:ValidatedUser -Group $group -Ticket $ticket -Reason $reason -DurationType $type -DurationValue $value -Environment $script:Environment
        if ($result.Status -eq 'Success') { Set-Status -Box $txtStatus -Kind Success -Text $result.Message }
        else { Set-Status -Box $txtStatus -Kind Warning -Text $result.Message }
    } catch {
    Set-Status -Box $txtStatus -Kind Error -Text $_.Exception.Message
}
 finally {
        $btnGrant.IsEnabled=$true; $btnValidate.IsEnabled=$true
    }
})

$window.Add_KeyDown({ param($s,$e)
    if ($e.Key -eq 'Escape') { $window.Close() }
    elseif ($e.Key -eq 'Return') {
        $btnGrant.RaiseEvent((New-Object Windows.RoutedEventArgs([Windows.Controls.Button]::ClickEvent)))
    }
})
$window.Add_ContentRendered({ $txtUser.Focus() })
[void]$window.ShowDialog()
