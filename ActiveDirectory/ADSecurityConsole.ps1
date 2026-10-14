<#

  On-premises Active Directory authentication security dashboard.
  lockouts and threshold alerts, and supports CSV export and optional email alerts.
#>
[CmdletBinding()]
param(
    [int]$LookbackMinutes = 15,
    [int]$BruteForceThreshold = 10,
    [int]$SprayUserThreshold = 5,
    [int]$SprayFailureThreshold = 10,
    [int]$FailureThenSuccessMinutes = 10,
    [int]$MaxEventsPerDC = 1000,
    [int]$DnsCacheMinutes = 60,
    [int]$UserSearchLookbackHours = 24,
    [int]$UserSearchMaxRowsPerDC = 20000,
    [string[]]$ComputerName,
    [string]$ExportFolder = "D:\ADSecurityDashboard"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# AUTHENTICATION STATE
# ============================================================

$script:IsAuthenticated = $false
$script:AuthenticatedUser = ''
$script:AuthenticatedDomain = ''
$script:AuthenticatedRole = ''

# ============================================================
# AUTHORIZED AD GROUPS
# ============================================================

$script:ADUtilityAdminGroup = 'Domain Admins'
$script:ADUtilityHelpdeskGroup = 'Helpdesk Admins'

$script:UserDisplayNameCache = @{}
$script:DnsCache = @{}
$script:LastCollection = $null
$script:LastAnalysis = $null
$script:Busy = $false
$script:DashboardDataLoaded = $false
$script:UserSearchPowerShell = $null
$script:UserSearchAsync = $null
$script:UserSearchName = ''
$script:UserSearchStarted = $null
$script:UserSearchDots = 0
$script:InventoryForm = $null
$script:CurrentUserReport = @()
$script:CurrentUserReportName = ''
$script:SelectedUserColumns = $null
$script:RealLastLogonFailedDCs = @()
$script:SelectedOUName = ''

$script:CurrentComputerReport = @()
$script:CurrentComputerReportName = ''
$script:SelectedComputerColumns = $null
$script:SelectedComputerOUName = ''



function Get-SafeCount {
    param($Value)
    if ($null -eq $Value) { return 0 }
    return @($Value).Count
}

function Test-RealUserName {
    param([string]$SamAccountName)
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) { return $false }
    $excluded = @('-','ANONYMOUS LOGON','SYSTEM','LOCAL SERVICE','NETWORK SERVICE','Unavailable','Not Recorded')
    if ($SamAccountName -in $excluded -or $SamAccountName -like '*$' -or
        $SamAccountName -like 'DWM-*' -or $SamAccountName -like 'UMFD-*') { return $false }
    return $true
}

function Normalize-IPAddress {
    param([string]$IPAddress)
    if ([string]::IsNullOrWhiteSpace($IPAddress)) { return '-' }
    $value = $IPAddress.Trim()
    if ($value -match '^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$') { return $Matches[1] }
    return $value
}

function Get-FiveMinuteBucket {
    param([datetime]$Time)
    return $Time.Date.AddHours($Time.Hour).AddMinutes($Time.Minute - ($Time.Minute % 5))
}

function Normalize-SamAccountName {
    param([string]$UserName)
    if ([string]::IsNullOrWhiteSpace($UserName)) { return '' }
    $value = $UserName.Trim()
    if ($value.Contains('\')) { $value = ($value -split '\\')[-1] }
    if ($value.Contains('@')) { $value = ($value -split '@')[0] }
    return $value
}

function Get-LogonTypeName {
    param([string]$LogonType)
    switch ($LogonType) {
        '0'  { return 'System' }
        '2'  { return 'Interactive' }
        '3'  { return 'Network' }
        '4'  { return 'Batch' }
        '5'  { return 'Service' }
        '7'  { return 'Unlock' }
        '8'  { return 'NetworkClearText' }
        '9'  { return 'NewCredentials' }
        '10' { return 'RemoteInteractive' }
        '11' { return 'CachedInteractive' }
        default { return 'Other' }
    }
}

function Get-EventActivityName {
    param([int]$EventId,[string]$Kind)
    switch ($EventId) {
        4624 { return 'Successful logon' }
        4625 { return 'Failed logon' }
        4740 { return 'Account lockout' }
        4768 { if ($Kind -eq 'Success') { return 'Kerberos TGT request successful' } else { return 'Kerberos TGT request failed' } }
        4771 { return 'Kerberos pre-authentication failed' }
        4776 { if ($Kind -eq 'Success') { return 'Credential validation successful' } else { return 'Credential validation failed' } }
        default { return $Kind }
    }
}

function Get-UserDisplayName {
    param([string]$SamAccountName)
    if ([string]::IsNullOrWhiteSpace($SamAccountName) -or
        $SamAccountName -in @('-','ANONYMOUS LOGON','Unavailable','Not Recorded')) { return '-' }
    $lookupName = $SamAccountName.Trim()
    if ($lookupName.Contains('\')) { $lookupName = ($lookupName -split '\\')[-1] }
    if ($lookupName.Contains('@')) { $lookupName = ($lookupName -split '@')[0] }
    if ($script:UserDisplayNameCache.ContainsKey($lookupName)) {
        return [string]$script:UserDisplayNameCache[$lookupName]
    }
    try {
        if (-not (Get-Module -Name ActiveDirectory)) { Import-Module ActiveDirectory -ErrorAction Stop }
        $adUser = Get-ADUser -Identity $lookupName -Properties DisplayName,Name -ErrorAction Stop
        $displayName = [string]$adUser.DisplayName
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [string]$adUser.Name }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $lookupName }
        $script:UserDisplayNameCache[$lookupName] = $displayName
        return $displayName
    }
    catch {
    $script:UserDisplayNameCache[$lookupName] = $lookupName
    return $lookupName
}
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)
    $map = @{}
    try {
        $xml = [xml]$EventRecord.ToXml()
        $nodes = @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))
        foreach ($node in $nodes) {
            $name = ''
            if ($null -ne $node.Attributes -and $null -ne $node.Attributes['Name']) {
                $name = [string]$node.Attributes['Name'].Value
            }
            if (-not [string]::IsNullOrWhiteSpace($name)) { $map[$name] = [string]$node.InnerText }
        }
    }
    catch { }
    return $map
}

function Get-MapValue {
    param([hashtable]$Map,[string[]]$Names,[string]$Default='-')
    foreach ($name in $Names) {
        if ($Map.ContainsKey($name)) {
            $value = [string]$Map[$name]
            if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '-') { return $value }
        }
    }
    return $Default
}

function Get-CallerComputer4740 {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)
    $callerComputer = ''
    try {
        $xml = [xml]$EventRecord.ToXml()
        $node = $xml.SelectSingleNode("//*[local-name()='EventData']/*[local-name()='Data'][@Name='CallerComputerName']")
        if ($null -ne $node) { $callerComputer = [string]$node.InnerText }
        if ([string]::IsNullOrWhiteSpace($callerComputer)) {
            try {
                if ($EventRecord.Properties.Count -gt 7 -and $null -ne $EventRecord.Properties[7].Value) {
                    $callerComputer = [string]$EventRecord.Properties[7].Value
                }
            }
            catch { $callerComputer = '' }
        }
        if ([string]::IsNullOrWhiteSpace($callerComputer)) {
            try {
                $message = $EventRecord.FormatDescription()
                if ($message -match '(?im)^\s*Caller\s+Computer\s+Name\s*:\s*([^\r\n]+)') {
                    $callerComputer = $Matches[1].Trim()
                }
            }
            catch { $callerComputer = '' }
        }
    }
    catch { $callerComputer = '' }
    if ([string]::IsNullOrWhiteSpace($callerComputer) -or $callerComputer -eq '-') { return 'Not Recorded' }
    return $callerComputer.Trim()
}

function Convert-SecurityEvent {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)
    $data = Get-EventDataMap -EventRecord $EventRecord
    $eventId = [int]$EventRecord.Id
    $user = Get-MapValue -Map $data -Names @('TargetUserName','AccountName','TargetUser')
    $ip = Normalize-IPAddress (Get-MapValue -Map $data -Names @('IpAddress','ClientAddress'))
    if ($eventId -eq 4740) {
        $callerComputer = Get-CallerComputer4740 -EventRecord $EventRecord
        $workstation = $callerComputer
    }
    else {
        $workstation = Get-MapValue -Map $data -Names @('WorkstationName','Workstation','ClientName','CallerComputerName')
        $callerComputer = Get-MapValue -Map $data -Names @('CallerComputerName')
    }
    $statusCode = Get-MapValue -Map $data -Names @(
    'Status',
    'SubStatus',
    'ResultCode',
    'FailureCode',
    'ErrorCode'
)
    $source = '-'
    if ($ip -notin @('-','127.0.0.1','::1')) { $source = $ip }
    elseif ($workstation -ne '-') { $source = $workstation }
    $kind = 'Other'
    if ($eventId -eq 4624) { $kind = 'Success' }
    elseif ($eventId -in @(4625,4771)) { $kind = 'Failure' }
    elseif ($eventId -eq 4740) { $kind = 'Lockout' }
    elseif ($eventId -in @(4768,4776)) {
        if ($statusCode -in @('0x0','0x00000000','0')) { $kind = 'Success' } else { $kind = 'Failure' }
    }
    [pscustomobject][ordered]@{
        Time=[datetime]$EventRecord.TimeCreated;EventId=$eventId;Kind=$kind;User=[string]$user
        Source=[string]$source;IPAddress=[string]$ip;Workstation=[string]$workstation
        CallerComputer=[string]$callerComputer;Status=[string]$statusCode
        LogonType=[string](Get-MapValue -Map $data -Names @('LogonType'));Computer=[string]$EventRecord.MachineName
    }
}

function Get-MonitorTargets {
    if ((Get-SafeCount $ComputerName) -gt 0) { return [string[]]$ComputerName }
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $found = @(Get-ADDomainController -Filter * | ForEach-Object { [string]$_.HostName })
        if ($found.Count -gt 0) { return [string[]]$found }
    }
    catch { }
    return [string[]]@($env:COMPUTERNAME)
}

function Resolve-SourceHostName {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq '-') { return '-' }
    $value = Normalize-IPAddress $Value
    if ($script:DnsCache.ContainsKey($value)) {
        $cached = $script:DnsCache[$value]
        if ([datetime]$cached.Time -ge (Get-Date).AddMinutes(-$DnsCacheMinutes)) { return [string]$cached.Value }
        $script:DnsCache.Remove($value)
    }
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($value,[ref]$parsed)) {
        try { $resolved = [string]([System.Net.Dns]::GetHostEntry($parsed).HostName) }
        catch { $resolved = $value }
        if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved = $value }
        $script:DnsCache[$value] = [pscustomobject]@{Time=Get-Date;Value=$resolved}
        return $resolved
    }
    return $value
}

function Add-LockoutWorkstationFallback {
    param($Events)
    $all = @($Events)
    $failures = @($all | Where-Object { $_ -and $_.Kind -eq 'Failure' -and (Test-RealUserName $_.User) })
    foreach ($lockout in @($all | Where-Object { $_ -and $_.EventId -eq 4740 })) {
        $caller = '-'
        if ($lockout.CallerComputer -notin @($null,'','-','Not Recorded','Unavailable')) { $caller=[string]$lockout.CallerComputer }
        elseif ($lockout.Workstation -notin @($null,'','-','Not Recorded','Unavailable')) { $caller=[string]$lockout.Workstation }
        if ($caller -ne '-') {
            $caller = Resolve-SourceHostName $caller
            $lockout.CallerComputer=$caller;$lockout.Workstation=$caller;$lockout.Source=$caller
            continue
        }
        $candidate = $failures | Where-Object {
            $_.User -eq $lockout.User -and $_.Time -le $lockout.Time -and
            $_.Time -ge $lockout.Time.AddMinutes(-10) -and
            (($_.Workstation -and $_.Workstation -ne '-') -or ($_.Source -and $_.Source -ne '-'))
        } | Sort-Object Time -Descending | Select-Object -First 1
        if ($candidate) {
            if ($candidate.Workstation -and $candidate.Workstation -ne '-') { $fallback=[string]$candidate.Workstation }
            else { $fallback=[string]$candidate.Source }
            $fallback=Resolve-SourceHostName $fallback
            $lockout.CallerComputer=$fallback;$lockout.Workstation=$fallback;$lockout.Source=$fallback
        }
        else { $lockout.CallerComputer='Unavailable';$lockout.Workstation='Unavailable';$lockout.Source='Unavailable' }
    }
    return $all
}


function Get-AuthenticationData {
    param(
        [string[]]$Targets,
        [datetime]$StartTime
    )

    $allEvents  = New-Object 'System.Collections.Generic.List[object]'
    $allErrors  = New-Object 'System.Collections.Generic.List[object]'
    $allSystems = New-Object 'System.Collections.Generic.List[object]'

    $ids = @(4624,4625,4740,4768,4771,4776)

    foreach ($target in $Targets) {

        $localEvents = New-Object 'System.Collections.Generic.List[object]'
        $queryStarted = Get-Date

        try {

            $records = @(
                Get-WinEvent `
                    -ComputerName $target `
                    -FilterHashtable @{
                        LogName   = 'Security'
                        Id        = $ids
                        StartTime = $StartTime
                    } `
                    -MaxEvents $MaxEventsPerDC `
                    -ErrorAction Stop
            )

            foreach ($record in $records) {
                try {
                    $event = Convert-SecurityEvent $record

                    [void]$allEvents.Add($event)
                    [void]$localEvents.Add($event)
                }
                catch {
                }
            }

            $local = @($localEvents.ToArray())

            [void]$allSystems.Add(
                [pscustomobject][ordered]@{
    Computer  = [string]$target
    Status    = 'Active and reachable'
    Success   = Get-SafeCount @(
        $local | Where-Object { $_.Kind -eq 'Success' }
    )
    Failure   = Get-SafeCount @(
        $local | Where-Object { $_.Kind -eq 'Failure' }
    )
    Lockouts  = Get-SafeCount @(
        $local | Where-Object { $_.EventId -eq 4740 }
    )
    LastQuery = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Error     = ''
}
            )
        }
        catch {

            $message = [string]$_.Exception.Message

            [void]$allErrors.Add(
                [pscustomobject][ordered]@{
                    Computer = [string]$target
                    Error    = $message
                }
            )

            [void]$allSystems.Add(
               [pscustomobject][ordered]@{
    Computer  = [string]$target
    Status    = 'Unavailable'
    Success   = 0
    Failure   = 0
    Lockouts  = 0
    LastQuery = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Error     = $message
}
            )
        }
    }

    $events = Add-LockoutWorkstationFallback $allEvents.ToArray()

    [pscustomobject]@{
        Events  = @($events)
        Errors  = @($allErrors.ToArray())
        Systems = @($allSystems.ToArray())
    }
}

function Get-Analysis {
    param($Events)
    $valid=@($Events|Where-Object{$_ -and $_.PSObject.Properties['User'] -and $_.PSObject.Properties['Kind'] -and $_.PSObject.Properties['Source'] -and $_.PSObject.Properties['EventId'] -and $_.PSObject.Properties['Time']})
    $failed=@($valid|Where-Object{$_.Kind-eq'Failure'-and(Test-RealUserName $_.User)})
    $allSuccess=@($valid|Where-Object{$_.Kind-eq'Success'-and(Test-RealUserName $_.User)})
    $success=@($valid|Where-Object{$_.EventId-eq4624-and(Test-RealUserName $_.User)})

    $lockoutRows=New-Object 'System.Collections.Generic.List[object]'
    foreach($lockout in @($valid|Where-Object{$_.EventId-eq4740})){
        $caller='Unavailable'
        if($lockout.CallerComputer-notin@($null,'','-','Not Recorded','Unavailable')){$caller=[string]$lockout.CallerComputer}
        elseif($lockout.Workstation-notin@($null,'','-','Not Recorded','Unavailable')){$caller=[string]$lockout.Workstation}
        [void]$lockoutRows.Add([pscustomobject][ordered]@{Time=[datetime]$lockout.Time;SamAccountName=[string]$lockout.User;DisplayName=Get-UserDisplayName $lockout.User;CallerComputer=$caller;AuthenticatedDC=[string]$lockout.Computer})
    }
    $lockouts=@($lockoutRows.ToArray());$alerts=New-Object 'System.Collections.Generic.List[object]'
    foreach($g in @($failed|Group-Object User,Source)){
        if($g.Count-ge$BruteForceThreshold-and$g.Group.Count-gt0){$f=$g.Group[0];[void]$alerts.Add([pscustomobject][ordered]@{Severity='HIGH';Type='Brute force';User=[string]$f.User;Source=[string]$f.Source;Count=[int]$g.Count;Details='Repeated failures against one account'})}
    }
    foreach($g in @($failed|Where-Object{$_.Source-ne'-'}|Group-Object Source)){
        $users=@($g.Group|ForEach-Object{[string]$_.User}|Sort-Object -Unique)
        if($users.Count-ge$SprayUserThreshold-and$g.Count-ge$SprayFailureThreshold){[void]$alerts.Add([pscustomobject][ordered]@{Severity='CRITICAL';Type='Password spray';User=($users-join', ');Source=[string]$g.Name;Count=[int]$g.Count;Details=('{0} distinct users'-f$users.Count)})}
    }
    foreach($userName in @($failed|ForEach-Object{$_.User}|Sort-Object -Unique)){
        $uf=@($failed|Where-Object{$_.User-eq$userName}|Sort-Object Time);if($uf.Count-lt$BruteForceThreshold){continue}
        $last=$uf[$uf.Count-1]
        $later=$success|Where-Object{$_.User-eq$userName-and$_.Time-gt$last.Time-and$_.Time-le$last.Time.AddMinutes($FailureThenSuccessMinutes)-and($_.Source-eq$last.Source-or$_.Source-eq'-'-or$last.Source-eq'-')}|Sort-Object Time|Select-Object -First 1
        if($later){[void]$alerts.Add([pscustomobject][ordered]@{Severity='HIGH';Type='Failure then success';User=[string]$userName;Source=[string]$later.Source;Count=[int]$uf.Count;Details=('Success at {0:yyyy-MM-dd HH:mm:ss}; correlation window {1} minutes'-f$later.Time,$FailureThenSuccessMinutes)})}
    }

    $sessions=New-Object 'System.Collections.Generic.List[object]'
    foreach($g in @($success|Group-Object -Property { $b=Get-FiveMinuteBucket $_.Time;'{0}|{1}|{2}|{3}|{4:yyyyMMddHHmm}'-f$_.User,$_.Source,$_.Computer,$_.LogonType,$b })){
        $items=@($g.Group|Sort-Object Time);if($items.Count-eq0){continue};$first=$items[0];$last=$items[$items.Count-1]
        $logonTypeName=Get-LogonTypeName -LogonType ([string]$first.LogonType)
        [void]$sessions.Add([pscustomobject][ordered]@{User=[string]$first.User;DisplayName=Get-UserDisplayName $first.User;Source=[string]$first.Source;AuthenticatedDC=[string]$first.Computer;LogonType=[string]$first.LogonType;LogonTypeName=[string]$logonTypeName;FirstSeen=[datetime]$first.Time;LastSeen=[datetime]$last.Time;RawEvents=[int]$items.Count})
    }
    $failureRows=New-Object 'System.Collections.Generic.List[object]'
    foreach($g in @($failed|Group-Object -Property { $sip=[string]$_.IPAddress;if([string]::IsNullOrWhiteSpace($sip)-or$sip-eq'-'){$sip=[string]$_.Source};'{0}|{1}|{2}'-f$_.User,$sip,$_.Computer })){
        $items=@($g.Group|Sort-Object Time);if($items.Count-eq0){continue};$first=$items[0];$last=$items[$items.Count-1];$sip=[string]$first.IPAddress;if([string]::IsNullOrWhiteSpace($sip)-or$sip-eq'-'){$sip=[string]$first.Source}
        [void]$failureRows.Add([pscustomobject][ordered]@{SamAccountName=[string]$first.User;DisplayName=Get-UserDisplayName $first.User;SourceIP=$sip;AuthenticatedDC=[string]$first.Computer;FirstSeen=[datetime]$first.Time;LastSeen=[datetime]$last.Time;Attempts=[int]$items.Count})
    }
    $activity=New-Object 'System.Collections.Generic.List[object]'
foreach ($r in $sessions.ToArray()) {
    [void]$activity.Add([pscustomobject][ordered]@{
        LastSeen       = $r.LastSeen
        User           = $r.User
        Source         = $r.Source
        Activity       = 'Successful session'
        Count          = $r.RawEvents
        AuthenticatedDC = $r.AuthenticatedDC
    })
}

foreach ($r in $failureRows.ToArray()) {
    [void]$activity.Add([pscustomobject][ordered]@{
        LastSeen       = $r.LastSeen
        User           = $r.SamAccountName
        Source         = $r.SourceIP
        Activity       = 'Failed attempts'
        Count          = $r.Attempts
        AuthenticatedDC = $r.AuthenticatedDC
    })
}

foreach ($r in $lockouts) {
    [void]$activity.Add([pscustomobject][ordered]@{
        LastSeen       = $r.Time
        User           = $r.SamAccountName
        Source         = $r.CallerComputer
        Activity       = 'Account lockout'
        Count          = 1
        AuthenticatedDC = $r.AuthenticatedDC
    })
}
    [pscustomobject]@{
        Failed=$failed;Success=$allSuccess;SuccessfulLogons=$success;Lockouts=$lockouts;Alerts=@($alerts.ToArray())
        SuccessSessions=@($sessions.ToArray());FailureSummary=@($failureRows.ToArray());RecentActivity=@($activity.ToArray()|Sort-Object LastSeen -Descending)
        TopUsers=@($failed|Group-Object User|Sort-Object Count -Descending|Select-Object -First 15 @{n='User';e={$_.Name}},@{n='Failures';e={$_.Count}})
        TopSources=@($failed|Group-Object Source|Sort-Object Count -Descending|Select-Object -First 15 @{n='Source';e={$_.Name}},@{n='Failures';e={$_.Count}})
    }
}

function Set-UserSearchBusyState {
    param(
        [bool]$Busy
    )

    $searchButton.Enabled = -not $Busy
    $searchBox.Enabled = -not $Busy
    $export.Enabled = -not $Busy
    $searchProgress.Visible = $Busy

    if ($Busy) {

        $searchButton.Text = 'Searching...'
        $form.UseWaitCursor = $true

        $fetch.Enabled = $false
        $refresh.Enabled = $false
    }
    else {

        $searchButton.Text = 'Search last 1 day'
        $form.UseWaitCursor = $false

        if ($script:DashboardDataLoaded) {
            $fetch.Enabled = $false
            $refresh.Enabled = $true
            $export.Enabled = $true
        }
        else {
            $fetch.Enabled = $true
            $refresh.Enabled = $false
            $export.Enabled = $false
        }
    }
}

function Stop-UserSearch {
    $userSearchTimer.Stop()
    if ($null -ne $script:UserSearchPowerShell) {
        try {
            if ($null -ne $script:UserSearchAsync -and -not $script:UserSearchAsync.IsCompleted) {
                $script:UserSearchPowerShell.Stop()
            }
        }
        catch { }
        try { $script:UserSearchPowerShell.Dispose() } catch { }
    }
    $script:UserSearchPowerShell = $null
    $script:UserSearchAsync = $null
    Set-UserSearchBusyState $false
}

function Start-UserSearch {
    param([string]$SamAccountName)

    $searchName = Normalize-SamAccountName -UserName $SamAccountName
    if ([string]::IsNullOrWhiteSpace($searchName)) {
        [void][System.Windows.Forms.MessageBox]::Show(
            'Enter a SamAccountName first.','User search','OK','Information'
        )
        $searchBox.Focus()
        return
    }

    if ($searchName -notmatch '^[A-Za-z0-9._-]+$') {
        [void][System.Windows.Forms.MessageBox]::Show(
            'Invalid SamAccountName. Use letters, numbers, dot, underscore or hyphen.',
            'User search','OK','Warning'
        )
        return
    }

    if ($null -ne $script:UserSearchPowerShell) { Stop-UserSearch }

    $worker = {
        param(
            [string[]]$Targets,
            [string]$SearchName,
            [int]$LookbackHours,
            [int]$MaximumEventsPerDC
        )

        function Read-EventMap {
            param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)
            $map = @{}
            try {
                $xml = [xml]$Record.ToXml()
                foreach ($node in @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))) {
                    $name = ''
                    if ($null -ne $node.Attributes -and $null -ne $node.Attributes['Name']) {
                        $name = [string]$node.Attributes['Name'].Value
                    }
                    if (-not [string]::IsNullOrWhiteSpace($name)) { $map[$name] = [string]$node.InnerText }
                }
            }
            catch { }
            return $map
        }

        function Read-MapValue {
            param([hashtable]$Map,[string[]]$Names,[string]$Default='-')
            foreach ($name in $Names) {
                if ($Map.ContainsKey($name)) {
                    $value = [string]$Map[$name]
                    if (-not [string]::IsNullOrWhiteSpace($value) -and $value -ne '-') { return $value }
                }
            }
            return $Default
        }

        function Normalize-User {
            param([string]$Value)
            if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
            $v = $Value.Trim()
            if ($v.Contains('\\')) { $v = ($v -split '\\\\')[-1] }
            if ($v.Contains('@')) { $v = ($v -split '@')[0] }
            return $v
        }

        function Normalize-IP {
            param([string]$Value)
            if ([string]::IsNullOrWhiteSpace($Value)) { return '-' }
            if ($Value -match '^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$') { return $Matches[1] }
            return $Value
        }

        function Get-LogonName {
            param([string]$Value)
            switch ($Value) {
                '0' {'System'} '2' {'Interactive'} '3' {'Network'} '4' {'Batch'}
                '5' {'Service'} '7' {'Unlock'} '8' {'NetworkClearText'}
                '9' {'NewCredentials'} '10' {'RemoteInteractive'}
                '11' {'CachedInteractive'} default {'Other'}
            }
        }

        function Get-Caller4740 {
            param([System.Diagnostics.Eventing.Reader.EventRecord]$Record,[hashtable]$Map)
            $caller = Read-MapValue -Map $Map -Names @('CallerComputerName') -Default ''
            if ([string]::IsNullOrWhiteSpace($caller)) {
                try {
                    if ($Record.Properties.Count -gt 7 -and $null -ne $Record.Properties[7].Value) {
                        $caller = [string]$Record.Properties[7].Value
                    }
                }
                catch { $caller = '' }
            }
            if ([string]::IsNullOrWhiteSpace($caller)) {
                try {
                    $message = $Record.FormatDescription()
                    if ($message -match '(?im)^\s*Caller\s+Computer\s+Name\s*:\s*([^\r\n]+)') {
                        $caller = $Matches[1].Trim()
                    }
                }
                catch { $caller = '' }
            }
            if ([string]::IsNullOrWhiteSpace($caller)) { return 'Not Recorded' }
            return $caller.Trim()
        }

        $eventIds = @(4624,4625,4740,4768,4771,4776)
        $startTime = (Get-Date).AddHours(-$LookbackHours)

        foreach ($target in $Targets) {
            try {
                $records = @(Get-WinEvent -ComputerName $target -FilterHashtable @{
                    LogName='Security'; Id=$eventIds; StartTime=$startTime
                } -MaxEvents $MaximumEventsPerDC -ErrorAction Stop)

                foreach ($record in $records) {
                    try {
                        $map = Read-EventMap -Record $record
                        $user = Read-MapValue -Map $map -Names @('TargetUserName','AccountName','TargetUser')
                        $normalizedUser = Normalize-User -Value $user
                        if (-not $normalizedUser.Equals($SearchName,[System.StringComparison]::OrdinalIgnoreCase)) { continue }

                        $eventId = [int]$record.Id
                        $ip = Normalize-IP (Read-MapValue -Map $map -Names @('IpAddress','ClientAddress'))
                        $workstation = Read-MapValue -Map $map -Names @('WorkstationName','Workstation','ClientName','CallerComputerName')
                        $caller = Read-MapValue -Map $map -Names @('CallerComputerName')
                        if ($eventId -eq 4740) {
                            $caller = Get-Caller4740 -Record $record -Map $map
                            $workstation = $caller
                        }
                        $statusCode = Read-MapValue -Map $map -Names @(
    'Status',
    'SubStatus',
    'ResultCode',
    'FailureCode',
    'ErrorCode'
)
                        $logonType = Read-MapValue -Map $map -Names @('LogonType')
                        $source = '-'
                        if ($ip -notin @('-','127.0.0.1','::1')) { $source = $ip }
                        elseif ($workstation -ne '-') { $source = $workstation }

                        $result = 'Other'
                        $activity = 'Authentication event'
                        switch ($eventId) {
                            4624 { $result='Success';$activity='Successful logon' }
                            4625 { $result='Failure';$activity='Failed logon' }
                            4740 { $result='Lockout';$activity='Account lockout' }
                            4768 {
                                if ($statusCode -in @('0x0','0x00000000','0')) {$result='Success';$activity='Kerberos TGT request successful'}
                                else {$result='Failure';$activity='Kerberos TGT request failed'}
                            }
                            4771 { $result='Failure';$activity='Kerberos pre-authentication failed' }
                            4776 {
                                if ($statusCode -in @('0x0','0x00000000','0')) {$result='Success';$activity='Credential validation successful'}
                                else {$result='Failure';$activity='Credential validation failed'}
                            }
                        }

                        [pscustomobject][ordered]@{
                            RecordType='Event';Time=[datetime]$record.TimeCreated;EventId=$eventId
                            Activity=$activity;Result=$result;SamAccountName=$SearchName
                            Source=[string]$source;IPAddress=[string]$ip;Workstation=[string]$workstation
                            CallerComputer=[string]$caller;AuthenticationDC=[string]$record.MachineName
                            LogonType=[string]$logonType;LogonTypeName=[string](Get-LogonName $logonType)
                            Status=[string]$statusCode;Error=''
                        }
                    }
                    catch { }
                }
            }
            catch {
                [pscustomobject][ordered]@{
                    RecordType='Error';Time=Get-Date;EventId=0;Activity='DC query failed';Result='Error'
                    SamAccountName=$SearchName;Source='-';IPAddress='-';Workstation='-';CallerComputer='-'
                    AuthenticationDC=[string]$target;LogonType='-';LogonTypeName='-';Status='-'
                    Error=[string]$_.Exception.Message
                }
            }
        }
    }

    try {
        $script:UserSearchName = $searchName
        $script:UserSearchStarted = Get-Date
        $script:UserSearchDots = 0
        Set-UserSearchBusyState $true
        $status.Text = ('Searching last {0} hours for {1}' -f $UserSearchLookbackHours,$searchName)
        $form.Refresh()

        $script:UserSearchPowerShell = [PowerShell]::Create()
        [void]$script:UserSearchPowerShell.AddScript($worker.ToString())
        [void]$script:UserSearchPowerShell.AddArgument([string[]]$targets)
        [void]$script:UserSearchPowerShell.AddArgument($searchName)
        [void]$script:UserSearchPowerShell.AddArgument($UserSearchLookbackHours)
        [void]$script:UserSearchPowerShell.AddArgument($UserSearchMaxRowsPerDC)
        $script:UserSearchAsync = $script:UserSearchPowerShell.BeginInvoke()
        $userSearchTimer.Start()
    }
    catch {
        Stop-UserSearch
        [void][System.Windows.Forms.MessageBox]::Show(
            ("Unable to start user search.`r`n`r`n{0}" -f $_.Exception.Message),
            'User search error','OK','Error'
        )
    }
}

function New-Grid {
    $g=New-Object System.Windows.Forms.DataGridView;$g.Dock='Fill';$g.ReadOnly=$true;$g.AllowUserToAddRows=$false;$g.AllowUserToDeleteRows=$false;$g.RowHeadersVisible=$false;$g.SelectionMode='FullRowSelect';$g.MultiSelect=$false;$g.BackgroundColor='White';$g.ColumnHeadersVisible=$true;$g.EnableHeadersVisualStyles=$false
    $g.ColumnHeadersDefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(25,42,65);$g.ColumnHeadersDefaultCellStyle.ForeColor='White';$g.RowsDefaultCellStyle.ForeColor='Black';$g.AlternatingRowsDefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(242,246,250);$g.GridColor='LightGray';$g.AllowUserToResizeColumns = $true;return $g
}
function Set-GridRows { param([System.Windows.Forms.DataGridView]$Grid,$Rows,[string[]]$Columns)
    $Grid.SuspendLayout();try{$Grid.DataSource=$null;$Grid.AutoSizeColumnsMode='None';$Grid.AutoGenerateColumns=$false;$Grid.Rows.Clear();$Grid.Columns.Clear()
        foreach($name in $Columns){$c=New-Object System.Windows.Forms.DataGridViewTextBoxColumn;$c.Name=$name;$c.HeaderText=$name;$c.MinimumWidth=75;$c.SortMode='Automatic';[void]$Grid.Columns.Add($c)}
        foreach($item in @($Rows)){if($null-eq$item){continue};$values=New-Object 'System.Collections.Generic.List[object]';foreach($name in $Columns){$p=$item.PSObject.Properties[$name];if($p-and$null-ne$p.Value){if($p.Value-is[datetime]){[void]$values.Add(([datetime]$p.Value).ToString('yyyy-MM-dd HH:mm:ss'))}else{[void]$values.Add([string]$p.Value)}}else{[void]$values.Add('')}};[void]$Grid.Rows.Add($values.ToArray())}
        $Grid.AutoSizeColumnsMode='None';if($Grid.Rows.Count-gt0){$Grid.ClearSelection()};$Grid.Refresh()
    }finally{$Grid.ResumeLayout()}
}
function Add-RowStyle {param($Table,[System.Windows.Forms.SizeType]$Type,[single]$Value);$s=New-Object System.Windows.Forms.RowStyle;$s.SizeType=$Type;$s.Height=$Value;[void]$Table.RowStyles.Add($s)}
function Add-ColumnStyle {param($Table,[System.Windows.Forms.SizeType]$Type,[single]$Value);$s=New-Object System.Windows.Forms.ColumnStyle;$s.SizeType=$Type;$s.Width=$Value;[void]$Table.ColumnStyles.Add($s)}
function New-MetricCard {param([string]$Caption);$p=New-Object System.Windows.Forms.Panel;$p.Dock='Fill';$p.Margin=New-Object System.Windows.Forms.Padding(8);$p.BackColor='White';$p.Cursor='Hand';$cl=New-Object System.Windows.Forms.Label;$cl.Text=$Caption;$cl.Left=12;$cl.Top=10;$cl.Width=190;$cl.Height=22;$cl.ForeColor='DimGray';$cl.Cursor='Hand';$vl=New-Object System.Windows.Forms.Label;$vl.Text='0';$vl.Left=0;$vl.Top=30;$vl.Width=220;$vl.Height=50;$vl.AutoSize=$false;$vl.TextAlign='MiddleCenter';$vl.Font=New-Object System.Drawing.Font('Segoe UI',18,[System.Drawing.FontStyle]::Bold);$vl.Cursor='Hand';$p.Controls.Add($cl);$p.Controls.Add($vl);[pscustomobject]@{Panel=$p;Caption=$cl;Value=$vl}}
function New-OverviewGroup {param([string]$Title,[string]$Description,[System.Windows.Forms.DataGridView]$Grid);$box=New-Object System.Windows.Forms.GroupBox;$box.Text=$Title;$box.Dock='Fill';$layout=New-Object System.Windows.Forms.TableLayoutPanel;$layout.Dock='Fill';$layout.RowCount=2;Add-RowStyle $layout 'Absolute' 30;Add-RowStyle $layout 'Percent' 100;$label=New-Object System.Windows.Forms.Label;$label.Text=$Description;$label.Dock='Fill';$label.ForeColor='DimGray';$label.Padding=New-Object System.Windows.Forms.Padding(3,4,0,0);$layout.Controls.Add($label,0,0);$layout.Controls.Add($Grid,0,1);$box.Controls.Add($layout);return $box}
function Show-DetailWindow {
    param(
        [string]$Title,
        [string]$Purpose,
        $Rows,
        [string[]]$Columns,
        [string]$EmptyMessage='No records found in the current monitoring window.',
        [switch]$EnableReportFilters
    )

    $w=New-Object System.Windows.Forms.Form
    $w.Text=$Title
    $w.StartPosition='CenterParent'
    $w.Size=New-Object System.Drawing.Size(1180,700)
    $w.MinimumSize=New-Object System.Drawing.Size(900,520)
    $w.Font=New-Object System.Drawing.Font('Segoe UI',9)

    $allRows=@($Rows)
    $layout=New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock='Fill'

    if($EnableReportFilters){
        $layout.RowCount=4
        Add-RowStyle $layout 'Absolute' 60
        Add-RowStyle $layout 'Absolute' 48
        Add-RowStyle $layout 'Percent' 100
        Add-RowStyle $layout 'Absolute' 48
    }
    else{
        $layout.RowCount=3
        Add-RowStyle $layout 'Absolute' 60
        Add-RowStyle $layout 'Percent' 100
        Add-RowStyle $layout 'Absolute' 48
    }

    $purposeLabel=New-Object System.Windows.Forms.Label
    $purposeLabel.Text=$Purpose
    $purposeLabel.Dock='Fill'
    $purposeLabel.Padding=New-Object System.Windows.Forms.Padding(12,10,12,5)
    $purposeLabel.BackColor=[System.Drawing.Color]::FromArgb(235,240,246)

    $grid=New-Grid
    $count=New-Object System.Windows.Forms.Label
    $count.AutoSize=$true
    $count.Margin=New-Object System.Windows.Forms.Padding(10,7,20,0)

    function Update-ReportGrid {
        param($FilteredRows)
        $visibleRows=@($FilteredRows)
        Set-GridRows $grid $visibleRows $Columns
        if($visibleRows.Count-gt0){
            $count.Text=('Showing: {0} of {1} record(s) | Double-click a row for full details.' -f $visibleRows.Count,$allRows.Count)
        }
        else{
            $count.Text=('Showing: 0 of {0} record(s) | {1}' -f $allRows.Count,$EmptyMessage)
        }
    }

    $grid.Add_CellDoubleClick({
        if($null-eq$grid.CurrentRow){return}
        $lines=@()
        foreach($cell in $grid.CurrentRow.Cells){
            $lines+=('{0}: {1}' -f $grid.Columns[$cell.ColumnIndex].HeaderText,[string]$cell.Value)
        }
        [void][System.Windows.Forms.MessageBox]::Show(($lines-join"`r`n"),'Selected record','OK','Information')
    })

    $layout.Controls.Add($purposeLabel,0,0)

    if($EnableReportFilters){
        $filterPanel=New-Object System.Windows.Forms.FlowLayoutPanel
        $filterPanel.Dock='Fill'
        $filterPanel.WrapContents=$false
        $filterPanel.Padding=New-Object System.Windows.Forms.Padding(10,7,0,0)
        $filterPanel.BackColor=[System.Drawing.Color]::WhiteSmoke

        $eventLabel=New-Object System.Windows.Forms.Label
        $eventLabel.Text='Event ID:'
        $eventLabel.AutoSize=$true
        $eventLabel.Margin=New-Object System.Windows.Forms.Padding(0,7,3,0)
        $eventFilter=New-Object System.Windows.Forms.ComboBox
        $eventFilter.DropDownStyle='DropDownList'
        $eventFilter.Width=180
        [void]$eventFilter.Items.Add('All Events')
        foreach($id in @($allRows|ForEach-Object{$_.EventId}|Where-Object{$_}|Sort-Object -Unique)){
            $eventText=switch([int]$id){4624{'4624 - Successful Logon'}4625{'4625 - Failed Logon'}4740{'4740 - Account Lockout'}4768{'4768 - Kerberos TGT'}4771{'4771 - Kerberos Failure'}4776{'4776 - Credential Validation'}default{[string]$id}}
            [void]$eventFilter.Items.Add($eventText)
        }
        $eventFilter.SelectedIndex=0

        $resultLabel=New-Object System.Windows.Forms.Label
        $resultLabel.Text='Result:'
        $resultLabel.AutoSize=$true
        $resultLabel.Margin=New-Object System.Windows.Forms.Padding(12,7,3,0)
        $resultFilter=New-Object System.Windows.Forms.ComboBox
        $resultFilter.DropDownStyle='DropDownList'
        $resultFilter.Width=100
        [void]$resultFilter.Items.Add('All Results')
        foreach($value in @($allRows|ForEach-Object{$_.Result}|Where-Object{$_}|Sort-Object -Unique)){[void]$resultFilter.Items.Add([string]$value)}
        $resultFilter.SelectedIndex=0

        $logonLabel=New-Object System.Windows.Forms.Label
        $logonLabel.Text='Logon Type:'
        $logonLabel.AutoSize=$true
        $logonLabel.Margin=New-Object System.Windows.Forms.Padding(12,7,3,0)
        $logonFilter=New-Object System.Windows.Forms.ComboBox
        $logonFilter.DropDownStyle='DropDownList'
        $logonFilter.Width=155
        [void]$logonFilter.Items.Add('All Logon Types')
        foreach($value in @($allRows|Where-Object{$_.LogonType -and $_.LogonType-ne'-'}|Sort-Object {[int]$_.LogonType}|ForEach-Object{'{0} - {1}'-f$_.LogonType,$_.LogonTypeName}|Sort-Object -Unique)){[void]$logonFilter.Items.Add([string]$value)}
        $logonFilter.SelectedIndex=0

        $textLabel=New-Object System.Windows.Forms.Label
        $textLabel.Text='Contains:'
        $textLabel.AutoSize=$true
        $textLabel.Margin=New-Object System.Windows.Forms.Padding(12,7,3,0)
        $textFilter=New-Object System.Windows.Forms.TextBox
        $textFilter.Width=130

        $applyFilter=New-Object System.Windows.Forms.Button
        $applyFilter.Text='Apply Filter'
        $applyFilter.Width=88
        $clearFilter=New-Object System.Windows.Forms.Button
        $clearFilter.Text='Clear'
        $clearFilter.Width=65

        $applyAction={
            $selectedEvent=[string]$eventFilter.SelectedItem
            $selectedResult=[string]$resultFilter.SelectedItem
            $selectedLogon=[string]$logonFilter.SelectedItem
            $contains=$textFilter.Text.Trim()
            $filtered=@($allRows|Where-Object{
                $row=$_
                $eventOk=($selectedEvent-eq'All Events'-or [string]$row.EventId-eq(($selectedEvent-split'\s+-\s+')[0]))
                $resultOk=($selectedResult-eq'All Results'-or [string]$row.Result-eq$selectedResult)
                $logonOk=($selectedLogon-eq'All Logon Types'-or [string]$row.LogonType-eq(($selectedLogon-split'\s+-\s+')[0]))
                $textOk=$true
                if(-not[string]::IsNullOrWhiteSpace($contains)){
                    $joined=@($row.PSObject.Properties|ForEach-Object{[string]$_.Value})-join' '
                    $textOk=$joined.IndexOf($contains,[System.StringComparison]::OrdinalIgnoreCase)-ge0
                }
                $eventOk-and$resultOk-and$logonOk-and$textOk
            })
            Update-ReportGrid $filtered
        }

        $applyFilter.Add_Click($applyAction)
        $eventFilter.Add_SelectedIndexChanged($applyAction)
        $resultFilter.Add_SelectedIndexChanged($applyAction)
        $logonFilter.Add_SelectedIndexChanged($applyAction)
        $textFilter.Add_KeyDown({if($_.KeyCode-eq[System.Windows.Forms.Keys]::Enter){$_.SuppressKeyPress=$true;&$applyAction}})
        $clearFilter.Add_Click({
            $eventFilter.SelectedIndex=0
            $resultFilter.SelectedIndex=0
            $logonFilter.SelectedIndex=0
            $textFilter.Clear()
            Update-ReportGrid $allRows
        })

        foreach($control in @($eventLabel,$eventFilter,$resultLabel,$resultFilter,$logonLabel,$logonFilter,$textLabel,$textFilter,$applyFilter,$clearFilter)){
            [void]$filterPanel.Controls.Add($control)
        }
        $layout.Controls.Add($filterPanel,0,1)
        $layout.Controls.Add($grid,0,2)
        $footerRow=3
    }
    else{
        $layout.Controls.Add($grid,0,1)
        $footerRow=2
    }

    $footer=New-Object System.Windows.Forms.FlowLayoutPanel
    $footer.Dock='Fill'
    $footer.FlowDirection='RightToLeft'
    $footer.Padding=New-Object System.Windows.Forms.Padding(8)
    $close=New-Object System.Windows.Forms.Button
    $close.Text='Close'
    $close.Width=90
    $close.Add_Click({$w.Close()})
    $footer.Controls.Add($close)
    $footer.Controls.Add($count)
    $layout.Controls.Add($footer,0,$footerRow)
    $w.Controls.Add($layout)

    Update-ReportGrid $allRows
    [void]$w.ShowDialog($form)
}
function Get-InventorySummary {

    if (-not (Get-Module ActiveDirectory)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    $domain = Get-ADDomain
    $forest = Get-ADForest

    $totalUsers = @(Get-ADUser -Filter *).Count
    $activeUsers = @(Get-ADUser -Filter 'Enabled -eq $true').Count
    $disabledUsers = @(Get-ADUser -Filter 'Enabled -eq $false').Count

    $totalComputers = @(Get-ADComputer -Filter *).Count
    $activeComputers = @(Get-ADComputer -Filter 'Enabled -eq $true').Count
    $disabledComputers = @(Get-ADComputer -Filter 'Enabled -eq $false').Count

    $totalGroups = @(Get-ADGroup -Filter *).Count

    [pscustomobject]@{
        DomainName        = $domain.DNSRoot
        ForestName        = $forest.Name
        PDCEmulator       = $domain.PDCEmulator
        DCCount = @(Get-ADDomainController -Filter *).Count

        TotalUsers        = $totalUsers
        ActiveUsers       = $activeUsers
        DisabledUsers     = $disabledUsers

        TotalComputers    = $totalComputers
        ActiveComputers   = $activeComputers
        DisabledComputers = $disabledComputers

        TotalGroups       = $totalGroups
    }
}
function Format-ReportDate {

    param($Date)

    if ($null -eq $Date) {
        return ''
    }

    try {
        return ([datetime]$Date).ToString('dd/MM/yyyy')
    }
    catch {
        return ''
    }
}
function Get-AccountStatus {
    param($User)

    if($User.Enabled){
        return 'Enabled'
    }

    return 'Disabled'
}
function Get-PasswordStatus {
    param($User)

    if(-not $User.Enabled){
        return 'Disabled Account'
    }

    if($User.PasswordExpired){
        return 'Expired'
    }

    if($User.PasswordNeverExpires){
        return 'Never Expires'
    }

    return 'Active'
}
function Get-PasswordExpiryDate {

    param($User)

    try {

        if ($User.PasswordNeverExpires) {
            return 'Never Expires'
        }

        return ''
    }
    catch {
        return ''
    }
}
function Get-ManagerName {

    param(
        [string]$ManagerDN
    )

    if ($null -eq $ManagerDN -or $ManagerDN -eq '') {
        return ''
    }

    try {

        $manager = Get-ADUser `
            -Identity $ManagerDN `
            -Properties DisplayName `
            -ErrorAction Stop

        return $manager.DisplayName
    }
    catch {
        return ''
    }
}
function Get-AllUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
        -Filter * `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName       = $_.DisplayName
            Name              = $_.Name
            SamAccountName    = $_.SamAccountName
            EmailAddress      = $_.Mail
            EmployeeNumber    = $_.EmployeeNumber

            Department        = $_.Department
            Title             = $_.Title
            Company           = $_.Company
            Manager           = Get-ManagerName $_.Manager
            Office            = $_.Office
            City              = $_.City
            Country           = $_.co

            AccountStatus     = Get-AccountStatus $_
            PasswordStatus    = Get-PasswordStatus $_

            PasswordLastSet   = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate= Get-PasswordExpiryDate $_

            WhenCreated       = Format-ReportDate $_.WhenCreated

            Description       = $_.Description
            DistinguishedName = $_.DistinguishedName
        }
    } |
    Sort-Object DisplayName
}
function Get-AllManagersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
    -LDAPFilter '(directReports=*)' `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName       = $_.DisplayName
            Name              = $_.Name
            SamAccountName    = $_.SamAccountName
            EmailAddress      = $_.Mail
            EmployeeNumber    = $_.EmployeeNumber

            Department        = $_.Department
            Title             = $_.Title
            Company           = $_.Company
            Manager           = Get-ManagerName $_.Manager
            Office            = $_.Office
            City              = $_.City
            Country           = $_.co

            AccountStatus     = Get-AccountStatus $_
            PasswordStatus    = Get-PasswordStatus $_

            PasswordLastSet   = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate= Get-PasswordExpiryDate $_

            WhenCreated       = Format-ReportDate $_.WhenCreated

            Description       = $_.Description
            DistinguishedName = $_.DistinguishedName
        }
    } |
    Sort-Object DisplayName
}
function Get-UsersWithoutManagerReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
    -LDAPFilter '(!(manager=*))' `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName       = $_.DisplayName
            Name              = $_.Name
            SamAccountName    = $_.SamAccountName
            EmailAddress      = $_.Mail
            EmployeeNumber    = $_.EmployeeNumber

            Department        = $_.Department
            Title             = $_.Title
            Company           = $_.Company
            Manager           = Get-ManagerName $_.Manager
            Office            = $_.Office
            City              = $_.City
            Country           = $_.co

            AccountStatus     = Get-AccountStatus $_
            PasswordStatus    = Get-PasswordStatus $_

            PasswordLastSet   = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate= Get-PasswordExpiryDate $_

            WhenCreated       = Format-ReportDate $_.WhenCreated

            Description       = $_.Description
            DistinguishedName = $_.DistinguishedName
        }
    } |
    Sort-Object DisplayName
}
function Get-EnabledUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
        -Filter 'Enabled -eq $true' `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName        = $_.DisplayName
            Name               = $_.Name
            SamAccountName     = $_.SamAccountName
            EmailAddress       = $_.Mail
            EmployeeNumber     = $_.EmployeeNumber

            Department         = $_.Department
            Title              = $_.Title
            Company            = $_.Company

            Manager            = Get-ManagerName $_.Manager

            Office             = $_.Office
            City               = $_.City
            Country            = $_.co

            AccountStatus      = Get-AccountStatus $_
            PasswordStatus     = Get-PasswordStatus $_

            PasswordLastSet    = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate = Get-PasswordExpiryDate $_

            WhenCreated        = Format-ReportDate $_.WhenCreated

            Description        = $_.Description
            DistinguishedName  = $_.DistinguishedName
        }

    } |
    Sort-Object DisplayName

}
function Get-DisabledUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
        -Filter 'Enabled -eq $false' `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName        = $_.DisplayName
            Name               = $_.Name
            SamAccountName     = $_.SamAccountName
            EmailAddress       = $_.Mail
            EmployeeNumber     = $_.EmployeeNumber

            Department         = $_.Department
            Title              = $_.Title
            Company            = $_.Company

            Manager            = Get-ManagerName $_.Manager

            Office             = $_.Office
            City               = $_.City
            Country            = $_.co

            AccountStatus      = Get-AccountStatus $_
            PasswordStatus     = Get-PasswordStatus $_

            PasswordLastSet    = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate = Get-PasswordExpiryDate $_

            WhenCreated        = Format-ReportDate $_.WhenCreated

            Description        = $_.Description
            DistinguishedName  = $_.DistinguishedName
        }

    } |
    Sort-Object DisplayName

}
function Get-AccountExpiredUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
        -Filter * `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated,
            AccountExpirationDate |

       Where-Object {
            $_.AccountExpirationDate -and
            $_.AccountExpirationDate -lt (Get-Date)
     } |
    ForEach-Object {

        [pscustomobject]@{

            DisplayName        = $_.DisplayName
            Name               = $_.Name
            SamAccountName     = $_.SamAccountName
            EmailAddress       = $_.Mail
            EmployeeNumber     = $_.EmployeeNumber

            Department         = $_.Department
            Title              = $_.Title
            Company            = $_.Company

            Manager            = Get-ManagerName $_.Manager

            Office             = $_.Office
            City               = $_.City
            Country            = $_.co

            AccountStatus      = Get-AccountStatus $_
            PasswordStatus     = Get-PasswordStatus $_

            PasswordLastSet    = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate = Get-PasswordExpiryDate $_
            AccountExpiryDate = Format-ReportDate $_.AccountExpirationDate

            WhenCreated        = Format-ReportDate $_.WhenCreated

            Description        = $_.Description
            DistinguishedName  = $_.DistinguishedName
        }

    } |
    Sort-Object DisplayName

}
function Get-NeverLoggedOnUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
        -Filter * `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated,
            AccountExpirationDate,
            LastLogonDate,
            LastLogonTimestamp |

    Where-Object {
    $null -eq $_.LastLogonDate
} |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName        = $_.DisplayName
            Name               = $_.Name
            SamAccountName     = $_.SamAccountName
            EmailAddress       = $_.Mail
            EmployeeNumber     = $_.EmployeeNumber

            Department         = $_.Department
            Title              = $_.Title
            Company            = $_.Company

            Manager            = Get-ManagerName $_.Manager

            Office             = $_.Office
            City               = $_.City
            Country            = $_.co

            AccountStatus      = Get-AccountStatus $_
            PasswordStatus     = Get-PasswordStatus $_

            PasswordLastSet    = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate = Get-PasswordExpiryDate $_
            AccountExpiryDate = Format-ReportDate $_.AccountExpirationDate
            LastLogonDate =  Format-ReportDate $_.LastLogonDate

            WhenCreated        = Format-ReportDate $_.WhenCreated

            Description        = $_.Description
            DistinguishedName  = $_.DistinguishedName
        }

    } |
    Sort-Object DisplayName

}
function Get-InactiveUsersRealLastLogonReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    #
    # Discover all domain controllers
    #

    $DomainControllers = @(
        Get-ADDomainController -Filter * -ErrorAction Stop |
            Sort-Object HostName
    )

    if ($DomainControllers.Count -eq 0) {
        throw 'No domain controllers were found.'
    }

    #
    # Use the first discovered DC for replicated user properties
    #

    $ReferenceDC = [string]$DomainControllers[0].HostName

    $UserProperties = @(
        'DisplayName'
        'Mail'
        'EmployeeNumber'
        'Department'
        'Title'
        'Company'
        'Manager'
        'Office'
        'City'
        'co'
        'Description'
        'DistinguishedName'
        'Enabled'
        'PasswordLastSet'
        'PasswordNeverExpires'
        'PasswordExpired'
        'WhenCreated'
        'AccountExpirationDate'
        'LastLogonDate'
    )

    $Users = @(
        Get-ADUser `
            -Server $ReferenceDC `
            -Filter * `
            -Properties $UserProperties `
            -ErrorAction Stop
    )

    #
    # Lookup table containing the greatest lastLogon value
    # found for each user across every reachable DC
    #

    $LastLogonMap = @{}

    foreach ($User in $Users) {

        $UserKey = $User.ObjectGUID.ToString()

        $LastLogonMap[$UserKey] = @{
            LastLogonValue   = [int64]0
            DomainController = ''
        }
    }

    $FailedDomainControllers = New-Object `
        'System.Collections.Generic.List[string]'

    #
    # Query every DC once
    #

    foreach ($DC in $DomainControllers) {

        $Server = [string]$DC.HostName

        try {

            $DCUsers = @(
                Get-ADUser `
                    -Server $Server `
                    -Filter * `
                    -Properties LastLogon `
                    -ErrorAction Stop
            )

            foreach ($DCUser in $DCUsers) {

                $UserKey = $DCUser.ObjectGUID.ToString()
                $CurrentLastLogon = [int64]$DCUser.LastLogon

                if (
                    $LastLogonMap.ContainsKey($UserKey) -and
                    $CurrentLastLogon -gt
                        [int64]$LastLogonMap[$UserKey].LastLogonValue
                ) {
                    $LastLogonMap[$UserKey].LastLogonValue =
                        $CurrentLastLogon

                    $LastLogonMap[$UserKey].DomainController =
                        $Server
                }
            }
        }
        catch {

            [void]$FailedDomainControllers.Add($Server)
        }
    }

    #
    # Save DC warnings so the Run Report handler can display them
    #

    $script:RealLastLogonFailedDCs = @(
        $FailedDomainControllers.ToArray()
    )

    #
    # Build report rows
    #

    $Results = foreach ($User in $Users) {

        $UserKey = $User.ObjectGUID.ToString()

        $RawRealLastLogon = [int64]0
        $RealLastLogon = ''
        $RealLastLogonDC = ''

        if ($LastLogonMap.ContainsKey($UserKey)) {

            $RawRealLastLogon = $LastLogonMap[$UserKey].LastLogonValue
            

            $RealLastLogonDC = $LastLogonMap[$UserKey].DomainController
            
        }

        if ($RawRealLastLogon -gt 0) {

            $ConvertedLastLogon =
                [System.DateTime]::FromFileTimeUtc(
                    $RawRealLastLogon
                ).ToLocalTime()

            $RealLastLogon =
                $ConvertedLastLogon.ToString('dd/MM/yyyy')
        }
        else {
            $RealLastLogon = 'Never'
        }
        if ($RawRealLastLogon -eq 0) {
    continue
}

$ConvertedLastLogon =
    [System.DateTime]::FromFileTimeUtc(
        $RawRealLastLogon
    ).ToLocalTime()

if ($ConvertedLastLogon -gt (Get-Date).AddDays(-90)) {
    continue
}
        [pscustomobject][ordered]@{

            DisplayName         = [string]$User.DisplayName
            Name                = [string]$User.Name
            SamAccountName      = [string]$User.SamAccountName
            EmailAddress        = [string]$User.Mail
            EmployeeNumber      = [string]$User.EmployeeNumber

            Department          = [string]$User.Department
            Title               = [string]$User.Title
            Company             = [string]$User.Company
            Manager             = Get-ManagerName $User.Manager
            Office              = [string]$User.Office
            City                = [string]$User.City
            Country             = [string]$User.co

            AccountStatus       = Get-AccountStatus $User
            PasswordStatus      = Get-PasswordStatus $User

            PasswordLastSet     =
                Format-ReportDate $User.PasswordLastSet

            PasswordExpiryDate  =
                Get-PasswordExpiryDate $User

            AccountExpiryDate   =
                Format-ReportDate $User.AccountExpirationDate

            LastLogonDate       =
                Format-ReportDate $User.LastLogonDate

            RealLastLogon       = $RealLastLogon
            RealLastLogonDC     = $RealLastLogonDC

            WhenCreated         =
                Format-ReportDate $User.WhenCreated

            Description         = [string]$User.Description
            DistinguishedName   =
                [string]$User.DistinguishedName
        }
    }

    return @(
        $Results |
            Sort-Object DisplayName
    )
}
function Get-RealLastLogonReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    #
    # Discover all domain controllers
    #

    $DomainControllers = @(
        Get-ADDomainController -Filter * -ErrorAction Stop |
            Sort-Object HostName
    )

    if ($DomainControllers.Count -eq 0) {
        throw 'No domain controllers were found.'
    }

    #
    # Use the first discovered DC for replicated user properties
    #

    $ReferenceDC = [string]$DomainControllers[0].HostName

    $UserProperties = @(
        'DisplayName'
        'Mail'
        'EmployeeNumber'
        'Department'
        'Title'
        'Company'
        'Manager'
        'Office'
        'City'
        'co'
        'Description'
        'DistinguishedName'
        'Enabled'
        'PasswordLastSet'
        'PasswordNeverExpires'
        'PasswordExpired'
        'WhenCreated'
        'AccountExpirationDate'
        'LastLogonDate'
    )

    $Users = @(
        Get-ADUser `
            -Server $ReferenceDC `
            -Filter * `
            -Properties $UserProperties `
            -ErrorAction Stop
    )

    #
    # Lookup table containing the greatest lastLogon value
    # found for each user across every reachable DC
    #

    $LastLogonMap = @{}

    foreach ($User in $Users) {

        $UserKey = $User.ObjectGUID.ToString()

        $LastLogonMap[$UserKey] = @{
            LastLogonValue   = [int64]0
            DomainController = ''
        }
    }

    $FailedDomainControllers = New-Object `
        'System.Collections.Generic.List[string]'

    #
    # Query every DC once
    #

    foreach ($DC in $DomainControllers) {

        $Server = [string]$DC.HostName

        try {

            $DCUsers = @(
                Get-ADUser `
                    -Server $Server `
                    -Filter * `
                    -Properties LastLogon `
                    -ErrorAction Stop
            )

            foreach ($DCUser in $DCUsers) {

                $UserKey = $DCUser.ObjectGUID.ToString()
                $CurrentLastLogon = [int64]$DCUser.LastLogon

                if (
                    $LastLogonMap.ContainsKey($UserKey) -and
                    $CurrentLastLogon -gt
                        [int64]$LastLogonMap[$UserKey].LastLogonValue
                ) {
                    $LastLogonMap[$UserKey].LastLogonValue =
                        $CurrentLastLogon

                    $LastLogonMap[$UserKey].DomainController =
                        $Server
                }
            }
        }
        catch {

            [void]$FailedDomainControllers.Add($Server)
        }
    }

    #
    # Save DC warnings so the Run Report handler can display them
    #

    $script:RealLastLogonFailedDCs = @(
        $FailedDomainControllers.ToArray()
    )

    #
    # Build report rows
    #

    $Results = foreach ($User in $Users) {

        $UserKey = $User.ObjectGUID.ToString()

        $RawRealLastLogon = [int64]0
        $RealLastLogon = ''
        $RealLastLogonDC = ''

        if ($LastLogonMap.ContainsKey($UserKey)) {

            $RawRealLastLogon = $LastLogonMap[$UserKey].LastLogonValue
            

            $RealLastLogonDC = $LastLogonMap[$UserKey].DomainController
            
        }

        if ($RawRealLastLogon -gt 0) {

            $ConvertedLastLogon =
                [System.DateTime]::FromFileTimeUtc(
                    $RawRealLastLogon
                ).ToLocalTime()

            $RealLastLogon =
                $ConvertedLastLogon.ToString('dd/MM/yyyy')
        }
        else {
            $RealLastLogon = 'Never'
        }

        [pscustomobject][ordered]@{

            DisplayName         = [string]$User.DisplayName
            Name                = [string]$User.Name
            SamAccountName      = [string]$User.SamAccountName
            EmailAddress        = [string]$User.Mail
            EmployeeNumber      = [string]$User.EmployeeNumber

            Department          = [string]$User.Department
            Title               = [string]$User.Title
            Company             = [string]$User.Company
            Manager             = Get-ManagerName $User.Manager
            Office              = [string]$User.Office
            City                = [string]$User.City
            Country             = [string]$User.co

            AccountStatus       = Get-AccountStatus $User
            PasswordStatus      = Get-PasswordStatus $User

            PasswordLastSet     =
                Format-ReportDate $User.PasswordLastSet

            PasswordExpiryDate  =
                Get-PasswordExpiryDate $User

            AccountExpiryDate   =
                Format-ReportDate $User.AccountExpirationDate

            LastLogonDate       =
                Format-ReportDate $User.LastLogonDate

            RealLastLogon       = $RealLastLogon
            RealLastLogonDC     = $RealLastLogonDC

            WhenCreated         =
                Format-ReportDate $User.WhenCreated

            Description         = [string]$User.Description
            DistinguishedName   =
                [string]$User.DistinguishedName
        }
    }

    return @(
        $Results |
            Sort-Object DisplayName
    )
}

function Get-PasswordNeverExpiresReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
    -Filter * `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    Where-Object {
    $_.PasswordNeverExpires -eq $true
    } |
    ForEach-Object {

        [pscustomobject]@{

            DisplayName        = $_.DisplayName
            Name               = $_.Name
            SamAccountName     = $_.SamAccountName
            EmailAddress       = $_.Mail
            EmployeeNumber     = $_.EmployeeNumber

            Department         = $_.Department
            Title              = $_.Title
            Company            = $_.Company

            Manager            = Get-ManagerName $_.Manager

            Office             = $_.Office
            City               = $_.City
            Country            = $_.co

            AccountStatus      = Get-AccountStatus $_
            PasswordStatus     = Get-PasswordStatus $_

            PasswordLastSet    = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate = Get-PasswordExpiryDate $_

            WhenCreated        = Format-ReportDate $_.WhenCreated

            Description        = $_.Description
            DistinguishedName  = $_.DistinguishedName
        }

    } |
    Sort-Object DisplayName

}

function Get-PasswordExpiredUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
    -Filter * `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |
    
    Where-Object {
    $_.PasswordExpired -eq $true
    } |
    ForEach-Object {

        [pscustomobject]@{

            DisplayName        = $_.DisplayName
            Name               = $_.Name
            SamAccountName     = $_.SamAccountName
            EmailAddress       = $_.Mail
            EmployeeNumber     = $_.EmployeeNumber

            Department         = $_.Department
            Title              = $_.Title
            Company            = $_.Company

            Manager            = Get-ManagerName $_.Manager

            Office             = $_.Office
            City               = $_.City
            Country            = $_.co

            AccountStatus      = Get-AccountStatus $_
            PasswordStatus     = Get-PasswordStatus $_

            PasswordLastSet    = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate = Get-PasswordExpiryDate $_

            WhenCreated        = Format-ReportDate $_.WhenCreated

            Description        = $_.Description
            DistinguishedName  = $_.DistinguishedName
        }

    } |
    Sort-Object DisplayName

}

function Get-RecentlyCreatedUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
        -Filter * `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |
    Where-Object {
    $_.WhenCreated -ge (Get-Date).AddDays(-30)
    } |
    ForEach-Object {

        [pscustomobject]@{

            DisplayName       = $_.DisplayName
            Name              = $_.Name
            SamAccountName    = $_.SamAccountName
            EmailAddress      = $_.Mail
            EmployeeNumber    = $_.EmployeeNumber

            Department        = $_.Department
            Title             = $_.Title
            Company           = $_.Company
            Manager           = Get-ManagerName $_.Manager
            Office            = $_.Office
            City              = $_.City
            Country           = $_.co

            AccountStatus     = Get-AccountStatus $_
            PasswordStatus    = Get-PasswordStatus $_

            PasswordLastSet   = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate= Get-PasswordExpiryDate $_

            WhenCreated       = Format-ReportDate $_.WhenCreated

            Description       = $_.Description
            DistinguishedName = $_.DistinguishedName
        }
    } |
    Sort-Object DisplayName
}

function Get-RecentlyDeletedUsersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    $cutoffDate = (Get-Date).AddDays(-30)

    $deletedUsers = @(
        Get-ADObject `
            -IncludeDeletedObjects `
            -Filter 'isDeleted -eq $true -and objectClass -eq "user"' `
            -Properties `
                msDS-LastKnownRDN,
                lastKnownParent,
                whenChanged,
                whenCreated,
                sAMAccountName,
                displayName,
                mail,
                description `
            -ErrorAction Stop
    )

    $results = foreach ($user in $deletedUsers) {

        #
        # whenChanged on the deleted object is used here
        # as the deletion/change timestamp for this report.
        #

        if (
            $null -eq $user.whenChanged -or
            $user.whenChanged -lt $cutoffDate
        ) {
            continue
        }

        #
        # Deleted objects may not retain every normal
        # AD user property, so unavailable fields remain blank.
        #

        $displayName = $user.displayName

        if ([string]::IsNullOrWhiteSpace($displayName)) {
            $displayName = $user.'msDS-LastKnownRDN'
        }

        [pscustomobject][ordered]@{

            DisplayName        = $displayName
            Name               = $user.'msDS-LastKnownRDN'
            SamAccountName     = $user.sAMAccountName
            EmailAddress       = $user.mail
            EmployeeNumber     = ''

            Department         = ''
            Title              = ''
            Company            = ''
            Manager            = ''
            Office             = ''
            City               = ''
            Country            = ''

            AccountStatus      = 'Deleted'
            PasswordStatus     = ''

            PasswordLastSet    = ''
            PasswordExpiryDate = ''
            AccountExpiryDate  = ''

            LastLogonDate      = ''
            RealLastLogon      = ''
            RealLastLogonDC    = ''

            WhenCreated        =
                Format-ReportDate $user.whenCreated

            DeletedDate        =
                Format-ReportDate $user.whenChanged

            LastKnownParent    =
                $user.lastKnownParent

            Description        =
                $user.description

            DistinguishedName  =
                $user.DistinguishedName
        }
    }

    return @(
        $results |
            Sort-Object DeletedDate -Descending
    )
}
function Get-LogonFailureReason {

    param(
        [string]$Status,
        [string]$SubStatus
    )

    $code = $SubStatus

    if (
        [string]::IsNullOrWhiteSpace($code) -or
        $code -eq '0x0'
    ) {
        $code = $Status
    }

    switch ($code.ToLower()) {

        '0xc0000064' { return 'User name does not exist' }
        '0xc000006a' { return 'Incorrect password' }
        '0xc0000234' { return 'Account locked out' }
        '0xc0000072' { return 'Account disabled' }
        '0xc000006f' { return 'Logon outside permitted hours' }
        '0xc0000070' { return 'Workstation restriction' }
        '0xc0000193' { return 'Account expired' }
        '0xc0000071' { return 'Password expired' }
        '0xc0000133' { return 'Clock synchronization problem' }
        '0xc0000224' { return 'change required' }
        '0xc000015b' { return 'Requested logon type not granted' }

        default {
            return "Status: $Status / SubStatus: $SubStatus"
        }
    }
}
function Get-LogonTypeName {

    param(
        [string]$LogonType
    )

    switch ($LogonType) {

        '2'  { return '2 - Interactive' }
        '3'  { return '3 - Network' }
        '4'  { return '4 - Batch' }
        '5'  { return '5 - Service' }
        '7'  { return '7 - Unlock' }
        '8'  { return '8 - Network Cleartext' }
        '9'  { return '9 - New Credentials' }
        '10' { return '10 - Remote Interactive' }
        '11' { return '11 - Cached Interactive' }

        default {
            return $LogonType
        }
    }
}

function Get-RecentLogonFailuresReport {

    $startTime = (Get-Date).AddHours(-24)

    $DCs = @(
        Get-ADDomainController -Filter * |
            Sort-Object HostName
    )

    $results = foreach ($DC in $DCs) {

        try {

            $events = Get-WinEvent `
                -ComputerName $DC.HostName `
                -FilterHashtable @{
                    LogName   = 'Security'
                    Id        = 4625
                    StartTime = $startTime
                } `
                -ErrorAction Stop

            foreach ($event in $events) {

                try {

                    [xml]$xml = $event.ToXml()

                    $eventData = @{}

                    foreach ($data in $xml.Event.EventData.Data) {

                        $eventData[
                            [string]$data.Name
                        ] = [string]$data.'#text'
                    }

                    [pscustomobject][ordered]@{

                        DisplayName =
                            $eventData['TargetUserName']

                        Name =
                            $eventData['TargetUserName']

                        SamAccountName =
                            $eventData['TargetUserName']

                        EmailAddress = ''
                        EmployeeNumber = ''

                        Department = ''
                        Title = ''
                        Company = ''
                        Manager = ''
                        Office = ''
                        City = ''
                        Country = ''

                        AccountStatus = ''
                        PasswordStatus = ''

                        PasswordLastSet = ''
                        PasswordExpiryDate = ''
                        AccountExpiryDate = ''

                        LastLogonDate = ''
                        RealLastLogon = ''
                        RealLastLogonDC = ''

                        WhenCreated = ''
                        DeletedDate = ''
                        LastKnownParent = ''

                        FailureTime =
                            $event.TimeCreated.ToString(
                                'dd/MM/yyyy HH:mm:ss'
                            )

                        FailureReason =
    Get-LogonFailureReason `
        -Status $eventData['Status'] `
        -SubStatus $eventData['SubStatus']

LogonType =
    Get-LogonTypeName `
        $eventData['LogonType']

                        SourceIP =
                            $eventData['IpAddress']

                        Workstation =
                            $eventData['WorkstationName']

                        DomainController =
                            $DC.HostName

                        Description =
                            (
                                'Status: {0}; SubStatus: {1}' -f
                                $eventData['Status'],
                                $eventData['SubStatus']
                            )

                        DistinguishedName = ''
                    }

                }
                catch {
                }
            }
        }
        catch {

            # Skip DC if Security log cannot be queried.
        }
    }

    return @(
        $results |
            Sort-Object FailureTime -Descending
    )
}
function Show-GroupNameDialog {

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Group Members'
    $form.Width = 430
    $form.Height = 165
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Group Name:'
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(15,20)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Width = 280
    $textBox.Location = New-Object System.Drawing.Point(105,17)

    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Text = 'Run'
    $btnRun.Width = 80
    $btnRun.Location = New-Object System.Drawing.Point(215,65)
    $btnRun.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Width = 80
    $btnCancel.Location = New-Object System.Drawing.Point(305,65)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.Controls.Add($label)
    $form.Controls.Add($textBox)
    $form.Controls.Add($btnRun)
    $form.Controls.Add($btnCancel)

    $form.AcceptButton = $btnRun
    $form.CancelButton = $btnCancel

    $result = $form.ShowDialog()

    if (
        $result -eq [System.Windows.Forms.DialogResult]::OK -and
        -not [string]::IsNullOrWhiteSpace($textBox.Text)
    ) {
        return $textBox.Text.Trim()
    }

    return $null
}

function Get-UserGroupMembersReport {

    param(
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    $group = Get-ADGroup `
        -Identity $GroupName `
        -ErrorAction Stop

    $members = @(
        Get-ADGroupMember `
            -Identity $group `
            -ErrorAction Stop
    )

    $results = foreach ($member in $members) {

        $displayName = $member.Name
        $email = ''
        $department = ''
        $title = ''
        $accountStatus = ''

        if ($member.ObjectClass -eq 'user') {

            try {

                $user = Get-ADUser `
                    -Identity $member.DistinguishedName `
                    -Properties `
                        DisplayName,
                        Mail,
                        Department,
                        Title,
                        Enabled `
                    -ErrorAction Stop

                $displayName = $user.DisplayName
                $email = $user.Mail
                $department = $user.Department
                $title = $user.Title

                if ($user.Enabled) {
                    $accountStatus = 'Enabled'
                }
                else {
                    $accountStatus = 'Disabled'
                }
            }
            catch {
            }
        }

        [pscustomobject][ordered]@{

            GroupName          = $group.Name
            ObjectType        = $member.ObjectClass

            DisplayName       = $displayName
            Name              = $member.Name
            SamAccountName    = $member.SamAccountName
            EmailAddress      = $email

            Department        = $department
            Title             = $title
            AccountStatus     = $accountStatus

            DistinguishedName = $member.DistinguishedName
        }
    }

    return @(
        $results |
            Sort-Object ObjectType, DisplayName
    )
}
function Get-GroupsWithoutMembersReport {

    Import-Module ActiveDirectory -ErrorAction Stop

    $groups = @(
        Get-ADGroup `
            -Filter * `
            -Properties `
                Member,
                PrimaryGroupToken,
                Description `
            -ErrorAction Stop
    )

    $results = foreach ($group in $groups) {

        #
        # Normal direct members
        #
        $directMemberCount = @($group.Member).Count

        if ($directMemberCount -gt 0) {
            continue
        }

        #
        # Check Primary Group membership
        #
        $primaryGroupMember = $null

        if ($null -ne $group.PrimaryGroupToken) {

            try {

                $primaryGroupMember = Get-ADUser `
                    -Filter "PrimaryGroupID -eq $($group.PrimaryGroupToken)" `
                    -ResultSetSize 1 `
                    -ErrorAction Stop

            }
            catch {
                $primaryGroupMember = $null
            }
        }

        #
        # Primary-group member exists
        # so this group is NOT empty
        #
        if ($null -ne $primaryGroupMember) {
            continue
        }

        #
        # Truly empty group
        #
        [pscustomobject][ordered]@{

            GroupName          = $group.Name
            DisplayName       = $group.Name
            Name              = $group.Name
            SamAccountName    = $group.SamAccountName

            ObjectType        = 'Group'

            GroupScope        = $group.GroupScope
            GroupCategory     = $group.GroupCategory

            Description       = $group.Description
            DistinguishedName = $group.DistinguishedName
        }
    }

    return @(
        $results |
            Sort-Object GroupName
    )
}
function Show-OUSelectionDialog {

    Import-Module ActiveDirectory -ErrorAction Stop

    $OUs = @(
        Get-ADOrganizationalUnit `
            -Filter * `
            -Properties CanonicalName `
            -ErrorAction Stop |
        Sort-Object CanonicalName
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Select Organizational Unit'
    $form.Width = 600
    $form.Height = 180
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Organizational Unit:'
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(15,22)

    $cmbOU = New-Object System.Windows.Forms.ComboBox
    $cmbOU.Location = New-Object System.Drawing.Point(135,18)
    $cmbOU.Width = 430
    $cmbOU.DropDownStyle = 'DropDownList'

    foreach ($OU in $OUs) {

        [void]$cmbOU.Items.Add(
            $OU.CanonicalName
        )
    }

    if ($cmbOU.Items.Count -gt 0) {
        $cmbOU.SelectedIndex = 0
    }

    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Text = 'Run'
    $btnRun.Width = 80
    $btnRun.Location = New-Object System.Drawing.Point(395,70)
    $btnRun.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Width = 80
    $btnCancel.Location = New-Object System.Drawing.Point(485,70)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.Controls.Add($label)
    $form.Controls.Add($cmbOU)
    $form.Controls.Add($btnRun)
    $form.Controls.Add($btnCancel)

    $form.AcceptButton = $btnRun
    $form.CancelButton = $btnCancel

    $result = $form.ShowDialog()

    if (
        $result -ne [System.Windows.Forms.DialogResult]::OK -or
        $cmbOU.SelectedIndex -lt 0
    ) {
        return $null
    }

    return $OUs[$cmbOU.SelectedIndex]
}
function Get-UsersFromOUReport {
param(
        [Parameter(Mandatory)]
        [string]$SearchBase
    )
    Import-Module ActiveDirectory -ErrorAction Stop

    Get-ADUser `
    -Filter * `
    -SearchBase $SearchBase `
    -SearchScope Subtree `
        -Properties `
            DisplayName,
            Mail,
            EmployeeNumber,
            Department,
            Title,
            Company,
            Manager,
            Office,
            City,
            co,
            Description,
            DistinguishedName,
            Enabled,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordExpired,
            WhenCreated |

    ForEach-Object {

        [pscustomobject]@{

            DisplayName       = $_.DisplayName
            Name              = $_.Name
            SamAccountName    = $_.SamAccountName
            EmailAddress      = $_.Mail
            EmployeeNumber    = $_.EmployeeNumber

            Department        = $_.Department
            Title             = $_.Title
            Company           = $_.Company
            Manager           = Get-ManagerName $_.Manager
            Office            = $_.Office
            City              = $_.City
            Country           = $_.co

            AccountStatus     = Get-AccountStatus $_
            PasswordStatus    = Get-PasswordStatus $_
            AccountExpiryDate  = Format-ReportDate $_.AccountExpirationDate
            LastLogonDate      = Format-ReportDate $_.LastLogonDate

            PasswordLastSet   = Format-ReportDate $_.PasswordLastSet
            PasswordExpiryDate= Get-PasswordExpiryDate $_

            WhenCreated       = Format-ReportDate $_.WhenCreated

            Description       = $_.Description
            DistinguishedName = $_.DistinguishedName
        }
    } |
    Sort-Object DisplayName
}
function Show-InventoryWindow {

    #
    # Prevent multiple Inventory windows
    #

    if (
        $null -ne $script:InventoryForm -and
        -not $script:InventoryForm.IsDisposed
    ) {
        $script:InventoryForm.Activate()
        return
    }

    #
    # Inventory form
    #

    $w = New-Object System.Windows.Forms.Form
    $script:InventoryForm = $w

    $w.Text = 'Active Directory Inventory'
    $w.StartPosition = 'CenterParent'
    $w.Size = New-Object System.Drawing.Size(1220,760)
    $w.MinimumSize = New-Object System.Drawing.Size(1050,650)
    $w.Font = New-Object System.Drawing.Font('Segoe UI',9)
    $w.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    #
    # Modern-style tabs
    #

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $tabs.Appearance = 'Buttons'
    $tabs.SizeMode = 'Fixed'
    $tabs.ItemSize = New-Object System.Drawing.Size(145,38)
    $tabs.Font = New-Object System.Drawing.Font(
        'Segoe UI',
        10,
        [System.Drawing.FontStyle]::Bold
    )

    $tabSummary = New-Object System.Windows.Forms.TabPage
    $tabSummary.Text = 'OVERVIEW'
    $tabSummary.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    $tabUsers = New-Object System.Windows.Forms.TabPage
    $tabUsers.Text = 'Users'
    $tabUsers.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    $tabComputers = New-Object System.Windows.Forms.TabPage
    $tabComputers.Text = 'Computers'
    $tabComputers.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    $tabGroups = New-Object System.Windows.Forms.TabPage
    $tabGroups.Text = 'Groups'
    $tabGroups.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    $tabDCHealth = New-Object System.Windows.Forms.TabPage
    $tabDCHealth.Text = 'DC Health'
    $tabDCHealth.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    [void]$tabs.TabPages.Add($tabSummary)
    [void]$tabs.TabPages.Add($tabUsers)
    [void]$tabs.TabPages.Add($tabComputers)
    [void]$tabs.TabPages.Add($tabGroups)
    [void]$tabs.TabPages.Add($tabDCHealth)

    #
    # Compact inventory-card creator
    #

  $newInventoryCard = {
    param(
        [string]$Title,
        [System.Drawing.Color]$AccentColor
    )

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Width = 200
    $panel.Height = 80
    $panel.Margin = New-Object System.Windows.Forms.Padding(8)
    $panel.BackColor = [System.Drawing.Color]::White
    $panel.BorderStyle = 'None'

    #
    # Statistic title
    #

    $caption = New-Object System.Windows.Forms.Label
    $caption.Text = $Title
    $caption.Left = 0
    $caption.Top = 7
    $caption.Width = $panel.Width
    $caption.Height = 20
    $caption.AutoSize = $false
    $caption.TextAlign = 'MiddleCenter'
    $caption.ForeColor = [System.Drawing.Color]::DimGray

    $caption.Font = New-Object System.Drawing.Font(
        'Segoe UI',
        9,
        [System.Drawing.FontStyle]::Bold
    )

    #
    # Statistic count
    #

    $value = New-Object System.Windows.Forms.Label
    $value.Text = '-'
    $value.Left = 0
    $value.Top = 28
    $value.Width = $panel.Width
    $value.Height = 40
    $value.AutoSize = $false
    $value.TextAlign = 'MiddleCenter'
    $value.ForeColor = $AccentColor

    $value.Font = New-Object System.Drawing.Font(
        'Segoe UI',
        22,
        [System.Drawing.FontStyle]::Bold
    )

    $panel.Controls.Add($caption)
    $panel.Controls.Add($value)

    [pscustomobject]@{
        Panel   = $panel
        Value   = $value
        Caption = $caption
    }
}
#
# Directory information card creator
#

$newDirectoryCard = {
    param(
        [string]$Title
    )

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = 'Fill'
    $panel.Margin = New-Object System.Windows.Forms.Padding(6)
    $panel.BackColor = [System.Drawing.Color]::White
    $panel.BorderStyle = 'None'

    #
    # Internal layout prevents title/value overlap
    #

    $cardLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $cardLayout.Dock = 'Fill'
    $cardLayout.ColumnCount = 1
    $cardLayout.RowCount = 2
    $cardLayout.Margin = New-Object System.Windows.Forms.Padding(0)
    $cardLayout.Padding = New-Object System.Windows.Forms.Padding(4)

    Add-RowStyle $cardLayout 'Absolute' 28
    Add-RowStyle $cardLayout 'Percent' 100

    #
    # Directory field title
    #

    $caption = New-Object System.Windows.Forms.Label
    $caption.Text = $Title
    $caption.Dock = 'Fill'
    $caption.AutoSize = $false
    $caption.TextAlign = 'MiddleCenter'
    $caption.ForeColor = [System.Drawing.Color]::DimGray
    $caption.Margin = New-Object System.Windows.Forms.Padding(0)

    $caption.Font = New-Object System.Drawing.Font(
        'Segoe UI',
        9,
        [System.Drawing.FontStyle]::Bold
    )

    #
    # Directory field value
    #

    $value = New-Object System.Windows.Forms.Label
    $value.Text = 'Not Loaded'
    $value.Dock = 'Fill'
    $value.AutoSize = $false
    $value.TextAlign = 'MiddleCenter'
    $value.AutoEllipsis = $true
    $value.Margin = New-Object System.Windows.Forms.Padding(2,0,2,2)
    $value.ForeColor = [System.Drawing.Color]::FromArgb(
        0,
        120,
        212
    )

    $value.Font = New-Object System.Drawing.Font(
        'Segoe UI',
        10,
        [System.Drawing.FontStyle]::Bold
    )

    $cardLayout.Controls.Add($caption,0,0)
    $cardLayout.Controls.Add($value,0,1)
    $panel.Controls.Add($cardLayout)

    [pscustomobject]@{
        Panel   = $panel
        Value   = $value
        Caption = $caption
    }
}

    #
    # Summary root layout
    #

    $summaryRoot = New-Object System.Windows.Forms.TableLayoutPanel
    $summaryRoot.Dock = 'Fill'
    $summaryRoot.RowCount = 6
    $summaryRoot.ColumnCount = 1
    $summaryRoot.Padding = New-Object System.Windows.Forms.Padding(12)

Add-RowStyle $summaryRoot 'Absolute' 80     # Header
Add-RowStyle $summaryRoot 'Absolute' 115    # Directory Overview
Add-RowStyle $summaryRoot 'Absolute' 105    # User Statistics
Add-RowStyle $summaryRoot 'Absolute' 105    # Computer Statistics
Add-RowStyle $summaryRoot 'Absolute' 105    # Group Statistics
Add-RowStyle $summaryRoot 'Percent' 100     # Status footer

    #
    # Summary header
    #

    $summaryHeader = New-Object System.Windows.Forms.Panel
    $summaryHeader.Dock = 'Fill'
    $summaryHeader.BackColor = [System.Drawing.Color]::FromArgb(25,42,65)

    $summaryTitle = New-Object System.Windows.Forms.Label
    $summaryTitle.Text = 'ACTIVE DIRECTORY INVENTORY'
    $summaryTitle.Left = 18
    $summaryTitle.Top = 12
    $summaryTitle.Width = 360
    $summaryTitle.Height = 28
    $summaryTitle.ForeColor = [System.Drawing.Color]::White
    $summaryTitle.Font = New-Object System.Drawing.Font(
        'Segoe UI',
        14,
        [System.Drawing.FontStyle]::Bold
    )

    $summaryDescription = New-Object System.Windows.Forms.Label
    $summaryDescription.Text =
        'Directory information and AD object statistics are collected only when requested.'
    $summaryDescription.Left = 19
    $summaryDescription.Top = 42
    $summaryDescription.Width = 650
    $summaryDescription.Height = 22
    $summaryDescription.ForeColor =
        [System.Drawing.Color]::FromArgb(195,210,225)

$btnFetchInventory = New-Object System.Windows.Forms.Button
$btnFetchInventory.Text = 'Fetch Inventory'
$btnFetchInventory.Width = 140
$btnFetchInventory.Height = 34
$btnFetchInventory.Left = 780
$btnFetchInventory.Top = 20

$btnFetchInventory.BackColor =
    [System.Drawing.Color]::FromArgb(0,120,212)

    $btnFetchInventory.ForeColor = [System.Drawing.Color]::White
    $btnFetchInventory.FlatStyle = 'Flat'
    $btnFetchInventory.FlatAppearance.BorderSize = 0
    $btnFetchInventory.UseVisualStyleBackColor = $false

    $summaryHeader.Controls.Add($summaryTitle)
    $summaryHeader.Controls.Add($summaryDescription)
    $summaryHeader.Controls.Add($btnFetchInventory)
    $btnFetchInventory.BringToFront()
    $summaryRoot.Controls.Add($summaryHeader,0,0)

   
   #
# Directory Overview
#

$directoryGroup = New-Object System.Windows.Forms.GroupBox
$directoryGroup.Text = 'Directory Overview'
$directoryGroup.Dock = 'Fill'
$directoryGroup.BackColor = [System.Drawing.Color]::FromArgb(
    238,
    242,
    247
)

$directoryGroup.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    9,
    [System.Drawing.FontStyle]::Bold
)

#
# Four equal-width columns
#

$directoryLayout = New-Object System.Windows.Forms.TableLayoutPanel
$directoryLayout.Dock = 'Fill'
$directoryLayout.ColumnCount = 4
$directoryLayout.RowCount = 1
$directoryLayout.Padding = New-Object System.Windows.Forms.Padding(5)
$directoryLayout.Margin = New-Object System.Windows.Forms.Padding(0)

1..4 | ForEach-Object {
    Add-ColumnStyle $directoryLayout 'Percent' 25
}

Add-RowStyle $directoryLayout 'Percent' 100

#
# Create Directory cards
#

$dirDomain = & $newDirectoryCard 'Domain Name'
$dirForest = & $newDirectoryCard 'Forest Name'
$dirPDC = & $newDirectoryCard 'PDC Emulator'
$dirDCCount = & $newDirectoryCard 'Domain Controllers'

#
# Add one card per column
#

$directoryLayout.Controls.Add($dirDomain.Panel,0,0)
$directoryLayout.Controls.Add($dirForest.Panel,1,0)
$directoryLayout.Controls.Add($dirPDC.Panel,2,0)
$directoryLayout.Controls.Add($dirDCCount.Panel,3,0)

$directoryGroup.Controls.Add($directoryLayout)
$summaryRoot.Controls.Add($directoryGroup,0,1)

    #
    # User statistics
    #

    $userGroup = New-Object System.Windows.Forms.GroupBox
    $userGroup.Text = 'User Statistics'
    $userGroup.Dock = 'Fill'
    $userGroup.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    $userCards = New-Object System.Windows.Forms.FlowLayoutPanel
    $userCards.Dock = 'Fill'
    $userCards.WrapContents = $false
    $userCards.AutoScroll = $false
    $userCards.Padding = New-Object System.Windows.Forms.Padding(2)

    $uTotal = & $newInventoryCard `
        'Total Users' `
        ([System.Drawing.Color]::FromArgb(0,120,212))

    $uActive = & $newInventoryCard `
        'Active Users' `
        ([System.Drawing.Color]::FromArgb(16,124,16))

    $uDisabled = & $newInventoryCard `
        'Disabled Users' `
        ([System.Drawing.Color]::FromArgb(202,80,16))

    [void]$userCards.Controls.Add($uTotal.Panel)
    [void]$userCards.Controls.Add($uActive.Panel)
    [void]$userCards.Controls.Add($uDisabled.Panel)

    $userGroup.Controls.Add($userCards)
    $summaryRoot.Controls.Add($userGroup,0,2)


$script:ComputerADProperties = @(

    'Name'
    'SamAccountName'
    'CN'

    'DNSHostName'
    'Enabled'
    'IPv4Address'

    'OperatingSystem'
    'OperatingSystemVersion'
    'OperatingSystemServicePack'

    'LastLogonDate'

    'PasswordLastSet'
    'PasswordNeverExpires'
    'msDS-UserPasswordExpiryTimeComputed'

    'ManagedBy'
    'Description'

    'WhenCreated'
    'WhenChanged'

    'CanonicalName'
    'DistinguishedName'
)
function ConvertTo-ComputerReportRow {

    param(
        [Parameter(Mandatory)]
        $Computer
    )

    #
    # Account Status
    #

    $accountStatus = if ($Computer.Enabled) {
        'Enabled'
    }
    else {
        'Disabled'
    }


    #
    # Last Logon Date
    #

    $lastLogonDate = ''

    if ($null -ne $Computer.LastLogonDate) {

        $lastLogonDate =
            $Computer.LastLogonDate.ToString(
                'dd/MM/yyyy'
            )
    }


    #
    # Password Last Set
    #

    $passwordLastSet = ''

    if ($null -ne $Computer.PasswordLastSet) {

        $passwordLastSet =
            $Computer.PasswordLastSet.ToString(
                'dd/MM/yyyy'
            )
    }


    #
    # Password Expiry Date
    #

    $passwordExpiryDate = ''

    $expiryValue =
        $Computer.'msDS-UserPasswordExpiryTimeComputed'

    if ($null -ne $expiryValue) {

        try {

            $expiryValue = [Int64]$expiryValue

            if (
                $expiryValue -gt 0 -and
                $expiryValue -lt [Int64]::MaxValue
            ) {

                $passwordExpiryDate =
                    [DateTime]::FromFileTime(
                        $expiryValue
                    ).ToString('dd/MM/yyyy')
            }
        }
        catch {

            $passwordExpiryDate = ''
        }
    }


    #
    # Created
    #

    $whenCreated = ''

    if ($null -ne $Computer.WhenCreated) {

        $whenCreated =
            $Computer.WhenCreated.ToString(
                'dd/MM/yyyy'
            )
    }


    #
    # Changed
    #

    $whenChanged = ''

    if ($null -ne $Computer.WhenChanged) {

        $whenChanged =
            $Computer.WhenChanged.ToString(
                'dd/MM/yyyy'
            )
    }


    #
    # Return Computer row
    #

    [PSCustomObject]@{

        Name =
            $Computer.Name

        SamAccountName =
            $Computer.SamAccountName

        CN =
            $Computer.CN

        DNSHostName =
            $Computer.DNSHostName

        Enabled =
            [bool]$Computer.Enabled

        AccountStatus =
            $accountStatus

        IPv4Address =
            $Computer.IPv4Address

        OperatingSystem =
            $Computer.OperatingSystem

        OperatingSystemVersion =
            $Computer.OperatingSystemVersion

        OperatingSystemServicePack =
            $Computer.OperatingSystemServicePack

        LastLogonDate =
            $lastLogonDate

        RealLastLogon = ''

        RealLastLogonDC = ''

        PasswordLastSet =
            $passwordLastSet

        PasswordExpiryDate =
            $passwordExpiryDate

        PasswordNeverExpires =
            [bool]$Computer.PasswordNeverExpires

        ManagedBy =
            $Computer.ManagedBy

        Description =
            $Computer.Description

        WhenCreated =
            $whenCreated

        WhenChanged =
            $whenChanged

        CanonicalName =
            $Computer.CanonicalName

        DistinguishedName =
            $Computer.DistinguishedName
    }
}
function Get-AllComputersReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-EnabledComputersReport {

    $computers = @(
        Get-ADComputer `
            -Filter 'Enabled -eq $true' `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-DisabledComputersReport {

    $computers = @(
        Get-ADComputer `
            -Filter 'Enabled -eq $false' `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}

function Get-ComputerRealLastLogonMap {

    #
    # Stores the highest lastLogon value found for each computer
    #

    $lastLogonMap = @{}


    #
    # Get all writable Domain Controllers
    #

    $domainControllers = @(
        Get-ADDomainController `
            -Filter * |
        Where-Object {
            -not $_.IsReadOnly
        } |
        Sort-Object HostName
    )


    if ($domainControllers.Count -eq 0) {

        throw 'No writable domain controllers were found.'
    }


    $reachableDCCount = 0


    #
    # Query every Domain Controller
    #

    foreach ($dc in $domainControllers) {

        try {

            $dcComputers = @(
                Get-ADComputer `
                    -Filter * `
                    -Server $dc.HostName `
                    -Properties lastLogon `
                    -ErrorAction Stop
            )

            $reachableDCCount++


            foreach ($computer in $dcComputers) {

                $distinguishedName =
                    [string]$computer.DistinguishedName

                $lastLogonValue = 0L


                if ($null -ne $computer.lastLogon) {

                    $lastLogonValue =
                        [Int64]$computer.lastLogon
                }


                #
                # Add the first value found
                #

                if (
                    -not $lastLogonMap.ContainsKey(
                        $distinguishedName
                    )
                ) {

                    $lastLogonMap[
                        $distinguishedName
                    ] = [PSCustomObject]@{

                        LastLogonValue =
                            $lastLogonValue

                        DomainController =
                            $dc.HostName
                    }

                    continue
                }


                #
                # Keep the highest lastLogon value
                #

                if (
                    $lastLogonValue -gt
                    $lastLogonMap[
                        $distinguishedName
                    ].LastLogonValue
                ) {

                    $lastLogonMap[
                        $distinguishedName
                    ].LastLogonValue =
                        $lastLogonValue

                    $lastLogonMap[
                        $distinguishedName
                    ].DomainController =
                        $dc.HostName
                }
            }
        }
        catch {

            #
            # Continue if one Domain Controller is unavailable
            #

            Write-Warning (
                'Unable to query Domain Controller {0}: {1}' -f
                $dc.HostName,
                $_.Exception.Message
            )
        }
    }


    if ($reachableDCCount -eq 0) {

        throw (
            'None of the Domain Controllers could be queried ' +
            'for computer lastLogon data.'
        )
    }


    return $lastLogonMap
}
function Set-ComputerRealLastLogon {

    param(
        [Parameter(Mandatory)]
        $Row,

        [Parameter(Mandatory)]
        $Computer,

        [Parameter(Mandatory)]
        [hashtable]$LastLogonMap
    )


    $distinguishedName =
        [string]$Computer.DistinguishedName


    #
    # No entry found
    #

    if (
        -not $LastLogonMap.ContainsKey(
            $distinguishedName
        )
    ) {

        $Row.RealLastLogon = ''
        $Row.RealLastLogonDC = ''

        return
    }


    $lastLogonInformation =
        $LastLogonMap[$distinguishedName]

    $lastLogonValue =
        [Int64]$lastLogonInformation.LastLogonValue


    #
    # Zero means no known last logon
    #

    if ($lastLogonValue -le 0) {

        $Row.RealLastLogon = ''
        $Row.RealLastLogonDC = ''

        return
    }


    try {

        $Row.RealLastLogon =
            [DateTime]::FromFileTime(
                $lastLogonValue
            ).ToString(
                'dd/MM/yyyy HH:mm:ss'
            )

        $Row.RealLastLogonDC =
            $lastLogonInformation.DomainController
    }
    catch {

        $Row.RealLastLogon = ''
        $Row.RealLastLogonDC = ''
    }
}
function Get-ComputerRealLastLogonReport {

    #
    # Collect the highest lastLogon from all reachable DCs
    #

    $lastLogonMap =
        Get-ComputerRealLastLogonMap


    #
    # Get the standard Computer attributes
    #

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )


    $rows = foreach ($computer in $computers) {

        $row =
            ConvertTo-ComputerReportRow `
                -Computer $computer


        Set-ComputerRealLastLogon `
            -Row $row `
            -Computer $computer `
            -LastLogonMap $lastLogonMap


        $row
    }


    return @($rows)
}
function Get-InactiveComputersRealLastLogonReport {

    #
    # Inactivity cutoff
    #

    $cutoffDate =
        (Get-Date).AddDays(-90)


    #
    # Get accurate multi-DC lastLogon values
    #

    $lastLogonMap =
        Get-ComputerRealLastLogonMap


    #
    # Get standard Computer attributes
    #

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )


    $rows = foreach ($computer in $computers) {

        $distinguishedName =
            [string]$computer.DistinguishedName


        if (
            -not $lastLogonMap.ContainsKey(
                $distinguishedName
            )
        ) {

            continue
        }


        $lastLogonInformation =
            $lastLogonMap[$distinguishedName]

        $lastLogonValue =
            [Int64]$lastLogonInformation.LastLogonValue


        #
        # Never logged on, handled by another report
        #

        if ($lastLogonValue -le 0) {
            continue
        }


        try {

            $realLastLogonDate =
                [DateTime]::FromFileTime(
                    $lastLogonValue
                )
        }
        catch {

            continue
        }


        #
        # Skip computers active within the last 90 days
        #

        if ($realLastLogonDate -gt $cutoffDate) {
            continue
        }


        $row =
            ConvertTo-ComputerReportRow `
                -Computer $computer


        $row.RealLastLogon =
            $realLastLogonDate.ToString(
                'dd/MM/yyyy HH:mm:ss'
            )

        $row.RealLastLogonDC =
            $lastLogonInformation.DomainController


        $row
    }


    return @(
        $rows |
        Sort-Object RealLastLogon
    )
}

function Get-ComputersNeverLoggedOnReport {

    #
    # Get multi-DC lastLogon values
    #

    $lastLogonMap =
        Get-ComputerRealLastLogonMap


    #
    # Get standard Computer attributes
    #

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )


    $rows = foreach ($computer in $computers) {

        $distinguishedName =
            [string]$computer.DistinguishedName

        $lastLogonValue = 0L


        if (
            $lastLogonMap.ContainsKey(
                $distinguishedName
            )
        ) {

            $lastLogonValue =
                [Int64]$lastLogonMap[
                    $distinguishedName
                ].LastLogonValue
        }


        #
        # Skip computers that have logged on
        #

        if ($lastLogonValue -gt 0) {
            continue
        }


        $row =
            ConvertTo-ComputerReportRow `
                -Computer $computer


        $row.RealLastLogon = ''
        $row.RealLastLogonDC = ''


        $row
    }


    return @($rows)
}

function Get-RecentlyCreatedComputersReport {

    #
    # Computers created during the last 30 days
    #

    $cutoffDate = (Get-Date).AddDays(-30)


    #
    # Retrieve Computer objects
    #

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {
            $null -ne $_.WhenCreated -and
            $_.WhenCreated -ge $cutoffDate
        } |
        Sort-Object WhenCreated -Descending
    )


    #
    # Convert to standard Computer report rows
    #

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }


    return @($rows)
}
function Get-ComputersByOperatingSystemReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                $_.OperatingSystem
            )
        } |
        Sort-Object `
            OperatingSystem,
            OperatingSystemVersion,
            Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-WindowsServersReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {
            $_.OperatingSystem -like '*Windows Server*'
        } |
        Sort-Object `
            OperatingSystem,
            OperatingSystemVersion,
            Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-WindowsWorkstationsReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {

            -not [string]::IsNullOrWhiteSpace(
                $_.OperatingSystem
            ) -and

            $_.OperatingSystem -like '*Windows*' -and

            $_.OperatingSystem -notlike '*Windows Server*'
        } |
        Sort-Object `
            OperatingSystem,
            OperatingSystemVersion,
            Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-ComputersWithoutOperatingSystemReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {
            [string]::IsNullOrWhiteSpace(
                $_.OperatingSystem
            )
        } |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-ComputersFromOUReport {

    param(
        [Parameter(Mandatory)]
        [string]$SearchBase
    )

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -SearchBase $SearchBase `
            -SearchScope Subtree `
            -Properties $script:ComputerADProperties |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-ManagedComputersReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [string]$_.ManagedBy
            )
        } |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
function Get-ComputersWithoutManagedByReport {

    $computers = @(
        Get-ADComputer `
            -Filter * `
            -Properties $script:ComputerADProperties |
        Where-Object {
            [string]::IsNullOrWhiteSpace(
                [string]$_.ManagedBy
            )
        } |
        Sort-Object Name
    )

    $rows = foreach ($computer in $computers) {

        ConvertTo-ComputerReportRow `
            -Computer $computer
    }

    return @($rows)
}
    #
    # Computer statistics
    #

    $computerGroup = New-Object System.Windows.Forms.GroupBox
    $computerGroup.Text = 'Computer Statistics'
    $computerGroup.Dock = 'Fill'
    $computerGroup.BackColor = [System.Drawing.Color]::FromArgb(238,242,247)

    $computerCards = New-Object System.Windows.Forms.FlowLayoutPanel
    $computerCards.Dock = 'Fill'
    $computerCards.WrapContents = $false
    $computerCards.AutoScroll = $false
    $computerCards.Padding = New-Object System.Windows.Forms.Padding(2)

    $cTotal = & $newInventoryCard `
        'Total Computers' `
        ([System.Drawing.Color]::FromArgb(0,120,212))

    $cActive = & $newInventoryCard `
        'Active Computers' `
        ([System.Drawing.Color]::FromArgb(16,124,16))

    $cDisabled = & $newInventoryCard `
        'Disabled Computers' `
        ([System.Drawing.Color]::FromArgb(202,80,16))

    [void]$computerCards.Controls.Add($cTotal.Panel)
    [void]$computerCards.Controls.Add($cActive.Panel)
    [void]$computerCards.Controls.Add($cDisabled.Panel)

    $computerGroup.Controls.Add($computerCards)
    $summaryRoot.Controls.Add($computerGroup,0,3)

    #
    # Group statistics
    #

    $groupStatsGroup = New-Object System.Windows.Forms.GroupBox
    $groupStatsGroup.Text = 'Group Statistics'
    $groupStatsGroup.Dock = 'Fill'
    $groupStatsGroup.BackColor =
        [System.Drawing.Color]::FromArgb(238,242,247)

    $groupCards = New-Object System.Windows.Forms.FlowLayoutPanel
    $groupCards.Dock = 'Fill'
    $groupCards.WrapContents = $false
    $groupCards.AutoScroll = $false
    $groupCards.Padding = New-Object System.Windows.Forms.Padding(2)

    $gTotal = & $newInventoryCard `
        'Total Groups' `
        ([System.Drawing.Color]::FromArgb(95,45,145))

    [void]$groupCards.Controls.Add($gTotal.Panel)

    $groupStatsGroup.Controls.Add($groupCards)
    $summaryRoot.Controls.Add($groupStatsGroup,0,4)

    #
    # Status footer
    #

    $statusPanel = New-Object System.Windows.Forms.Panel
    $statusPanel.Dock = 'Fill'
    $statusPanel.BackColor = [System.Drawing.Color]::White

    $statusIndicator = New-Object System.Windows.Forms.Panel
    $statusIndicator.Left = 15
    $statusIndicator.Top = 17
    $statusIndicator.Width = 12
    $statusIndicator.Height = 12
    $statusIndicator.BackColor =
        [System.Drawing.Color]::FromArgb(120,120,120)

    $lblInventoryStatus = New-Object System.Windows.Forms.Label
    $lblInventoryStatus.Text = 'Waiting for inventory collection'
    $lblInventoryStatus.Left = 36
    $lblInventoryStatus.Top = 13
    $lblInventoryStatus.Width = 400
    $lblInventoryStatus.Height = 22
    $lblInventoryStatus.Font =
        New-Object System.Drawing.Font('Segoe UI',9)

    $statusPanel.Controls.Add($statusIndicator)
    $statusPanel.Controls.Add($lblInventoryStatus)

    $summaryRoot.Controls.Add($statusPanel,0,5)
    $tabSummary.Controls.Add($summaryRoot)

#
# User Reports
#

$usersSplit = New-Object System.Windows.Forms.SplitContainer
$usersSplit.Dock = 'Fill'
$usersSplit.Orientation = 'Vertical'
$usersSplit.FixedPanel = 'Panel1'
$usersSplit.SplitterWidth = 4

#
# LEFT PANEL
#

$reportsPanel = New-Object System.Windows.Forms.GroupBox
$reportsPanel.Text = 'User Reports'
$reportsPanel.Dock = 'Fill'


$userReports = New-Object System.Windows.Forms.TreeView
$userReports.Dock = 'Fill'
$userReports.HideSelection = $false
$userReports.FullRowSelect = $true

# Restore the classic TreeView appearance
$userReports.ShowLines = $true
$userReports.ShowPlusMinus = $true
$userReports.ShowRootLines = $true

# Keep the horizontal scrollbar removed
$userReports.Scrollable = $false

$userReports.BorderStyle = 'None'
$userReports.ItemHeight = 22

$userReports.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    9
)
#
# ACCOUNT REPORTS
#

$accountNode = New-Object System.Windows.Forms.TreeNode(
    'Account Reports'
)

[void]$accountNode.Nodes.Add('All Users')
[void]$accountNode.Nodes.Add('Enabled Users')
[void]$accountNode.Nodes.Add('Disabled Users')
[void]$accountNode.Nodes.Add('Account Expired Users')
[void]$accountNode.Nodes.Add('Inactive Users - Real Last Logon (90 Days+)')
[void]$accountNode.Nodes.Add('Real Last Logon')
[void]$accountNode.Nodes.Add('Users Never Logged On')

#
# MANAGEMENT REPORTS
#

$managementNode = New-Object System.Windows.Forms.TreeNode(
    'Management Reports'
)

[void]$managementNode.Nodes.Add('All Managers')
[void]$managementNode.Nodes.Add('Users Without Manager')

#
# ACTIVITY REPORTS
#

$activityNode = New-Object System.Windows.Forms.TreeNode(
    'Activity Reports'
)

[void]$activityNode.Nodes.Add('Recently Created Users - 30 Days')
[void]$activityNode.Nodes.Add('Recently Deleted Users - 30 Days')
[void]$activityNode.Nodes.Add('Recent Logon Failures - 24 Hours')

#
# PASSWORD REPORTS
#

$passwordNode = New-Object System.Windows.Forms.TreeNode(
    'Password Reports'
)

[void]$passwordNode.Nodes.Add('Password Never Expires')
[void]$passwordNode.Nodes.Add('Password Expired Users')

#
# MEMBERSHIP REPORTS
#

$membershipNode = New-Object System.Windows.Forms.TreeNode(
    'Membership Reports'
)

[void]$membershipNode.Nodes.Add('Group Members')
[void]$membershipNode.Nodes.Add('Groups Without Members')

#
# OU REPORTS
#

$ouNode = New-Object System.Windows.Forms.TreeNode(
    'OU Reports'
)

[void]$ouNode.Nodes.Add('Users From OU')

#
# Add Categories
#

[void]$userReports.Nodes.Add($accountNode)
[void]$userReports.Nodes.Add($managementNode)
[void]$userReports.Nodes.Add($activityNode)
[void]$userReports.Nodes.Add($passwordNode)
[void]$userReports.Nodes.Add($membershipNode)
[void]$userReports.Nodes.Add($ouNode)

$userReports.ExpandAll()

$reportsPanel.Controls.Add($userReports)
$usersSplit.Panel1.Controls.Add($reportsPanel)

#
# RIGHT PANEL
#

$usersRightLayout = New-Object System.Windows.Forms.TableLayoutPanel
$usersRightLayout.Dock = 'Fill'
$usersRightLayout.RowCount = 2

Add-RowStyle $usersRightLayout 'Absolute' 72
Add-RowStyle $usersRightLayout 'Percent' 100

#
# Toolbar
#

$usersToolbar = New-Object System.Windows.Forms.FlowLayoutPanel
$usersToolbar.Dock = 'Fill'
$usersToolbar.Padding = New-Object System.Windows.Forms.Padding(8,7,0,0)
$usersToolbar.FlowDirection = 'LeftToRight'
$usersToolbar.WrapContents = $true

$btnRunUserReport = New-Object System.Windows.Forms.Button
$btnRunUserReport.Text = 'Run Report'
$btnRunUserReport.Width = 100
$btnRunUserReport.Enabled = $false

$btnSelectAttributes = New-Object System.Windows.Forms.Button
$btnSelectAttributes.Text = 'Select Attributes'
$btnSelectAttributes.Width = 120

$btnExportUsers = New-Object System.Windows.Forms.Button
$btnExportUsers.Text = 'Export CSV'
$btnExportUsers.Width = 100
$btnExportUsers.Enabled = $false

$txtUserReportSearch = New-Object System.Windows.Forms.TextBox
$txtUserReportSearch.Width = 150
$btnUserReportSearch = New-Object System.Windows.Forms.Button
$btnUserReportSearch.Text = 'Search'
$btnUserReportSearch.Width = 65
$btnClearUserSearch = New-Object System.Windows.Forms.Button
$btnClearUserSearch.Text = 'Clear'
$btnClearUserSearch.Width = 55

$lblSelectedReport = New-Object System.Windows.Forms.Label
$lblSelectedReport.Text = 'No report selected'
$lblSelectedReport.AutoSize = $true
$lblSelectedReport.Margin = New-Object System.Windows.Forms.Padding(12,6,0,0)

$usersToolbar.Controls.Add($btnRunUserReport)
$usersToolbar.Controls.Add($btnSelectAttributes)
$usersToolbar.Controls.Add($btnExportUsers)
$usersToolbar.Controls.Add($txtUserReportSearch)
$usersToolbar.Controls.Add($btnUserReportSearch)
$usersToolbar.Controls.Add($btnClearUserSearch)
$usersToolbar.SetFlowBreak($btnClearUserSearch, $true)
$usersToolbar.Controls.Add($lblSelectedReport)

#
# Results Grid
#

$gridInventoryUsers = New-Grid
$userReportColumns = @(
    'DisplayName',
    'Name',
    'SamAccountName',
    'EmailAddress',
    'EmployeeNumber',

    'Department',
    'Title',
    'Company',
    'Manager',
    'Office',
    'City',
    'Country',

    'AccountStatus',
    'PasswordStatus',
    'PasswordLastSet',
    'PasswordExpiryDate',
    'AccountExpiryDate',
    'LastLogonDate',
    'RealLastLogon',
    'RealLastLogonDC',
    'WhenCreated',
    'DeletedDate'
    'LastKnownParent'
    'FailureTime'
    'FailureReason'
    'LogonType'
    'SourceIP'
    'Workstation'
    'DomainController'

    'Description',
    'DistinguishedName'

    'GroupName'
    'ObjectType'
    'GroupScope'
    'GroupCategory'
)

$userReportAvailableColumns = @{

    'All Users' = @(
        'DisplayName'
        'Name'
        'SamAccountName'
        'EmailAddress'
        'EmployeeNumber'
        'Department'
        'Title'
        'Company'
        'Manager'
        'Office'
        'City'
        'Country'
        'AccountStatus'
        'PasswordStatus'
        'PasswordLastSet'
        'PasswordExpiryDate'
        'AccountExpiryDate'
        'LastLogonDate'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )

    'Enabled Users' = @(
        'DisplayName'
        'Name'
        'SamAccountName'
        'EmailAddress'
        'EmployeeNumber'
        'Department'
        'Title'
        'Company'
        'Manager'
        'Office'
        'AccountStatus'
        'LastLogonDate'
        'WhenCreated'
    )

    'Disabled Users' = @(
        'DisplayName'
        'Name'
        'SamAccountName'
        'EmailAddress'
        'EmployeeNumber'
        'Department'
        'Title'
        'Manager'
        'AccountStatus'
        'LastLogonDate'
        'WhenCreated'
    )

    'Account Expired Users' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'AccountStatus'
        'AccountExpiryDate'
        'LastLogonDate'
    )

    'Users Never Logged On' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'AccountStatus'
        'WhenCreated'
    )

    'Inactive Users - Real Last Logon (90 Days+)' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'AccountStatus'
        'LastLogonDate'
        'RealLastLogon'
        'RealLastLogonDC'
    )

    'Real Last Logon' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'AccountStatus'
        'LastLogonDate'
        'RealLastLogon'
        'RealLastLogonDC'
    )

    'All Managers' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'Title'
        'Manager'
        'AccountStatus'
    )

    'Users Without Manager' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'Title'
        'Manager'
        'AccountStatus'
    )

    'Password Never Expires' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'AccountStatus'
        'PasswordStatus'
        'PasswordLastSet'
        'PasswordExpiryDate'
    )

    'Password Expired Users' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'AccountStatus'
        'PasswordStatus'
        'PasswordLastSet'
        'PasswordExpiryDate'
    )

    'Recently Created Users - 30 Days' = @(
        'DisplayName'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'Title'
        'AccountStatus'
        'WhenCreated'
    )

    'Recently Deleted Users - 30 Days' = @(
        'DisplayName'
        'Name'
        'SamAccountName'
        'AccountStatus'
        'WhenCreated'
        'DeletedDate'
        'LastKnownParent'
        'Description'
        'DistinguishedName'
    )

    'Recent Logon Failures - 24 Hours' = @(
        'FailureTime'
        'SamAccountName'
        'FailureReason'
        'LogonType'
        'SourceIP'
        'Workstation'
        'DomainController'
        'Description'
    )

    'Group Members' = @(
        'GroupName'
        'ObjectType'
        'DisplayName'
        'Name'
        'SamAccountName'
        'EmailAddress'
        'Department'
        'Title'
        'AccountStatus'
        'DistinguishedName'
    )

    'Groups Without Members' = @(
        'GroupName'
        'SamAccountName'
        'GroupScope'
        'GroupCategory'
        'Description'
        'DistinguishedName'
    )

    'Users From OU' = @(
        'DisplayName'
        'Name'
        'SamAccountName'
        'EmailAddress'
        'EmployeeNumber'
        'Department'
        'Title'
        'Company'
        'Manager'
        'Office'
        'City'
        'Country'
        'AccountStatus'
        'PasswordStatus'
        'PasswordLastSet'
        'PasswordExpiryDate'
        'AccountExpiryDate'
        'LastLogonDate'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )
}
if ($null -eq $script:SelectedUserColumns) {
    $script:SelectedUserColumns = @($userReportColumns)
}

$usersRightLayout.Controls.Add($usersToolbar,0,0)
$usersRightLayout.Controls.Add($gridInventoryUsers,0,1)

$usersSplit.Panel2.Controls.Add($usersRightLayout)

$tabUsers.Controls.Add($usersSplit)


#
# Apply left-panel width after layout initialization
#

$usersSplit.Panel1MinSize = 210
$usersSplit.SplitterDistance = 210
$tabUsers.Add_Enter({
    if ($usersSplit.Width -gt 500) {
        $usersSplit.SplitterDistance = 210
    }
})

$userReports.Add_AfterSelect({

    if ($null -eq $userReports.SelectedNode) {
        return
    }

    #
    # Category clicked
    #

    if ($userReports.SelectedNode.Level -eq 0) {

        $btnRunUserReport.Enabled = $false

        $lblSelectedReport.Text =
            'Select a report'

        return
    }

    #
    # Actual report selected
    #

    $btnRunUserReport.Enabled = $true

   $lblSelectedReport.Text =
    'Selected Report: ' +
    $userReports.SelectedNode.Text +
    ' - Click Run Report to load data.'

  if ($script:CurrentUserReportName -ne $userReports.SelectedNode.Text) {

    $script:CurrentUserReport = @()
    $script:CurrentUserReportName = ''

    $gridInventoryUsers.DataSource = $null
    $gridInventoryUsers.Columns.Clear()
    $txtUserReportSearch.Clear()

    $btnExportUsers.Enabled = $false
}
})
$btnRunUserReport.Add_Click({

    if ($null -eq $userReports.SelectedNode) {
        return
    }

    if ($userReports.SelectedNode.Level -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Please select a report first.',
            'User Reports',
            'OK',
            'Information'
        )

        return
    }

    $selectedReport = $userReports.SelectedNode.Text

   try {

    $btnRunUserReport.Enabled = $false
    $btnRunUserReport.Text = 'Running...'

    $lblSelectedReport.Text = "Running $selectedReport... Please wait."

    $w.UseWaitCursor = $true
    $w.Refresh()

    [System.Windows.Forms.Application]::DoEvents()

    switch ($selectedReport) {

    'All Users' {
        $rows = Get-AllUsersReport
    }

    'Enabled Users' {
        $rows = Get-EnabledUsersReport
    }

    'Disabled Users' {
    $rows = Get-DisabledUsersReport
    }

    'Account Expired Users' {
    $rows = Get-AccountExpiredUsersReport
    }

    'Users Never Logged On' {
    $rows = Get-NeverLoggedOnUsersReport
    }

    'Inactive Users - Real Last Logon (90 Days+)' {
    $rows = Get-InactiveUsersRealLastLogonReport
    }

    'Real Last Logon' {
    $rows = Get-RealLastLogonReport
    }

    'All Managers' {
    $rows = Get-AllManagersReport
    }

    'Users Without Manager' {
    $rows = Get-UsersWithoutManagerReport
    }

    'Password Never Expires' {
    $rows = Get-PasswordNeverExpiresReport
    }
        
    'Password Expired Users' {
    $rows = Get-PasswordExpiredUsersReport
    }

    'Recently Created Users - 30 Days' {
    $rows = Get-RecentlyCreatedUsersReport
    }

    'Recently Deleted Users - 30 Days' {
    $rows = Get-RecentlyDeletedUsersReport
    }

    'Recent Logon Failures - 24 Hours' {
    $rows = Get-RecentLogonFailuresReport
    }

    'Group Members' {

    $groupName = Show-GroupNameDialog

    if ([string]::IsNullOrWhiteSpace($groupName)) {
        return
    }

    $rows = Get-UserGroupMembersReport `
        -GroupName $groupName
    }

    'Groups Without Members' {
    $rows = Get-GroupsWithoutMembersReport
    }

    'Users From OU' {

    $selectedOU = Show-OUSelectionDialog

    if ($null -eq $selectedOU) {
        return
    }

    $rows = Get-UsersFromOUReport `
        -SearchBase $selectedOU.DistinguishedName

    $script:SelectedOUName =
        $selectedOU.CanonicalName
    }
    default {

        [void][System.Windows.Forms.MessageBox]::Show(
            "$selectedReport not implemented yet.",
            'User Reports',
            'OK',
            'Information'
        )

        return
    }
}

$script:CurrentUserReport = @($rows)
$script:CurrentUserReportName = $selectedReport
if ($userReportAvailableColumns.ContainsKey($selectedReport)) {

    $script:SelectedUserColumns = @(
        $userReportAvailableColumns[$selectedReport]
    )
}
else {

    $script:SelectedUserColumns = @(
        $userReportColumns
    )
}

Set-GridRows `
    -Grid $gridInventoryUsers `
    -Rows $script:CurrentUserReport `
    -Columns $script:SelectedUserColumns

$btnExportUsers.Enabled = (
    $script:CurrentUserReport.Count -gt 0
)

       $lblSelectedReport.Text = ('{0} - {1} record(s)' -f $selectedReport, $script:CurrentUserReport.Count)

    }
    catch {

        [void][System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Report Error',
            'OK',
            'Error'
        )
    }
    finally {
        $w.UseWaitCursor = $false
        $btnRunUserReport.Text = 'Run Report'
        $btnRunUserReport.Enabled = $true
    }
})
$btnExportUsers.Add_Click({

    if (@($script:CurrentUserReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a report first.',
            'Export',
            'OK',
            'Information'
        )

        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog

    $saveDialog.Title = 'Export User Report'
    $saveDialog.Filter = 'CSV Files (*.csv)|*.csv'

    $saveDialog.FileName = (
        $script:CurrentUserReportName +
        '-' +
        (Get-Date -Format 'yyyyMMdd-HHmmss') +
        '.csv'
    )

    if (
        $saveDialog.ShowDialog() -eq
        [System.Windows.Forms.DialogResult]::OK
    ) {

        $script:CurrentUserReport |
            Select-Object $script:SelectedUserColumns |
            Export-Csv `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Path $saveDialog.FileName

        [void][System.Windows.Forms.MessageBox]::Show(
            'Export completed successfully.',
            'Export',
            'OK',
            'Information'
        )
    }

})
$btnSelectAttributes.Add_Click({

    $f = New-Object System.Windows.Forms.Form
    $f.BackColor = 'White'
    $f.Size = New-Object System.Drawing.Size(420,550)
    $f.Text = 'Select Attributes'
    $f.StartPosition = 'CenterParent'
    $f.Size = New-Object System.Drawing.Size(380,520)

    $list = New-Object System.Windows.Forms.CheckedListBox
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Dock = 'Top'
    $lblInfo.Height = 40
    $lblInfo.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    9,
    [System.Drawing.FontStyle]::Bold
)
    $list.Dock = 'Fill'
    $list.CheckOnClick = $true

    foreach($col in $userReportColumns){

        $index = $list.Items.Add($col)

        if($script:SelectedUserColumns -contains $col){
            $list.SetItemChecked($index,$true)
        }
    }
    $lblInfo.Text =
    "Total Attributes: $($list.Items.Count)"

   $btnSelectAll = New-Object System.Windows.Forms.Button
$btnSelectAll.Text = 'Select All'
$btnSelectAll.Width = 80

$btnClearAll = New-Object System.Windows.Forms.Button
$btnClearAll.Text = 'Clear All'
$btnClearAll.Width = 80

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = 'Apply'
$btnApply.Width = 80

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Width = 80
$btnSelectAll.Add_Click({

    for($i = 0; $i -lt $list.Items.Count; $i++){
        $list.SetItemChecked($i,$true)
    }

})

$btnClearAll.Add_Click({

    for($i = 0; $i -lt $list.Items.Count; $i++){
        $list.SetItemChecked($i,$false)
    }

})

$btnClose.Add_Click({
    $f.Close()
})
$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel

$buttonPanel.Dock = 'Bottom'
$buttonPanel.Height = 55
$buttonPanel.FlowDirection = 'LeftToRight'
$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(5)

$buttonPanel.Controls.Add($btnClose)
$buttonPanel.Controls.Add($btnApply)
$buttonPanel.Controls.Add($btnClearAll)
$buttonPanel.Controls.Add($btnSelectAll)

    $btnApply.Add_Click({

        $selected = @()

        foreach($item in $list.CheckedItems){
            $selected += [string]$item
        }

        if($selected.Count -eq 0){
            return
        }

        $script:SelectedUserColumns = $selected

        if($script:CurrentUserReport.Count -gt 0){

            Set-GridRows `
                -Grid $gridInventoryUsers `
                -Rows $script:CurrentUserReport `
                -Columns $script:SelectedUserColumns
        }

        $f.Close()
    })

$f.Controls.Add($list)
$f.Controls.Add($lblInfo)
$f.Controls.Add($buttonPanel)

    [void]$f.ShowDialog($w)
})
$btnUserReportSearch.Add_Click({

    if (@($script:CurrentUserReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a report before searching.',
            'Search User Report',
            'OK',
            'Information'
        )

        return
    }

    $searchText = $txtUserReportSearch.Text.Trim()

    if ($searchText -eq '') {
        return
    }

    $filteredRows = @(
        $script:CurrentUserReport |
            Where-Object {

                ($_.DisplayName -like "*$searchText*") -or
                ($_.Name -like "*$searchText*") -or
                ($_.SamAccountName -like "*$searchText*") -or
                ($_.EmailAddress -like "*$searchText*") -or
                ($_.EmployeeNumber -like "*$searchText*")
            }
    )

    Set-GridRows `
        -Grid $gridInventoryUsers `
        -Rows $filteredRows `
        -Columns $script:SelectedUserColumns

    $lblSelectedReport.Text = (
        '{0} - Search Results: {1}' -f
        $script:CurrentUserReportName,
        $filteredRows.Count
    )
})
$btnClearUserSearch.Add_Click({

    $txtUserReportSearch.Clear()

    if (@($script:CurrentUserReport).Count -gt 0) {

        Set-GridRows `
            -Grid $gridInventoryUsers `
            -Rows $script:CurrentUserReport `
            -Columns $script:SelectedUserColumns

        $lblSelectedReport.Text = (
            '{0} - {1} record(s)' -f
            $script:CurrentUserReportName,
            $script:CurrentUserReport.Count
        )
    }
})
$txtUserReportSearch.Add_KeyDown({

    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {

        $btnUserReportSearch.PerformClick()

        $_.SuppressKeyPress = $true
    }
})

#
# Computer Reports
#

# ============================================================
# COMPUTER REPORT STATE
# ============================================================

$script:CurrentComputerReport = @()
$script:CurrentComputerReportName = ''


# ============================================================
# COMPUTER SPLIT CONTAINER
# ============================================================

$computersSplit = New-Object System.Windows.Forms.SplitContainer

$computersSplit.Dock = 'Fill'
$computersSplit.Orientation = 'Vertical'
$computersSplit.FixedPanel = 'Panel1'
$computersSplit.SplitterWidth = 4


#
# LEFT PANEL
#

$computerReportsPanel = New-Object System.Windows.Forms.GroupBox

$computerReportsPanel.Text = 'Computer Reports'
$computerReportsPanel.Dock = 'Fill'


# ============================================================
# COMPUTER REPORT TREE
# ============================================================

$computerReports = New-Object System.Windows.Forms.TreeView

$computerReports.Dock = 'Fill'
$computerReports.HideSelection = $false
$computerReports.FullRowSelect = $true

# Same classic appearance as Users
$computerReports.ShowLines = $true
$computerReports.ShowPlusMinus = $true
$computerReports.ShowRootLines = $true

# Same behavior as Users
$computerReports.Scrollable = $false
$computerReports.BorderStyle = 'None'
$computerReports.ItemHeight = 22

$computerReports.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    9
)


# ============================================================
# ACCOUNT REPORTS
# ============================================================

$computerAccountNode =
    New-Object System.Windows.Forms.TreeNode(
        'Account Reports'
    )

[void]$computerAccountNode.Nodes.Add(
    'All Computers'
)

[void]$computerAccountNode.Nodes.Add(
    'Enabled Computers'
)

[void]$computerAccountNode.Nodes.Add(
    'Disabled Computers'
)

[void]$computerAccountNode.Nodes.Add(
    'Inactive Computers - Real Last Logon (90 Days+)'
)

[void]$computerAccountNode.Nodes.Add(
    'Computers Never Logged On'
)

[void]$computerAccountNode.Nodes.Add(
    'Real Last Logon'
)


# ============================================================
# ACTIVITY REPORTS
# ============================================================

$computerActivityNode =
    New-Object System.Windows.Forms.TreeNode(
        'Activity Reports'
    )

[void]$computerActivityNode.Nodes.Add(
    'Recently Created Computers - 30 Days'
)

# ============================================================
# OPERATING SYSTEM REPORTS
# ============================================================

$computerOSNode =
    New-Object System.Windows.Forms.TreeNode(
        'Operating System Reports'
    )

[void]$computerOSNode.Nodes.Add(
    'Computers by Operating System'
)

[void]$computerOSNode.Nodes.Add(
    'Windows Servers'
)

[void]$computerOSNode.Nodes.Add(
    'Windows Workstations'
)

[void]$computerOSNode.Nodes.Add(
    'Computers Without Operating System'
)


# ============================================================
# MANAGEMENT REPORTS
# ============================================================

$computerManagementNode =
    New-Object System.Windows.Forms.TreeNode(
        'Management Reports'
    )

[void]$computerManagementNode.Nodes.Add(
    'Managed Computers'
)

[void]$computerManagementNode.Nodes.Add(
    'Computers Without ManagedBy'
)


# ============================================================
# OU REPORTS
# ============================================================

$computerOUNode =
    New-Object System.Windows.Forms.TreeNode(
        'OU Reports'
    )

[void]$computerOUNode.Nodes.Add(
    'Computers From OU'
)


# ============================================================
# ADD CATEGORIES TO TREE
# ============================================================

[void]$computerReports.Nodes.Add(
    $computerAccountNode
)

[void]$computerReports.Nodes.Add(
    $computerActivityNode
)

[void]$computerReports.Nodes.Add(
    $computerOSNode
)

[void]$computerReports.Nodes.Add(
    $computerManagementNode
)

[void]$computerReports.Nodes.Add(
    $computerOUNode
)

$computerReports.ExpandAll()


# ============================================================
# ADD TREE TO LEFT PANEL
# ============================================================

$computerReportsPanel.Controls.Add(
    $computerReports
)

$computersSplit.Panel1.Controls.Add(
    $computerReportsPanel
)


#
# RIGHT PANEL
#

$computersRightLayout =
    New-Object System.Windows.Forms.TableLayoutPanel

$computersRightLayout.Dock = 'Fill'
$computersRightLayout.RowCount = 2
$computersRightLayout.ColumnCount = 1

Add-RowStyle $computersRightLayout 'Absolute' 72
Add-RowStyle $computersRightLayout 'Percent' 100


# ============================================================
# COMPUTER TOOLBAR
# ============================================================

$computersToolbar =
    New-Object System.Windows.Forms.FlowLayoutPanel

$computersToolbar.Dock = 'Fill'

$computersToolbar.Padding =
    New-Object System.Windows.Forms.Padding(
        8,7,0,0
    )

$computersToolbar.FlowDirection = 'LeftToRight'
$computersToolbar.WrapContents = $true


# ============================================================
# RUN REPORT BUTTON
# ============================================================

$btnRunComputerReport =
    New-Object System.Windows.Forms.Button

$btnRunComputerReport.Text = 'Run Report'
$btnRunComputerReport.Width = 100
$btnRunComputerReport.Enabled = $false


# ============================================================
# SELECT ATTRIBUTES BUTTON
# ============================================================

$btnSelectComputerAttributes =
    New-Object System.Windows.Forms.Button

$btnSelectComputerAttributes.Text =
    'Select Attributes'

$btnSelectComputerAttributes.Width = 120


# ============================================================
# EXPORT CSV BUTTON
# ============================================================

$btnExportComputers =
    New-Object System.Windows.Forms.Button

$btnExportComputers.Text = 'Export CSV'
$btnExportComputers.Width = 100
$btnExportComputers.Enabled = $false


# ============================================================
# SEARCH BOX
# ============================================================

$txtComputerReportSearch =
    New-Object System.Windows.Forms.TextBox

$txtComputerReportSearch.Width = 150


# ============================================================
# SEARCH BUTTON
# ============================================================

$btnComputerReportSearch =
    New-Object System.Windows.Forms.Button

$btnComputerReportSearch.Text = 'Search'
$btnComputerReportSearch.Width = 65


# ============================================================
# CLEAR BUTTON
# ============================================================

$btnClearComputerSearch =
    New-Object System.Windows.Forms.Button

$btnClearComputerSearch.Text = 'Clear'
$btnClearComputerSearch.Width = 55


# ============================================================
# SELECTED REPORT LABEL
# ============================================================

$lblSelectedComputerReport =
    New-Object System.Windows.Forms.Label

$lblSelectedComputerReport.Text =
    'No report selected'

$lblSelectedComputerReport.AutoSize = $true

$lblSelectedComputerReport.Margin =
    New-Object System.Windows.Forms.Padding(
        12,6,0,0
    )


# ============================================================
# ADD CONTROLS TO TOOLBAR
# ============================================================

[void]$computersToolbar.Controls.Add(
    $btnRunComputerReport
)

[void]$computersToolbar.Controls.Add(
    $btnSelectComputerAttributes
)

[void]$computersToolbar.Controls.Add(
    $btnExportComputers
)

[void]$computersToolbar.Controls.Add(
    $txtComputerReportSearch
)

[void]$computersToolbar.Controls.Add(
    $btnComputerReportSearch
)

[void]$computersToolbar.Controls.Add(
    $btnClearComputerSearch
)

# Force the selected report label onto line 2
$computersToolbar.SetFlowBreak(
    $btnClearComputerSearch,
    $true
)

[void]$computersToolbar.Controls.Add(
    $lblSelectedComputerReport
)


# ============================================================
# COMPUTER RESULTS GRID
# ============================================================

$gridInventoryComputers = New-Grid


# ============================================================
# COMPUTER ATTRIBUTE MASTER LIST
# ============================================================

$computerReportColumns = @(

    'Name'
    'SamAccountName'
    'CN'
    'DNSHostName'

    'Enabled'
    'AccountStatus'

    'IPv4Address'
    'OperatingSystem'
    'OperatingSystemVersion'
    'OperatingSystemServicePack'

    'LastLogonDate'
    'RealLastLogon'
    'RealLastLogonDC'

    'PasswordLastSet'
    'PasswordExpiryDate'
    'PasswordNeverExpires'

    'ManagedBy'
    'Description'

    'WhenCreated'
    'WhenChanged'

    'CanonicalName'
    'DistinguishedName'
)


# ============================================================
# DEFAULT COLUMNS FOR EACH REPORT
# ============================================================

$computerReportAvailableColumns = @{

    'All Computers' = @(

        'Name'
        'SamAccountName'
        'CN'
        'DNSHostName'
        'AccountStatus'
        'IPv4Address'
        'OperatingSystem'
        'OperatingSystemVersion'
        'LastLogonDate'
        'ManagedBy'
        'PasswordLastSet'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )

    'Enabled Computers' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'AccountStatus'
        'IPv4Address'
        'OperatingSystem'
        'OperatingSystemVersion'
        'LastLogonDate'
        'PasswordLastSet'
        'WhenCreated'
    )

    'Disabled Computers' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'AccountStatus'
        'OperatingSystem'
        'LastLogonDate'
        'PasswordLastSet'
        'WhenCreated'
        'Description'
    )

    'Inactive Computers - Real Last Logon (90 Days+)' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'AccountStatus'
        'OperatingSystem'
        'LastLogonDate'
        'RealLastLogon'
        'RealLastLogonDC'
    )

    'Computers Never Logged On' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'AccountStatus'
        'OperatingSystem'
        'WhenCreated'
    )

    'Real Last Logon' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'AccountStatus'
        'OperatingSystem'
        'LastLogonDate'
        'RealLastLogon'
        'RealLastLogonDC'
    )

    'Recently Created Computers - 30 Days' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'Enabled'
        'OperatingSystem'
        'OperatingSystemVersion'
        'WhenCreated'
        'DistinguishedName'
    )


    'Computers by Operating System' = @(

        'Name'
        'DNSHostName'
        'Enabled'
        'OperatingSystem'
        'OperatingSystemVersion'
        'OperatingSystemServicePack'
        'IPv4Address'
        'LastLogonDate'
    )

    'Windows Servers' = @(

        'Name'
        'DNSHostName'
        'Enabled'
        'IPv4Address'
        'OperatingSystem'
        'OperatingSystemVersion'
        'LastLogonDate'
        'PasswordLastSet'
    )

    'Windows Workstations' = @(

        'Name'
        'DNSHostName'
        'Enabled'
        'IPv4Address'
        'OperatingSystem'
        'OperatingSystemVersion'
        'LastLogonDate'
        'PasswordLastSet'
    )

    'Computers Without Operating System' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'Enabled'
        'LastLogonDate'
        'WhenCreated'
        'DistinguishedName'
    )

    'Managed Computers' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'Enabled'
        'OperatingSystem'
        'ManagedBy'
        'DistinguishedName'
    )

    'Computers Without ManagedBy' = @(

        'Name'
        'SamAccountName'
        'DNSHostName'
        'Enabled'
        'OperatingSystem'
        'ManagedBy'
        'DistinguishedName'
    )

    'Computers From OU' = @(

        'Name'
        'SamAccountName'
        'CN'
        'DNSHostName'
        'AccountStatus'
        'IPv4Address'
        'OperatingSystem'
        'OperatingSystemVersion'
        'LastLogonDate'
        'ManagedBy'
        'PasswordLastSet'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )
}


# ============================================================
# INITIAL SELECTED COLUMNS
# ============================================================

$script:SelectedComputerColumns = @(
    $computerReportColumns
)



# ============================================================
# ADD TOOLBAR AND GRID TO RIGHT LAYOUT
# ============================================================

$computersRightLayout.Controls.Add(
    $computersToolbar,
    0,
    0
)

$computersRightLayout.Controls.Add(
    $gridInventoryComputers,
    0,
    1
)

$computersSplit.Panel2.Controls.Add(
    $computersRightLayout
)


# ============================================================
# ADD SPLIT CONTAINER TO COMPUTERS TAB
# ============================================================

$tabComputers.Controls.Add(
    $computersSplit
)


# ============================================================
# APPLY SAME LEFT-PANEL WIDTH AS USERS
# ============================================================

$computersSplit.Panel1MinSize = 210
$computersSplit.SplitterDistance = 210

$tabComputers.Add_Enter({

    if ($computersSplit.Width -gt 500) {

        $computersSplit.SplitterDistance = 210
    }
})


# ============================================================
# COMPUTER REPORT SELECTION
# ============================================================

$computerReports.Add_AfterSelect({

    if ($null -eq $computerReports.SelectedNode) {
        return
    }

    #
    # Category clicked
    #

    if ($computerReports.SelectedNode.Level -eq 0) {

        $btnRunComputerReport.Enabled = $false

        $lblSelectedComputerReport.Text =
            'Select a report'

        return
    }

    #
    # Actual report selected
    #

    $btnRunComputerReport.Enabled = $true

    $selectedComputerReport =
        $computerReports.SelectedNode.Text

    $lblSelectedComputerReport.Text =
        'Selected Report: ' +
        $selectedComputerReport +
        ' - Click Run Report to load data.'

    #
    # Clear previous result when selecting a different report
    #

    if (
        $script:CurrentComputerReportName -ne
        $selectedComputerReport
    ) {

        $script:CurrentComputerReport = @()
        $script:CurrentComputerReportName = ''
        $script:SelectedComputerOUName = ''

        $gridInventoryComputers.DataSource = $null
        $gridInventoryComputers.Columns.Clear()

        $txtComputerReportSearch.Clear()

        $btnExportComputers.Enabled = $false
    }
})

$btnRunComputerReport.Add_Click({

    if ($null -eq $computerReports.SelectedNode) {
        return
    }

    if ($computerReports.SelectedNode.Level -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Please select a computer report first.',
            'Computer Reports',
            'OK',
            'Information'
        )

        return
    }

    $selectedReport =
        $computerReports.SelectedNode.Text

    try {

        $btnRunComputerReport.Enabled = $false
        $btnRunComputerReport.Text = 'Running...'

        $lblSelectedComputerReport.Text =
            "Running $selectedReport... Please wait."

        $w.UseWaitCursor = $true
        $w.Refresh()

        [System.Windows.Forms.Application]::DoEvents()


 switch ($selectedReport) {

    'All Computers' {

        $rows = Get-AllComputersReport
    }

    'Enabled Computers' {

        $rows = Get-EnabledComputersReport
    }

    'Disabled Computers' {

        $rows = Get-DisabledComputersReport
    }

    'Inactive Computers - Real Last Logon (90 Days+)' {

        $rows =
            Get-InactiveComputersRealLastLogonReport
    }

    'Computers Never Logged On' {

        $rows =
            Get-ComputersNeverLoggedOnReport
    }

    'Real Last Logon' {

        $rows =
            Get-ComputerRealLastLogonReport
    }

    'Recently Created Computers - 30 Days' {

    $rows =
        Get-RecentlyCreatedComputersReport
    }

    'Computers by Operating System' {

    $rows =
        Get-ComputersByOperatingSystemReport
    }

    'Windows Servers' {

    $rows =
        Get-WindowsServersReport
    }

    'Windows Workstations' {

    $rows =
        Get-WindowsWorkstationsReport
    }

    'Computers Without Operating System' {

    $rows =
        Get-ComputersWithoutOperatingSystemReport
    }

    'Managed Computers' {

    $rows =
        Get-ManagedComputersReport
    }

    'Computers Without ManagedBy' {

    $rows =
        Get-ComputersWithoutManagedByReport
    }

    'Computers From OU' {

    $selectedOU =
        Show-OUSelectionDialog

    if ($null -eq $selectedOU) {
        return
    }

    $rows =
        Get-ComputersFromOUReport `
            -SearchBase $selectedOU.DistinguishedName

    $script:SelectedComputerOUName =
        $selectedOU.CanonicalName
    }

    default {

        [void][System.Windows.Forms.MessageBox]::Show(
            "$selectedReport not implemented yet.",
            'Computer Reports',
            'OK',
            'Information'
        )

        return
    }
}

        #
        # Save report results
        #

        $script:CurrentComputerReport =
            @($rows)

        $script:CurrentComputerReportName =
            $selectedReport


        #
        # Select default attributes for report
        #

        if (
            $computerReportAvailableColumns.ContainsKey(
                $selectedReport
            )
        ) {

            $script:SelectedComputerColumns = @(
                $computerReportAvailableColumns[
                    $selectedReport
                ]
            )
        }
        else {

            $script:SelectedComputerColumns = @(
                $computerReportColumns
            )
        }


        #
        # Show results
        #

        Set-GridRows `
            -Grid $gridInventoryComputers `
            -Rows $script:CurrentComputerReport `
            -Columns $script:SelectedComputerColumns


        #
        # Export availability
        #

        $btnExportComputers.Enabled = (
            $script:CurrentComputerReport.Count -gt 0
        )


        #
        # Update label
        #

        if (
    $selectedReport -eq 'Computers From OU' -and
    -not [string]::IsNullOrWhiteSpace(
        $script:SelectedComputerOUName
    )
    ) {

    $lblSelectedComputerReport.Text = (
        'Computers From OU: {0} - {1} record(s)' -f
        $script:SelectedComputerOUName,
        $script:CurrentComputerReport.Count
    )
    }
    else {

    $lblSelectedComputerReport.Text = (
        '{0} - {1} record(s)' -f
        $selectedReport,
        $script:CurrentComputerReport.Count
    )
    }
    }

    catch {

        [void][System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Computer Report Error',
            'OK',
            'Error'
        )
    }

    finally {

        $w.UseWaitCursor = $false

        $btnRunComputerReport.Text =
            'Run Report'

        $btnRunComputerReport.Enabled =
            $true
    }
})

#
# ============================================================
# COMPUTER - SELECT ATTRIBUTES
# ============================================================
#

$btnSelectComputerAttributes.Add_Click({

    $f = New-Object System.Windows.Forms.Form

    $f.Text = 'Select Computer Attributes'
    $f.BackColor = 'White'
    $f.StartPosition = 'CenterParent'

    $f.Size =
        New-Object System.Drawing.Size(
            380,
            520
        )


    #
    # Attribute information
    #

    $lblInfo =
        New-Object System.Windows.Forms.Label

    $lblInfo.Dock = 'Top'
    $lblInfo.Height = 40

    $lblInfo.Font =
        New-Object System.Drawing.Font(
            'Segoe UI',
            9,
            [System.Drawing.FontStyle]::Bold
        )


    #
    # Attribute list
    #

    $list =
        New-Object System.Windows.Forms.CheckedListBox

    $list.Dock = 'Fill'
    $list.CheckOnClick = $true


    #
    # Add all available Computer attributes
    #

    foreach ($col in $computerReportColumns) {

        $index =
            $list.Items.Add($col)

        if (
            $script:SelectedComputerColumns -contains
            $col
        ) {

            $list.SetItemChecked(
                $index,
                $true
            )
        }
    }


    $lblInfo.Text =
        "Total Attributes: $($list.Items.Count)"


    #
    # Buttons
    #

    $btnSelectAll =
        New-Object System.Windows.Forms.Button

    $btnSelectAll.Text = 'Select All'
    $btnSelectAll.Width = 80


    $btnClearAll =
        New-Object System.Windows.Forms.Button

    $btnClearAll.Text = 'Clear All'
    $btnClearAll.Width = 80


    $btnApply =
        New-Object System.Windows.Forms.Button

    $btnApply.Text = 'Apply'
    $btnApply.Width = 80


    $btnClose =
        New-Object System.Windows.Forms.Button

    $btnClose.Text = 'Close'
    $btnClose.Width = 80


    #
    # Select All
    #

    $btnSelectAll.Add_Click({

        for (
            $i = 0
            $i -lt $list.Items.Count
            $i++
        ) {

            $list.SetItemChecked(
                $i,
                $true
            )
        }
    })


    #
    # Clear All
    #

    $btnClearAll.Add_Click({

        for (
            $i = 0
            $i -lt $list.Items.Count
            $i++
        ) {

            $list.SetItemChecked(
                $i,
                $false
            )
        }
    })


    #
    # Close
    #

    $btnClose.Add_Click({

        $f.Close()
    })


    #
    # Apply
    #

    $btnApply.Add_Click({

        $selected = @()

        foreach ($item in $list.CheckedItems) {

            $selected +=
                [string]$item
        }


        if ($selected.Count -eq 0) {

            [void][System.Windows.Forms.MessageBox]::Show(
                'Please select at least one attribute.',
                'Select Attributes',
                'OK',
                'Information'
            )

            return
        }


        #
        # Save selected attributes
        #

        $script:SelectedComputerColumns =
            @($selected)


        #
        # Refresh currently loaded report
        #

        if (
            @($script:CurrentComputerReport).Count -gt 0
        ) {

            Set-GridRows `
                -Grid $gridInventoryComputers `
                -Rows $script:CurrentComputerReport `
                -Columns $script:SelectedComputerColumns
        }


        $f.Close()
    })


    #
    # Bottom button panel
    #

    $buttonPanel =
        New-Object System.Windows.Forms.FlowLayoutPanel

    $buttonPanel.Dock = 'Bottom'
    $buttonPanel.Height = 55

    $buttonPanel.FlowDirection =
        'LeftToRight'

    $buttonPanel.Padding =
        New-Object System.Windows.Forms.Padding(5)


    [void]$buttonPanel.Controls.Add(
        $btnClose
    )

    [void]$buttonPanel.Controls.Add(
        $btnApply
    )

    [void]$buttonPanel.Controls.Add(
        $btnClearAll
    )

    [void]$buttonPanel.Controls.Add(
        $btnSelectAll
    )


    #
    # Add controls
    #

    $f.Controls.Add($list)
    $f.Controls.Add($lblInfo)
    $f.Controls.Add($buttonPanel)


    [void]$f.ShowDialog($w)
})

#
# ============================================================
# COMPUTER - EXPORT CSV
# ============================================================
#

$btnExportComputers.Add_Click({

    #
    # Make sure a report has been loaded
    #

    if (@($script:CurrentComputerReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a computer report first.',
            'Export',
            'OK',
            'Information'
        )

        return
    }


    #
    # Create Save File dialog
    #

    $saveDialog =
        New-Object System.Windows.Forms.SaveFileDialog

    $saveDialog.Title =
        'Export Computer Report'

    $saveDialog.Filter =
        'CSV Files (*.csv)|*.csv'


    #
    # Create safe filename from report name
    #

    $safeReportName =
        $script:CurrentComputerReportName -replace '[\\/:*?"<>|]', '-'


    #
    # Default filename
    #

    $saveDialog.FileName = (
        $safeReportName +
        '-' +
        (Get-Date -Format 'yyyyMMdd-HHmmss') +
        '.csv'
    )


    #
    # Show Save dialog
    #

    if (
        $saveDialog.ShowDialog() -eq
        [System.Windows.Forms.DialogResult]::OK
    ) {

        #
        # Export only currently selected attributes
        #

        $script:CurrentComputerReport |
            Select-Object $script:SelectedComputerColumns |
            Export-Csv `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Path $saveDialog.FileName


        #
        # Success message
        #

        [void][System.Windows.Forms.MessageBox]::Show(
            'Export completed successfully.',
            'Export',
            'OK',
            'Information'
        )
    }
})

#
# ============================================================
# COMPUTER - SEARCH
# ============================================================
#

$btnComputerReportSearch.Add_Click({

    #
    # Make sure a report is loaded
    #

    if (@($script:CurrentComputerReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a computer report before searching.',
            'Search Computer Report',
            'OK',
            'Information'
        )

        return
    }


    #
    # Get search text
    #

    $searchText =
        $txtComputerReportSearch.Text.Trim()


    if ([string]::IsNullOrWhiteSpace($searchText)) {
        return
    }


    #
    # Search currently selected attributes
    #

    $filteredRows = @(

        $script:CurrentComputerReport |

            Where-Object {

                $row = $_
                $matched = $false


                foreach (
                    $column in
                    $script:SelectedComputerColumns
                ) {

                    $property =
                        $row.PSObject.Properties[$column]


                    if (
                        $null -ne $property -and
                        $null -ne $property.Value
                    ) {

                        if (
                            $property.Value.ToString() -like
                            "*$searchText*"
                        ) {

                            $matched = $true
                            break
                        }
                    }
                }


                $matched
            }
    )


    #
    # Display search results
    #

    Set-GridRows `
        -Grid $gridInventoryComputers `
        -Rows $filteredRows `
        -Columns $script:SelectedComputerColumns


    #
    # Update status label
    #

    $lblSelectedComputerReport.Text = (
        '{0} - Search Results: {1}' -f
        $script:CurrentComputerReportName,
        $filteredRows.Count
    )
})

#
# ============================================================
# COMPUTER - CLEAR SEARCH
# ============================================================
#

$btnClearComputerSearch.Add_Click({

    #
    # Clear search box
    #

    $txtComputerReportSearch.Clear()


    #
    # Restore original report
    #

    if (@($script:CurrentComputerReport).Count -gt 0) {

        Set-GridRows `
            -Grid $gridInventoryComputers `
            -Rows $script:CurrentComputerReport `
            -Columns $script:SelectedComputerColumns


        #
        # Restore report status
        #

        $lblSelectedComputerReport.Text = (
            '{0} - {1} record(s)' -f
            $script:CurrentComputerReportName,
            $script:CurrentComputerReport.Count
        )
    }
})

#
# ============================================================
# COMPUTER - PRESS ENTER TO SEARCH
# ============================================================
#

$txtComputerReportSearch.Add_KeyDown({

    if (
        $_.KeyCode -eq
        [System.Windows.Forms.Keys]::Enter
    ) {

        $btnComputerReportSearch.PerformClick()

        $_.SuppressKeyPress = $true
    }
})

#
# Group Reports
#
$script:GroupADProperties = @(

    'Name'
    'SamAccountName'
    'DisplayName'

    'GroupCategory'
    'GroupScope'

    'Mail'
    'Description'
    'ManagedBy'

    'Members'

    'WhenCreated'
    'WhenChanged'

    'CanonicalName'
    'DistinguishedName'
)

function ConvertTo-GroupReportRow {

    param(
        [Parameter(Mandatory)]
        $Group
    )


    #
    # Created date
    #

    $whenCreated = ''

    if ($null -ne $Group.WhenCreated) {

        $whenCreated =
            $Group.WhenCreated.ToString(
                'dd/MM/yyyy'
            )
    }


    #
    # Changed date
    #

    $whenChanged = ''

    if ($null -ne $Group.WhenChanged) {

        $whenChanged =
            $Group.WhenChanged.ToString(
                'dd/MM/yyyy'
            )
    }


    #
    # Member count
    #

    $memberCount = 0

    if ($null -ne $Group.Members) {

        $memberCount =
            @($Group.Members).Count
    }


    #
    # Return standardized Group report row
    #

    [PSCustomObject]@{

        Name =
            $Group.Name

        SamAccountName =
            $Group.SamAccountName

        DisplayName =
            $Group.DisplayName

        GroupCategory =
            [string]$Group.GroupCategory

        GroupScope =
            [string]$Group.GroupScope

        EmailAddress =
            $Group.Mail

        ManagedBy =
            $Group.ManagedBy

        MemberCount =
            $memberCount

        Description =
            $Group.Description

        WhenCreated =
            $whenCreated

        WhenChanged =
            $whenChanged

        CanonicalName =
            $Group.CanonicalName

        DistinguishedName =
            $Group.DistinguishedName


        #
        # Reserved for Membership reports later
        #

        MemberName = ''

        MemberSamAccountName = ''

        MemberObjectType = ''

        MemberEmailAddress = ''
    }
}

function Get-AllGroupsReport {

    $groups = @(

        Get-ADGroup `
            -Filter * `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}

function Get-SecurityGroupsReport {

    $groups = @(

        Get-ADGroup `
            -Filter "GroupCategory -eq 'Security'" `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}

function Get-DistributionGroupsReport {

    $groups = @(

        Get-ADGroup `
            -Filter "GroupCategory -eq 'Distribution'" `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}

function Get-GroupMembersInventoryReport {

    param(
        [Parameter(Mandatory)]
        [string]$GroupIdentity
    )

    #
    # Get Group details
    #

    $group = Get-ADGroup `
        -Identity $GroupIdentity `
        -Properties $script:GroupADProperties `
        -ErrorAction Stop


    #
    # Get direct Group members
    #

    $members = @(
        Get-ADGroupMember `
            -Identity $group.DistinguishedName `
            -ErrorAction Stop |
        Sort-Object Name
    )


    $rows = foreach ($member in $members) {

        #
        # Default values
        #

        $memberName =
            [string]$member.Name

        $memberSamAccountName =
            [string]$member.SamAccountName

        $memberObjectType =
            [string]$member.ObjectClass

        $memberEmailAddress = ''


        #
        # Retrieve email address for User members
        #

        if ($member.ObjectClass -eq 'user') {

            try {

                $memberDetails =
                    Get-ADUser `
                        -Identity $member.DistinguishedName `
                        -Properties Mail `
                        -ErrorAction Stop

                $memberEmailAddress =
                    [string]$memberDetails.Mail
            }
            catch {

                $memberEmailAddress = ''
            }
        }


        #
        # Retrieve email address for Group members
        #

        elseif ($member.ObjectClass -eq 'group') {

            try {

                $memberDetails =
                    Get-ADGroup `
                        -Identity $member.DistinguishedName `
                        -Properties Mail `
                        -ErrorAction Stop

                $memberEmailAddress =
                    [string]$memberDetails.Mail
            }
            catch {

                $memberEmailAddress = ''
            }
        }


        #
        # Return one row per member
        #

        [PSCustomObject]@{

            Name =
                $group.Name

            SamAccountName =
                $group.SamAccountName

            DisplayName =
                $group.DisplayName

            GroupCategory =
                [string]$group.GroupCategory

            GroupScope =
                [string]$group.GroupScope

            EmailAddress =
                $group.Mail

            ManagedBy =
                $group.ManagedBy

            MemberCount =
                $members.Count

            Description =
                $group.Description

            WhenCreated =
                if ($null -ne $group.WhenCreated) {
                    $group.WhenCreated.ToString(
                        'dd/MM/yyyy'
                    )
                }
                else {
                    ''
                }

            WhenChanged =
                if ($null -ne $group.WhenChanged) {
                    $group.WhenChanged.ToString(
                        'dd/MM/yyyy'
                    )
                }
                else {
                    ''
                }

            CanonicalName =
                $group.CanonicalName

            DistinguishedName =
                $group.DistinguishedName

            MemberName =
                $memberName

            MemberSamAccountName =
                $memberSamAccountName

            MemberObjectType =
                $memberObjectType

            MemberEmailAddress =
                $memberEmailAddress
        }
    }


    return @($rows)
}

function Get-NestedGroupsReport {

    param(
        [Parameter(Mandatory)]
        [string]$GroupIdentity
    )


    #
    # Get Parent Group
    #

    $parentGroup =
        Get-ADGroup `
            -Identity $GroupIdentity `
            -Properties $script:GroupADProperties `
            -ErrorAction Stop


    #
    # Get only directly nested Groups
    #

    $nestedGroups = @(
        Get-ADGroupMember `
            -Identity $parentGroup.DistinguishedName `
            -ErrorAction Stop |
        Where-Object {
            $_.ObjectClass -eq 'group'
        } |
        Sort-Object Name
    )


    #
    # Build report rows
    #

    $rows = foreach ($nestedGroupMember in $nestedGroups) {

        #
        # Get complete nested Group details
        #

        $nestedGroup =
            Get-ADGroup `
                -Identity $nestedGroupMember.DistinguishedName `
                -Properties $script:GroupADProperties `
                -ErrorAction Stop


        #
        # Return one row per nested Group
        #

        [PSCustomObject]@{

            #
            # Parent Group
            #

            Name =
                $parentGroup.Name

            SamAccountName =
                $parentGroup.SamAccountName

            DisplayName =
                $parentGroup.DisplayName

            GroupCategory =
                [string]$parentGroup.GroupCategory

            GroupScope =
                [string]$parentGroup.GroupScope

            EmailAddress =
                $parentGroup.Mail

            ManagedBy =
                $parentGroup.ManagedBy

            MemberCount =
                @($nestedGroups).Count

            Description =
                $parentGroup.Description


            #
            # Nested Group
            #

            MemberName =
                $nestedGroup.Name

            MemberSamAccountName =
                $nestedGroup.SamAccountName

            MemberObjectType =
                'group'

            MemberEmailAddress =
                $nestedGroup.Mail


            #
            # Parent Group dates
            #

            WhenCreated =
                if ($null -ne $parentGroup.WhenCreated) {

                    $parentGroup.WhenCreated.ToString(
                        'dd/MM/yyyy'
                    )
                }
                else {

                    ''
                }

            WhenChanged =
                if ($null -ne $parentGroup.WhenChanged) {

                    $parentGroup.WhenChanged.ToString(
                        'dd/MM/yyyy'
                    )
                }
                else {

                    ''
                }


            CanonicalName =
                $parentGroup.CanonicalName

            DistinguishedName =
                $parentGroup.DistinguishedName
        }
    }


    return @($rows)
}

function Get-GlobalGroupsReport {

    $groups = @(

        Get-ADGroup `
            -Filter "GroupScope -eq 'Global'" `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}
function Get-UniversalGroupsReport {

    $groups = @(

        Get-ADGroup `
            -Filter "GroupScope -eq 'Universal'" `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}
function Get-DomainLocalGroupsReport {

    $groups = @(

        Get-ADGroup `
            -Filter "GroupScope -eq 'DomainLocal'" `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}
function Get-RecentlyCreatedGroupsReport {

    #
    # Cutoff date
    #

    $cutoffDate =
        (Get-Date).AddDays(-30)


    #
    # Get Groups created within last 30 days
    #

    $groups = @(

        Get-ADGroup `
            -Filter * `
            -Properties $script:GroupADProperties |

        Where-Object {

            $null -ne $_.WhenCreated -and
            $_.WhenCreated -ge $cutoffDate
        } |

        Sort-Object WhenCreated -Descending
    )


    #
    # Convert to standard Group rows
    #

    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}
function Get-GroupsFromOUReport {

    param(
        [Parameter(Mandatory)]
        [string]$SearchBase
    )


    #
    # Get Groups from selected OU
    #

    $groups = @(

        Get-ADGroup `
            -Filter * `
            -SearchBase $SearchBase `
            -SearchScope Subtree `
            -Properties $script:GroupADProperties |

        Sort-Object Name
    )


    #
    # Convert to standard Group rows
    #

    $rows = foreach ($group in $groups) {

        ConvertTo-GroupReportRow `
            -Group $group
    }


    return @($rows)
}
# ============================================================
# GROUP REPORT STATE
# ============================================================

$script:CurrentGroupReport = @()
$script:CurrentGroupReportName = ''
$script:SelectedGroupColumns = @()
$script:SelectedGroupName = ''
$script:SelectedGroupOUName = ''

# ============================================================
# GROUPS SPLIT CONTAINER
# ============================================================

$groupsSplit = New-Object System.Windows.Forms.SplitContainer

$groupsSplit.Dock = 'Fill'
$groupsSplit.Orientation = 'Vertical'
$groupsSplit.FixedPanel = 'Panel1'
$groupsSplit.SplitterWidth = 4


#
# LEFT PANEL
#

$groupReportsPanel =
    New-Object System.Windows.Forms.GroupBox

$groupReportsPanel.Text = 'Group Reports'
$groupReportsPanel.Dock = 'Fill'


# ============================================================
# GROUP REPORT TREE
# ============================================================

$groupReports =
    New-Object System.Windows.Forms.TreeView

$groupReports.Dock = 'Fill'
$groupReports.HideSelection = $false
$groupReports.FullRowSelect = $true

# Same classic appearance as Users and Computers
$groupReports.ShowLines = $true
$groupReports.ShowPlusMinus = $true
$groupReports.ShowRootLines = $true

# Same behavior as Users and Computers
$groupReports.Scrollable = $false
$groupReports.BorderStyle = 'None'
$groupReports.ItemHeight = 22

$groupReports.Font =
    New-Object System.Drawing.Font(
        'Segoe UI',
        9
    )


# ============================================================
# GENERAL REPORTS
# ============================================================

$groupGeneralNode =
    New-Object System.Windows.Forms.TreeNode(
        'General Reports'
    )

[void]$groupGeneralNode.Nodes.Add(
    'All Groups'
)

[void]$groupGeneralNode.Nodes.Add(
    'Security Groups'
)

[void]$groupGeneralNode.Nodes.Add(
    'Distribution Groups'
)


# ============================================================
# MEMBERSHIP REPORTS
# ============================================================

$groupMembershipNode =
    New-Object System.Windows.Forms.TreeNode(
        'Membership Reports'
    )

[void]$groupMembershipNode.Nodes.Add(
    'Group Members'
)

[void]$groupMembershipNode.Nodes.Add(
    'Nested Groups'
)


# ============================================================
# SCOPE REPORTS
# ============================================================

$groupScopeNode =
    New-Object System.Windows.Forms.TreeNode(
        'Scope Reports'
    )

[void]$groupScopeNode.Nodes.Add(
    'Global Groups'
)

[void]$groupScopeNode.Nodes.Add(
    'Universal Groups'
)

[void]$groupScopeNode.Nodes.Add(
    'Domain Local Groups'
)

# ============================================================
# ACTIVITY REPORTS
# ============================================================

$groupActivityNode =
    New-Object System.Windows.Forms.TreeNode(
        'Activity Reports'
    )

[void]$groupActivityNode.Nodes.Add(
    'Recently Created Groups - 30 Days'
)


# ============================================================
# OU REPORTS
# ============================================================

$groupOUNode =
    New-Object System.Windows.Forms.TreeNode(
        'OU Reports'
    )

[void]$groupOUNode.Nodes.Add(
    'Groups From OU'
)


# ============================================================
# ADD CATEGORIES TO TREE
# ============================================================

[void]$groupReports.Nodes.Add(
    $groupGeneralNode
)

[void]$groupReports.Nodes.Add(
    $groupMembershipNode
)

[void]$groupReports.Nodes.Add(
    $groupScopeNode
)

[void]$groupReports.Nodes.Add(
    $groupActivityNode
)

[void]$groupReports.Nodes.Add(
    $groupOUNode
)

$groupReports.ExpandAll()


# ============================================================
# ADD TREE TO LEFT PANEL
# ============================================================

$groupReportsPanel.Controls.Add(
    $groupReports
)

$groupsSplit.Panel1.Controls.Add(
    $groupReportsPanel
)


#
# RIGHT PANEL
#

$groupsRightLayout =
    New-Object System.Windows.Forms.TableLayoutPanel

$groupsRightLayout.Dock = 'Fill'
$groupsRightLayout.RowCount = 2
$groupsRightLayout.ColumnCount = 1

Add-RowStyle $groupsRightLayout 'Absolute' 72
Add-RowStyle $groupsRightLayout 'Percent' 100


# ============================================================
# GROUP TOOLBAR
# ============================================================

$groupsToolbar =
    New-Object System.Windows.Forms.FlowLayoutPanel

$groupsToolbar.Dock = 'Fill'

$groupsToolbar.Padding =
    New-Object System.Windows.Forms.Padding(
        8,7,0,0
    )

$groupsToolbar.FlowDirection = 'LeftToRight'
$groupsToolbar.WrapContents = $true


# ============================================================
# RUN REPORT BUTTON
# ============================================================

$btnRunGroupReport =
    New-Object System.Windows.Forms.Button

$btnRunGroupReport.Text = 'Run Report'
$btnRunGroupReport.Width = 100
$btnRunGroupReport.Enabled = $false


# ============================================================
# SELECT ATTRIBUTES BUTTON
# ============================================================

$btnSelectGroupAttributes =
    New-Object System.Windows.Forms.Button

$btnSelectGroupAttributes.Text =
    'Select Attributes'

$btnSelectGroupAttributes.Width = 120


# ============================================================
# EXPORT CSV BUTTON
# ============================================================

$btnExportGroups =
    New-Object System.Windows.Forms.Button

$btnExportGroups.Text = 'Export CSV'
$btnExportGroups.Width = 100
$btnExportGroups.Enabled = $false


# ============================================================
# SEARCH BOX
# ============================================================

$txtGroupReportSearch =
    New-Object System.Windows.Forms.TextBox

$txtGroupReportSearch.Width = 150


# ============================================================
# SEARCH BUTTON
# ============================================================

$btnGroupReportSearch =
    New-Object System.Windows.Forms.Button

$btnGroupReportSearch.Text = 'Search'
$btnGroupReportSearch.Width = 65


# ============================================================
# CLEAR BUTTON
# ============================================================

$btnClearGroupSearch =
    New-Object System.Windows.Forms.Button

$btnClearGroupSearch.Text = 'Clear'
$btnClearGroupSearch.Width = 55


# ============================================================
# SELECTED REPORT LABEL
# ============================================================

$lblSelectedGroupReport =
    New-Object System.Windows.Forms.Label

$lblSelectedGroupReport.Text =
    'No report selected'

$lblSelectedGroupReport.AutoSize = $true

$lblSelectedGroupReport.Margin =
    New-Object System.Windows.Forms.Padding(
        12,6,0,0
    )


# ============================================================
# ADD CONTROLS TO TOOLBAR
# ============================================================

[void]$groupsToolbar.Controls.Add(
    $btnRunGroupReport
)

[void]$groupsToolbar.Controls.Add(
    $btnSelectGroupAttributes
)

[void]$groupsToolbar.Controls.Add(
    $btnExportGroups
)

[void]$groupsToolbar.Controls.Add(
    $txtGroupReportSearch
)

[void]$groupsToolbar.Controls.Add(
    $btnGroupReportSearch
)

[void]$groupsToolbar.Controls.Add(
    $btnClearGroupSearch
)

# Force selected-report label onto line 2
$groupsToolbar.SetFlowBreak(
    $btnClearGroupSearch,
    $true
)

[void]$groupsToolbar.Controls.Add(
    $lblSelectedGroupReport
)


# ============================================================
# GROUP RESULTS GRID
# ============================================================

$gridInventoryGroups = New-Grid


# ============================================================
# GROUP ATTRIBUTE MASTER LIST
# ============================================================

$groupReportColumns = @(

    'Name'
    'SamAccountName'
    'DisplayName'

    'GroupCategory'
    'GroupScope'

    'EmailAddress'

    'ManagedBy'
    'MemberCount'

    'Description'

    'WhenCreated'
    'WhenChanged'

    'CanonicalName'
    'DistinguishedName'

    'MemberName'
    'MemberSamAccountName'
    'MemberObjectType'
    'MemberEmailAddress'
)


# ============================================================
# DEFAULT COLUMNS FOR EACH REPORT
# ============================================================

$groupReportAvailableColumns = @{

    'All Groups' = @(

        'Name'
        'SamAccountName'
        'DisplayName'
        'GroupCategory'
        'GroupScope'
        'EmailAddress'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )

    'Security Groups' = @(

        'Name'
        'SamAccountName'
        'DisplayName'
        'GroupCategory'
        'GroupScope'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )

    'Distribution Groups' = @(

        'Name'
        'SamAccountName'
        'DisplayName'
        'GroupCategory'
        'GroupScope'
        'EmailAddress'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
        'DistinguishedName'
    )


    'Group Members' = @(

        'Name'
        'SamAccountName'
        'GroupCategory'
        'GroupScope'
        'MemberName'
        'MemberSamAccountName'
        'MemberObjectType'
        'MemberEmailAddress'
    )

    'Nested Groups' = @(

        'Name'
        'SamAccountName'
        'GroupCategory'
        'GroupScope'
        'MemberName'
        'MemberSamAccountName'
        'MemberObjectType'
        'DistinguishedName'
    )

    'Global Groups' = @(

        'Name'
        'SamAccountName'
        'GroupCategory'
        'GroupScope'
        'EmailAddress'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
    )

    'Universal Groups' = @(

        'Name'
        'SamAccountName'
        'GroupCategory'
        'GroupScope'
        'EmailAddress'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
    )

    'Domain Local Groups' = @(

        'Name'
        'SamAccountName'
        'GroupCategory'
        'GroupScope'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
    )


    'Recently Created Groups - 30 Days' = @(

        'Name'
        'SamAccountName'
        'GroupCategory'
        'GroupScope'
        'EmailAddress'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'DistinguishedName'
    )

    'Groups From OU' = @(

        'Name'
        'SamAccountName'
        'DisplayName'
        'GroupCategory'
        'GroupScope'
        'EmailAddress'
        'ManagedBy'
        'MemberCount'
        'WhenCreated'
        'Description'
        'CanonicalName'
        'DistinguishedName'
    )
}


# ============================================================
# INITIAL SELECTED COLUMNS
# ============================================================

$script:SelectedGroupColumns = @(
    $groupReportColumns
)


# ============================================================
# ADD TOOLBAR AND GRID TO RIGHT LAYOUT
# ============================================================

$groupsRightLayout.Controls.Add(
    $groupsToolbar,
    0,
    0
)

$groupsRightLayout.Controls.Add(
    $gridInventoryGroups,
    0,
    1
)

$groupsSplit.Panel2.Controls.Add(
    $groupsRightLayout
)


# ============================================================
# ADD SPLIT CONTAINER TO GROUPS TAB
# ============================================================

$tabGroups.Controls.Add(
    $groupsSplit
)


# ============================================================
# APPLY SAME LEFT-PANEL WIDTH
# ============================================================

$groupsSplit.Panel1MinSize = 210
$groupsSplit.SplitterDistance = 210

$tabGroups.Add_Enter({

    if ($groupsSplit.Width -gt 500) {

        $groupsSplit.SplitterDistance = 210
    }
})


# ============================================================
# GROUP REPORT SELECTION
# ============================================================

$groupReports.Add_AfterSelect({

    if ($null -eq $groupReports.SelectedNode) {
        return
    }

    #
    # Category selected
    #

    if ($groupReports.SelectedNode.Level -eq 0) {

        $btnRunGroupReport.Enabled = $false

        $lblSelectedGroupReport.Text =
            'Select a report'

        return
    }

    #
    # Actual report selected
    #

    $btnRunGroupReport.Enabled = $true

    $selectedGroupReport =
        $groupReports.SelectedNode.Text

    $lblSelectedGroupReport.Text =
        'Selected Report: ' +
        $selectedGroupReport +
        ' - Click Run Report to load data.'

    #
    # Clear previous results when selecting another report
    #

    if (
        $script:CurrentGroupReportName -ne
        $selectedGroupReport
    ) {

        $script:CurrentGroupReport = @()
        $script:CurrentGroupReportName = ''

        $gridInventoryGroups.DataSource = $null
        $gridInventoryGroups.Columns.Clear()

        $txtGroupReportSearch.Clear()

        $btnExportGroups.Enabled = $false
    }
})

#
# ============================================================
# GROUP - RUN REPORT
# ============================================================
#

$btnRunGroupReport.Add_Click({

    if ($null -eq $groupReports.SelectedNode) {
        return
    }


    #
    # Category selected
    #

    if ($groupReports.SelectedNode.Level -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Please select a group report first.',
            'Group Reports',
            'OK',
            'Information'
        )

        return
    }


    $selectedReport =
        $groupReports.SelectedNode.Text


    try {

        $btnRunGroupReport.Enabled = $false
        $btnRunGroupReport.Text = 'Running...'

        $lblSelectedGroupReport.Text =
            "Running $selectedReport... Please wait."

        $w.UseWaitCursor = $true
        $w.Refresh()

        [System.Windows.Forms.Application]::DoEvents()


        #
        # Run selected Group report
        #

        switch ($selectedReport) {

            'All Groups' {

                $rows =
                    Get-AllGroupsReport
            }


            'Security Groups' {

                $rows =
                    Get-SecurityGroupsReport
            }


            'Distribution Groups' {

                $rows =
                    Get-DistributionGroupsReport
            }

            'Group Members' {

    $groupName =
        Show-GroupNameDialog

    if (
        [string]::IsNullOrWhiteSpace(
            $groupName
        )
    ) {
        return
    }


    $rows =
        Get-GroupMembersInventoryReport `
            -GroupIdentity $groupName


    $script:SelectedGroupName =
        $groupName
    }

    'Nested Groups' {

    $groupName =
        Show-GroupNameDialog

    if (
        [string]::IsNullOrWhiteSpace(
            $groupName
        )
    ) {
        return
    }


    $rows =
        Get-NestedGroupsReport `
            -GroupIdentity $groupName


    $script:SelectedGroupName =
        $groupName
}

'Global Groups' {

    $rows =
        Get-GlobalGroupsReport
}


'Universal Groups' {

    $rows =
        Get-UniversalGroupsReport
}


'Domain Local Groups' {

    $rows =
        Get-DomainLocalGroupsReport
}

'Recently Created Groups - 30 Days' {

    $rows =
        Get-RecentlyCreatedGroupsReport
}

'Groups From OU' {

    $selectedOU =
        Show-OUSelectionDialog

    if ($null -eq $selectedOU) {
        return
    }


    $rows =
        Get-GroupsFromOUReport `
            -SearchBase $selectedOU.DistinguishedName


    $script:SelectedGroupOUName =
        $selectedOU.CanonicalName
}

            default {

                [void][System.Windows.Forms.MessageBox]::Show(
                    "$selectedReport not implemented yet.",
                    'Group Reports',
                    'OK',
                    'Information'
                )

                return
            }
        }


        #
        # Store current report
        #

        $script:CurrentGroupReport =
            @($rows)

        $script:CurrentGroupReportName =
            $selectedReport


        #
        # Apply report default columns
        #

        if (
            $groupReportAvailableColumns.ContainsKey(
                $selectedReport
            )
        ) {

            $script:SelectedGroupColumns = @(

                $groupReportAvailableColumns[
                    $selectedReport
                ]
            )
        }
        else {

            $script:SelectedGroupColumns = @(
                $groupReportColumns
            )
        }


        #
        # Display results
        #

        Set-GridRows `
            -Grid $gridInventoryGroups `
            -Rows $script:CurrentGroupReport `
            -Columns $script:SelectedGroupColumns


        #
        # Export availability
        #

        $btnExportGroups.Enabled = (
            $script:CurrentGroupReport.Count -gt 0
        )


#
# Result label
#

if (
    $selectedReport -eq 'Group Members' -and
    -not [string]::IsNullOrWhiteSpace(
        $script:SelectedGroupName
    )
) {

    $lblSelectedGroupReport.Text = (
        'Group Members: {0} - {1} member(s)' -f
        $script:SelectedGroupName,
        $script:CurrentGroupReport.Count
    )
}
elseif (
    $selectedReport -eq 'Nested Groups' -and
    -not [string]::IsNullOrWhiteSpace(
        $script:SelectedGroupName
    )
) {

    $lblSelectedGroupReport.Text = (
        'Nested Groups: {0} - {1} nested group(s)' -f
        $script:SelectedGroupName,
        $script:CurrentGroupReport.Count
    )
}
elseif (
    $selectedReport -eq 'Groups From OU' -and
    -not [string]::IsNullOrWhiteSpace(
        $script:SelectedGroupOUName
    )
) {

    $lblSelectedGroupReport.Text = (
        'Groups From OU: {0} - {1} group(s)' -f
        $script:SelectedGroupOUName,
        $script:CurrentGroupReport.Count
    )
}
else {

    $lblSelectedGroupReport.Text = (
        '{0} - {1} record(s)' -f
        $selectedReport,
        $script:CurrentGroupReport.Count
    )
}
    }

    catch {

        [void][System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Group Report Error',
            'OK',
            'Error'
        )
    }

    finally {

        $w.UseWaitCursor = $false

        $btnRunGroupReport.Text =
            'Run Report'

        $btnRunGroupReport.Enabled =
            $true
    }
})
#
# ============================================================
# GROUP - SELECT ATTRIBUTES
# ============================================================
#

$btnSelectGroupAttributes.Add_Click({

    #
    # Create form
    #

    $f = New-Object System.Windows.Forms.Form

    $f.Text = 'Select Group Attributes'
    $f.BackColor = 'White'
    $f.StartPosition = 'CenterParent'

    $f.Size =
        New-Object System.Drawing.Size(
            380,
            520
        )


    #
    # Information label
    #

    $lblInfo =
        New-Object System.Windows.Forms.Label

    $lblInfo.Dock = 'Top'
    $lblInfo.Height = 40

    $lblInfo.Font =
        New-Object System.Drawing.Font(
            'Segoe UI',
            9,
            [System.Drawing.FontStyle]::Bold
        )


    #
    # Attribute list
    #

    $list =
        New-Object System.Windows.Forms.CheckedListBox

    $list.Dock = 'Fill'
    $list.CheckOnClick = $true


    #
    # Add Group attributes
    #

    foreach ($col in $groupReportColumns) {

        $index =
            $list.Items.Add($col)

        if (
            $script:SelectedGroupColumns -contains
            $col
        ) {

            $list.SetItemChecked(
                $index,
                $true
            )
        }
    }


    #
    # Attribute count
    #

    $lblInfo.Text =
        "Total Attributes: $($list.Items.Count)"


    #
    # Select All button
    #

    $btnSelectAll =
        New-Object System.Windows.Forms.Button

    $btnSelectAll.Text = 'Select All'
    $btnSelectAll.Width = 80


    #
    # Clear All button
    #

    $btnClearAll =
        New-Object System.Windows.Forms.Button

    $btnClearAll.Text = 'Clear All'
    $btnClearAll.Width = 80


    #
    # Apply button
    #

    $btnApply =
        New-Object System.Windows.Forms.Button

    $btnApply.Text = 'Apply'
    $btnApply.Width = 80


    #
    # Close button
    #

    $btnClose =
        New-Object System.Windows.Forms.Button

    $btnClose.Text = 'Close'
    $btnClose.Width = 80


    #
    # Select All action
    #

    $btnSelectAll.Add_Click({

        for (
            $i = 0
            $i -lt $list.Items.Count
            $i++
        ) {

            $list.SetItemChecked(
                $i,
                $true
            )
        }
    })


    #
    # Clear All action
    #

    $btnClearAll.Add_Click({

        for (
            $i = 0
            $i -lt $list.Items.Count
            $i++
        ) {

            $list.SetItemChecked(
                $i,
                $false
            )
        }
    })


    #
    # Close action
    #

    $btnClose.Add_Click({

        $f.Close()
    })


    #
    # Apply selected attributes
    #

    $btnApply.Add_Click({

        $selected = @()


        #
        # Collect checked attributes
        #

        foreach ($item in $list.CheckedItems) {

            $selected +=
                [string]$item
        }


        #
        # Require at least one attribute
        #

        if ($selected.Count -eq 0) {

            [void][System.Windows.Forms.MessageBox]::Show(
                'Please select at least one attribute.',
                'Select Attributes',
                'OK',
                'Information'
            )

            return
        }


        #
        # Store selected attributes
        #

        $script:SelectedGroupColumns =
            @($selected)


        #
        # Refresh currently loaded report
        #

        if (
            @($script:CurrentGroupReport).Count -gt 0
        ) {

            Set-GridRows `
                -Grid $gridInventoryGroups `
                -Rows $script:CurrentGroupReport `
                -Columns $script:SelectedGroupColumns
        }


        #
        # Close form after Apply
        #

        $f.Close()
    })


    #
    # Bottom button panel
    #

    $buttonPanel =
        New-Object System.Windows.Forms.FlowLayoutPanel

    $buttonPanel.Dock = 'Bottom'
    $buttonPanel.Height = 55

    $buttonPanel.FlowDirection =
        'LeftToRight'

    $buttonPanel.Padding =
        New-Object System.Windows.Forms.Padding(5)


    #
    # Add buttons
    #

    [void]$buttonPanel.Controls.Add(
        $btnClose
    )

    [void]$buttonPanel.Controls.Add(
        $btnApply
    )

    [void]$buttonPanel.Controls.Add(
        $btnClearAll
    )

    [void]$buttonPanel.Controls.Add(
        $btnSelectAll
    )


    #
    # Add controls to form
    #

    $f.Controls.Add(
        $list
    )

    $f.Controls.Add(
        $lblInfo
    )

    $f.Controls.Add(
        $buttonPanel
    )


    #
    # Show dialog
    #

    [void]$f.ShowDialog($w)
})
        
#
# ============================================================
# GROUP - EXPORT CSV
# ============================================================
#

$btnExportGroups.Add_Click({

    #
    # Make sure a Group report is loaded
    #

    if (@($script:CurrentGroupReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a group report first.',
            'Export',
            'OK',
            'Information'
        )

        return
    }


    #
    # Create Save dialog
    #

    $saveDialog =
        New-Object System.Windows.Forms.SaveFileDialog

    $saveDialog.Title =
        'Export Group Report'

    $saveDialog.Filter =
        'CSV Files (*.csv)|*.csv'


    #
    # Create safe filename
    #

    $safeReportName =
        $script:CurrentGroupReportName -replace '[\\/:*?"<>|]', '-'


    $saveDialog.FileName = (
        $safeReportName +
        '-' +
        (Get-Date -Format 'yyyyMMdd-HHmmss') +
        '.csv'
    )


    #
    # Show Save dialog
    #

    if (
        $saveDialog.ShowDialog() -eq
        [System.Windows.Forms.DialogResult]::OK
    ) {

        #
        # Export currently selected attributes
        #

        $script:CurrentGroupReport |
            Select-Object $script:SelectedGroupColumns |
            Export-Csv `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Path $saveDialog.FileName


        [void][System.Windows.Forms.MessageBox]::Show(
            'Export completed successfully.',
            'Export',
            'OK',
            'Information'
        )
    }
})

#
# ============================================================
# GROUP - SEARCH
# ============================================================
#

$btnGroupReportSearch.Add_Click({

    #
    # Make sure a report is loaded
    #

    if (@($script:CurrentGroupReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a group report before searching.',
            'Search Group Report',
            'OK',
            'Information'
        )

        return
    }


    #
    # Get search text
    #

    $searchText =
        $txtGroupReportSearch.Text.Trim()


    if ([string]::IsNullOrWhiteSpace($searchText)) {
        return
    }


    #
    # Search all currently selected attributes
    #

    $filteredRows = @(

        $script:CurrentGroupReport |

            Where-Object {

                $row = $_
                $matched = $false


                foreach (
                    $column in
                    $script:SelectedGroupColumns
                ) {

                    $property =
                        $row.PSObject.Properties[$column]


                    if (
                        $null -ne $property -and
                        $null -ne $property.Value
                    ) {

                        if (
                            $property.Value.ToString() -like
                            "*$searchText*"
                        ) {

                            $matched = $true
                            break
                        }
                    }
                }


                $matched
            }
    )


    #
    # Display filtered results
    #

    Set-GridRows `
        -Grid $gridInventoryGroups `
        -Rows $filteredRows `
        -Columns $script:SelectedGroupColumns


    #
    # Update status
    #

    $lblSelectedGroupReport.Text = (
        '{0} - Search Results: {1}' -f
        $script:CurrentGroupReportName,
        $filteredRows.Count
    )
})

#
# ============================================================
# GROUP - CLEAR SEARCH
# ============================================================
#

$btnClearGroupSearch.Add_Click({

    #
    # Clear search box
    #

    $txtGroupReportSearch.Clear()


    #
    # Restore original Group report
    #

    if (@($script:CurrentGroupReport).Count -gt 0) {

        Set-GridRows `
            -Grid $gridInventoryGroups `
            -Rows $script:CurrentGroupReport `
            -Columns $script:SelectedGroupColumns


        #
        # Restore status
        #

        $lblSelectedGroupReport.Text = (
            '{0} - {1} record(s)' -f
            $script:CurrentGroupReportName,
            $script:CurrentGroupReport.Count
        )
    }
})

#
# ============================================================
# GROUP - PRESS ENTER TO SEARCH
# ============================================================
#

$txtGroupReportSearch.Add_KeyDown({

    if (
        $_.KeyCode -eq
        [System.Windows.Forms.Keys]::Enter
    ) {

        $btnGroupReportSearch.PerformClick()

        $_.SuppressKeyPress = $true
    }
})

# ============================================================
# DC HEALTH REPORT FUNCTIONS
# ============================================================
function Get-DCRemoteServiceStatus {

    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [string]$ServiceName,

        [switch]$Optional
    )

    try {

        $service =
            Get-Service `
                -ComputerName $ComputerName `
                -Name $ServiceName `
                -ErrorAction Stop

        return [string]$service.Status
    }
    catch {

        if ($Optional) {

            return 'Not Installed'
        }

        return 'Unknown'
    }
}
function Get-ForestDomainControllers {

    Import-Module ActiveDirectory -ErrorAction Stop

    #
    # Get current Active Directory forest
    #

    $forest =
        Get-ADForest `
            -ErrorAction Stop

    $domainControllers = @()
    $discoveryFailures = @()


    #
    # Query every domain in the forest
    #

    foreach ($domainName in $forest.Domains) {

        try {

            $domainDCs = @(
                Get-ADDomainController `
                    -Filter * `
                    -Server $domainName `
                    -ErrorAction Stop
            )

            $domainControllers +=
                $domainDCs
        }
        catch {

            $discoveryFailures +=
                [PSCustomObject]@{

                    Domain =
                        [string]$domainName

                    Error =
                        $_.Exception.Message
                }
        }
    }


    #
    # Remove duplicate DC objects by HostName
    #

    $uniqueDomainControllers = @(
        $domainControllers |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace(
                    [string]$_.HostName
                )
            } |
            Sort-Object HostName -Unique
    )


    return [PSCustomObject]@{

        ForestName =
            [string]$forest.Name

        DomainControllers =
            @($uniqueDomainControllers)

        DiscoveryFailures =
            @($discoveryFailures)
    }
}
function Get-DCHealthCheckReport {

    Import-Module ActiveDirectory -ErrorAction Stop


    #
    # Discover all DCs across the current forest
    #

    $forestDiscovery =
        Get-ForestDomainControllers

    $forestName =
        [string]$forestDiscovery.ForestName

    $domainControllers =
        @($forestDiscovery.DomainControllers)

    $discoveryFailures =
        @($forestDiscovery.DiscoveryFailures)


    #
    # Ensure at least one DC was discovered
    #

    if ($domainControllers.Count -eq 0) {

        throw (
            'No domain controllers could be discovered ' +
            'in the current Active Directory forest.'
        )
    }


    #
    # Create one health row per DC
    #

    $rows = foreach ($dc in $domainControllers) {

        $hostName =
            [string]$dc.HostName


        #
        # Default connectivity values
        #

        $icmpStatus = 'Not Tested'
        $ldap389Status = 'Not Tested'
        $ldaps636Status = 'Not Tested'
        $rpc135Status = 'Not Tested'


        #
        # Default service values
        #

        $ntdsStatus = 'Not Tested'
        $netlogonStatus = 'Not Tested'
        $kdcStatus = 'Not Tested'
        $dnsClientStatus = 'Not Tested'
        $dnsServerStatus = 'Not Tested'
        $dfsrStatus = 'Not Tested'


        #
        # Default share values
        #

        $sysvolShareStatus = 'Not Tested'
        $netlogonShareStatus = 'Not Tested'

        #
        # Default replication values
        #

        $replicationStatus = 'Not Tested'
        $replicationPartners = 0
        $lastReplicationSuccess = $null
        $replicationIssues = ''

        #
        # Issue collection
        #

        $issues =
            New-Object System.Collections.Generic.List[string]


        #
        # ICMP / ping test
        #

        try {

            $icmpResult =
                Test-Connection `
                    -ComputerName $hostName `
                    -Count 1 `
                    -Quiet `
                    -ErrorAction Stop

            if ($icmpResult) {

                $icmpStatus = 'Available'
            }
            else {

                $icmpStatus = 'Unavailable'

                [void]$issues.Add(
                    'ICMP response is unavailable'
                )
            }
        }
        catch {

            $icmpStatus = 'Unknown'

            [void]$issues.Add(
                'ICMP response could not be tested'
            )
        }


        #
        # LDAP port 389
        #

        try {

            $ldap389Result =
                Test-NetConnection `
                    -ComputerName $hostName `
                    -Port 389 `
                    -InformationLevel Quiet `
                    -WarningAction SilentlyContinue `
                    -ErrorAction Stop

            if ($ldap389Result) {

                $ldap389Status = 'Available'
            }
            else {

                $ldap389Status = 'Unavailable'

                [void]$issues.Add(
                    'LDAP port 389 is unavailable'
                )
            }
        }
        catch {

            $ldap389Status = 'Unknown'

            [void]$issues.Add(
                'LDAP port 389 could not be tested'
            )
        }


        #
        # LDAPS port 636
        #

        try {

            $ldaps636Result =
                Test-NetConnection `
                    -ComputerName $hostName `
                    -Port 636 `
                    -InformationLevel Quiet `
                    -WarningAction SilentlyContinue `
                    -ErrorAction Stop

            if ($ldaps636Result) {

                $ldaps636Status = 'Available'
            }
            else {

                $ldaps636Status = 'Unavailable'

                [void]$issues.Add(
                    'LDAPS port 636 is unavailable'
                )
            }
        }
        catch {

            $ldaps636Status = 'Unknown'

            [void]$issues.Add(
                'LDAPS port 636 could not be tested'
            )
        }


        #
        # RPC endpoint mapper port 135
        #

        try {

            $rpc135Result =
                Test-NetConnection `
                    -ComputerName $hostName `
                    -Port 135 `
                    -InformationLevel Quiet `
                    -WarningAction SilentlyContinue `
                    -ErrorAction Stop

            if ($rpc135Result) {

                $rpc135Status = 'Available'
            }
            else {

                $rpc135Status = 'Unavailable'

                [void]$issues.Add(
                    'RPC port 135 is unavailable'
                )
            }
        }
        catch {

            $rpc135Status = 'Unknown'

            [void]$issues.Add(
                'RPC port 135 could not be tested'
            )
        }


        #
        # Core Domain Controller services
        #

        $ntdsStatus =
            Get-DCRemoteServiceStatus `
                -ComputerName $hostName `
                -ServiceName 'NTDS'


        $netlogonStatus =
            Get-DCRemoteServiceStatus `
                -ComputerName $hostName `
                -ServiceName 'Netlogon'


        $kdcStatus =
            Get-DCRemoteServiceStatus `
                -ComputerName $hostName `
                -ServiceName 'KDC'


        $dnsClientStatus =
            Get-DCRemoteServiceStatus `
                -ComputerName $hostName `
                -ServiceName 'Dnscache'


        #
        # Optional services
        #

        $dnsServerStatus =
            Get-DCRemoteServiceStatus `
                -ComputerName $hostName `
                -ServiceName 'DNS' `
                -Optional


        $dfsrStatus =
            Get-DCRemoteServiceStatus `
                -ComputerName $hostName `
                -ServiceName 'DFSR' `
                -Optional


        #
        # Required service issues
        #

        if ($ntdsStatus -ne 'Running') {

            [void]$issues.Add(
                "NTDS service: $ntdsStatus"
            )
        }


        if ($netlogonStatus -ne 'Running') {

            [void]$issues.Add(
                "Netlogon service: $netlogonStatus"
            )
        }


        if ($kdcStatus -ne 'Running') {

            [void]$issues.Add(
                "KDC service: $kdcStatus"
            )
        }


        if ($dnsClientStatus -ne 'Running') {

            [void]$issues.Add(
                "DNS Client service: $dnsClientStatus"
            )
        }


        #
        # Optional service issues
        #

        if (
            $dnsServerStatus -ne 'Running' -and
            $dnsServerStatus -ne 'Not Installed'
        ) {

            [void]$issues.Add(
                "DNS Server service: $dnsServerStatus"
            )
        }


        if (
            $dfsrStatus -ne 'Running' -and
            $dfsrStatus -ne 'Not Installed'
        ) {

            [void]$issues.Add(
                "DFSR service: $dfsrStatus"
            )
        }


        #
        # SYSVOL share
        #

        try {

            $sysvolPath =
                "\\$hostName\SYSVOL"

            if (
                Test-Path `
                    -Path $sysvolPath `
                    -ErrorAction Stop
            ) {

                $sysvolShareStatus = 'Available'
            }
            else {

                $sysvolShareStatus = 'Unavailable'

                [void]$issues.Add(
                    'SYSVOL share is unavailable'
                )
            }
        }
        catch {

            $sysvolShareStatus = 'Unknown'

            [void]$issues.Add(
                'SYSVOL share could not be tested'
            )
        }


        #
        # NETLOGON share
        #

        try {

            $netlogonPath =
                "\\$hostName\NETLOGON"

            if (
                Test-Path `
                    -Path $netlogonPath `
                    -ErrorAction Stop
            ) {

                $netlogonShareStatus = 'Available'
            }
            else {

                $netlogonShareStatus = 'Unavailable'

                [void]$issues.Add(
                    'NETLOGON share is unavailable'
                )
            }
        }
        catch {

            $netlogonShareStatus = 'Unknown'

            [void]$issues.Add(
                'NETLOGON share could not be tested'
            )
        }

        #
# ============================================================
# REPLICATION HEALTH
# ============================================================
#

try {

    $replicationData = @(
        Get-ADReplicationPartnerMetadata `
            -Target $hostName `
            -PartnerType Inbound `
            -ErrorAction Stop
    )


    #
    # Single DC / no inbound replication partner
    #

    if ($replicationData.Count -eq 0) {

        $replicationStatus = 'No Partners'
        $replicationPartners = 0
        $lastReplicationSuccess = $null
        $replicationIssues = ''
    }
    else {

        #
        # Partner count
        #

        $replicationPartners =
            $replicationData.Count


        #
        # Latest successful inbound replication
        #

        $successfulReplicationDates = @(

            $replicationData |
                Where-Object {
                    $null -ne $_.LastReplicationSuccess
                } |
                ForEach-Object {
                    [datetime]$_.LastReplicationSuccess
                }
        )


        if ($successfulReplicationDates.Count -gt 0) {

            $lastReplicationSuccess =
                (
                    $successfulReplicationDates |
                    Sort-Object -Descending |
                    Select-Object -First 1
                )
        }


        #
        # Detect replication failures
        #

        $failedPartners = @(

            $replicationData |
                Where-Object {

                    $resultProperty =
                        $_.PSObject.Properties[
                            'LastReplicationResult'
                        ]

                    $resultProperty -and
                    $null -ne $resultProperty.Value -and
                    [int]$resultProperty.Value -ne 0
                }
        )


        if ($failedPartners.Count -gt 0) {

            $replicationStatus = 'Failed'


            $replicationIssueList =
                New-Object System.Collections.Generic.List[string]


            foreach ($partner in $failedPartners) {

                $partnerName =
                    [string]$partner.Partner

                $result =
                    [string]$partner.LastReplicationResult


                [void]$replicationIssueList.Add(
                    (
                        '{0} (Result {1})' -f
                        $partnerName,
                        $result
                    )
                )
            }


            $replicationIssues =
                $replicationIssueList -join '; '


            [void]$issues.Add(
                (
                    'Replication failure: {0}' -f
                    $replicationIssues
                )
            )
        }
        else {

            $replicationStatus = 'Healthy'
            $replicationIssues = ''
        }
    }
}
catch {

    $replicationStatus = 'Unknown'
    $replicationIssues = $_.Exception.Message

    [void]$issues.Add(
        'Replication health could not be determined'
    )
}
        #
        # Overall health classification
        #
        # Critical:
        # LDAP 389 or RPC 135 is unavailable.
        #
        # Warning:
        # Other checks failed, including ICMP or LDAPS 636.
        #
        # Healthy:
        # No detected issues.
        #

        $overallStatus = 'Healthy'


        if (
    $ldap389Status -eq 'Unavailable' -or
    $rpc135Status -eq 'Unavailable' -or
    $replicationStatus -eq 'Failed'
    ) {

    $overallStatus = 'Critical'
    }
    elseif ($issues.Count -gt 0) {
    
    $overallStatus = 'Warning'
    }


        #
        # Consolidated issue text
        #

        $issueText = ''

        if ($issues.Count -gt 0) {

            $issueText =
                $issues -join '; '
        }


        #
        # Return one row per DC
        #

        [PSCustomObject]@{

            Forest =
                $forestName

            Domain =
                [string]$dc.Domain

            HostName =
                $hostName

            Site =
                [string]$dc.Site

            IPv4Address =
                [string]$dc.IPv4Address

            OverallStatus =
                $overallStatus

            ICMP =
                $icmpStatus

            LDAP389 =
                $ldap389Status

            LDAPS636 =
                $ldaps636Status

            RPC135 =
                $rpc135Status

            NTDS =
                $ntdsStatus

            Netlogon =
                $netlogonStatus

            KDC =
                $kdcStatus

            DNSClient =
                $dnsClientStatus

            DNSServer =
                $dnsServerStatus

            DFSR =
                $dfsrStatus

            SYSVOLShare =
                $sysvolShareStatus

            NETLOGONShare =
                 $netlogonShareStatus

            ReplicationStatus =
                 $replicationStatus

            ReplicationPartners =
                $replicationPartners

            LastReplicationSuccess =
                $lastReplicationSuccess

            ReplicationIssues =
                $replicationIssues

            IsGlobalCatalog =
                $dc.IsGlobalCatalog

            IsReadOnly =
                $dc.IsReadOnly

            Issues =
                $issueText
        }
    }


    #
    # Add a row for each forest-domain discovery failure
    #
    # This allows partial forest results instead of failing
    # the complete report.
    #

    foreach ($failure in $discoveryFailures) {

        $rows +=
            [PSCustomObject]@{

                Forest =
                    $forestName

                Domain =
                    [string]$failure.Domain

                HostName =
                    ''

                Site =
                    ''

                IPv4Address =
                    ''

                OverallStatus =
                    'Critical'

                ICMP =
                    'Not Tested'

                LDAP389 =
                    'Not Tested'

                LDAPS636 =
                    'Not Tested'

                RPC135 =
                    'Not Tested'

                NTDS =
                    'Not Tested'

                Netlogon =
                    'Not Tested'

                KDC =
                    'Not Tested'

                DNSClient =
                    'Not Tested'

                DNSServer =
                    'Not Tested'

                DFSR =
                    'Not Tested'

                SYSVOLShare =
                    'Not Tested'

                NETLOGONShare =
                    'Not Tested'

                ReplicationStatus =
                    'Not Tested'

                ReplicationPartners =
                    0

                LastReplicationSuccess =
                    $null

                ReplicationIssues =
                    ''

                IsGlobalCatalog =
                    ''

                IsReadOnly =
                    ''

                Issues = (
                    'Domain controller discovery failed: {0}' -f
                    $failure.Error
                )
            }
    }


    return @(
        $rows |
            Sort-Object Domain, HostName
    )
}

function Get-DCReplicationStatusReport {

    Import-Module ActiveDirectory -ErrorAction Stop


    #
    # Discover all DCs across the forest
    #

    $forestDiscovery =
        Get-ForestDomainControllers

    $forestName =
        [string]$forestDiscovery.ForestName

    $domainControllers =
        @($forestDiscovery.DomainControllers)

    $rows =
        New-Object System.Collections.Generic.List[object]


    #
    # Get replication information from every DC
    #

    foreach ($dc in $domainControllers) {

        $hostName =
            [string]$dc.HostName

        $domainName =
            [string]$dc.Domain

        $siteName =
            [string]$dc.Site


        try {

            $replicationData = @(
                Get-ADReplicationPartnerMetadata `
                    -Target $hostName `
                    -PartnerType Inbound `
                    -Partition * `
                    -ErrorAction Stop
            )


            #
            # Single DC / no inbound partners
            #

            if ($replicationData.Count -eq 0) {

                [void]$rows.Add(
                    [PSCustomObject]@{

                        Forest =
                            $forestName

                        Domain =
                            $domainName

                        Server =
                            $hostName

                        Site =
                            $siteName

                        Partner =
                            ''

                        Partition =
                            ''

                        LastReplicationAttempt =
                            $null

                        LastReplicationSuccess =
                            $null

                        LastReplicationResult =
                            ''

                        ConsecutiveReplicationFailures =
                            0

                        Status =
                            'No Partners'

                        Error =
                            ''
                    }
                )

                continue
            }


            #
            # One row per replication partner / partition
            #

            foreach ($replication in $replicationData) {

                $status = 'Healthy'
                $errorText = ''


                #
                # Last replication result
                #

                $resultProperty =
                    $replication.PSObject.Properties[
                        'LastReplicationResult'
                    ]


                $lastResult = $null

                if (
                    $null -ne $resultProperty -and
                    $null -ne $resultProperty.Value
                ) {

                    $lastResult =
                        [int]$resultProperty.Value
                }


                #
                # Consecutive failure count
                #

                $failureProperty =
                    $replication.PSObject.Properties[
                        'ConsecutiveReplicationFailures'
                    ]


                $failureCount = 0

                if (
                    $null -ne $failureProperty -and
                    $null -ne $failureProperty.Value
                ) {

                    $failureCount =
                        [int]$failureProperty.Value
                }


                #
                # Determine status
                #

                if (
                    $null -ne $lastResult -and
                    $lastResult -ne 0
                ) {

                    $status = 'Failed'

                    $errorText = (
                        'Replication result {0}' -f
                        $lastResult
                    )
                }
                elseif ($failureCount -gt 0) {

                    $status = 'Failed'

                    $errorText = (
                        '{0} consecutive replication failure(s)' -f
                        $failureCount
                    )
                }


                #
                # Add result row
                #

                [void]$rows.Add(
                    [PSCustomObject]@{

                        Forest =
                            $forestName

                        Domain =
                            $domainName

                        Server =
                            $hostName

                        Site =
                            $siteName

                        Partner =
                            [string]$replication.Partner

                        Partition =
                            [string]$replication.Partition

                        LastReplicationAttempt =
                            $replication.LastReplicationAttempt

                        LastReplicationSuccess =
                            $replication.LastReplicationSuccess

                        LastReplicationResult =
                            $lastResult

                        ConsecutiveReplicationFailures =
                            $failureCount

                        Status =
                            $status

                        Error =
                            $errorText
                    }
                )
            }
        }
        catch {

            #
            # Query failure for this DC should not stop
            # the complete forest report
            #

            [void]$rows.Add(
                [PSCustomObject]@{

                    Forest =
                        $forestName

                    Domain =
                        $domainName

                    Server =
                        $hostName

                    Site =
                        $siteName

                    Partner =
                        ''

                    Partition =
                        ''

                    LastReplicationAttempt =
                        $null

                    LastReplicationSuccess =
                        $null

                    LastReplicationResult =
                        ''

                    ConsecutiveReplicationFailures =
                        ''

                    Status =
                        'Unknown'

                    Error =
                        $_.Exception.Message
                }
            )
        }
    }


    return @(
        $rows |
            Sort-Object Domain, Server, Partner, Partition
    )
}

function Get-DCReplicationFailuresReport {

    #
    # Reuse existing Replication Status report
    #

    $replicationRows = @(
        Get-DCReplicationStatusReport
    )


    #
    # Return only actual replication failures
    #

    $failedRows = @(
        $replicationRows |
            Where-Object {
                $_.Status -eq 'Failed'
            }
    )


    return @($failedRows)
}
function Get-FSMORoleHoldersReport {

    Import-Module ActiveDirectory -ErrorAction Stop


    #
    # Get current forest
    #

    $forest =
        Get-ADForest `
            -ErrorAction Stop


    #
    # Use normal PowerShell array
    #

    $rows = @()


    #
    # Forest FSMO Role - Schema Master
    #

    $rows +=
        [PSCustomObject]@{

            Forest =
                [string]$forest.Name

            Domain =
                ''

            Scope =
                'Forest'

            Role =
                'Schema Master'

            RoleHolder =
                [string]$forest.SchemaMaster
        }


    #
    # Forest FSMO Role - Domain Naming Master
    #

    $rows +=
        [PSCustomObject]@{

            Forest =
                [string]$forest.Name

            Domain =
                ''

            Scope =
                'Forest'

            Role =
                'Domain Naming Master'

            RoleHolder =
                [string]$forest.DomainNamingMaster
        }


    #
    # Domain-level FSMO roles
    #

    foreach ($domainName in $forest.Domains) {

        try {

            $domain =
                Get-ADDomain `
                    -Identity $domainName `
                    -Server $domainName `
                    -ErrorAction Stop


            #
            # PDC Emulator
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        [string]$forest.Name

                    Domain =
                        [string]$domain.DNSRoot

                    Scope =
                        'Domain'

                    Role =
                        'PDC Emulator'

                    RoleHolder =
                        [string]$domain.PDCEmulator
                }


            #
            # RID Master
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        [string]$forest.Name

                    Domain =
                        [string]$domain.DNSRoot

                    Scope =
                        'Domain'

                    Role =
                        'RID Master'

                    RoleHolder =
                        [string]$domain.RIDMaster
                }


            #
            # Infrastructure Master
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        [string]$forest.Name

                    Domain =
                        [string]$domain.DNSRoot

                    Scope =
                        'Domain'

                    Role =
                        'Infrastructure Master'

                    RoleHolder =
                        [string]$domain.InfrastructureMaster
                }
        }
        catch {

            #
            # Do not stop the complete forest report
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        [string]$forest.Name

                    Domain =
                        [string]$domainName

                    Scope =
                        'Domain'

                    Role =
                        'Query Error'

                    RoleHolder =
                        [string]$_.Exception.Message
                }
        }
    }


    #
    # Return normal PowerShell array
    #

    return $rows
}

function Get-DCDiagReport {

    Import-Module ActiveDirectory -ErrorAction Stop


    #
    # Make sure DCDiag exists
    #

    $dcdiagCommand =
        Get-Command `
            -Name 'dcdiag.exe' `
            -ErrorAction SilentlyContinue


    if ($null -eq $dcdiagCommand) {

        throw (
            'DCDiag.exe was not found. ' +
            'Run this utility from a Domain Controller ' +
            'or a computer with the required AD DS/RSAT tools installed.'
        )
    }


    #
    # Discover all DCs across the forest
    #

    $forestDiscovery =
        Get-ForestDomainControllers


    $forestName =
        [string]$forestDiscovery.ForestName


    $domainControllers =
        @($forestDiscovery.DomainControllers)


    if ($domainControllers.Count -eq 0) {

        throw 'No domain controllers were discovered.'
    }


    #
    # Result collection
    #

    $rows = @()


    #
    # Run DCDiag against each discovered DC
    #

    foreach ($dc in $domainControllers) {

        $hostName =
            [string]$dc.HostName

        $domainName =
            [string]$dc.Domain

        $siteName =
            [string]$dc.Site


        try {

            #
            # Run DCDiag
            #
            # /s = specific DC
            # /q = return errors only
            #

            $output = @(
                & $dcdiagCommand.Source `
                    "/s:$hostName" `
                    '/q' `
                    2>&1
            )


            $exitCode =
                $LASTEXITCODE


            #
            # Convert console output to text
            #

            $outputText =
                (
                    $output |
                        ForEach-Object {
                            $_.ToString()
                        }
                ) -join ' '


            #
            # Clean excessive whitespace
            #

            $outputText =
                $outputText `
                    -replace '\s+', ' '

            $outputText =
                $outputText.Trim()


            #
            # Determine our report status
            #

            if (
                $exitCode -eq 0 -and
                [string]::IsNullOrWhiteSpace(
                    $outputText
                )
            ) {

                $status = 'Passed'
                $issues = ''
            }
            else {

                $status = 'Issues Found'

                if (
                    [string]::IsNullOrWhiteSpace(
                        $outputText
                    )
                ) {

                    $issues =
                        "DCDiag returned exit code $exitCode"
                }
                else {

                    $issues =
                        $outputText
                }
            }


            #
            # Result row
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        $forestName

                    Domain =
                        $domainName

                    HostName =
                        $hostName

                    Site =
                        $siteName

                    Status =
                        $status

                    ExitCode =
                        $exitCode

                    Issues =
                        $issues
                }
        }
        catch {

            #
            # Failure for one DC must not stop
            # diagnostics for remaining DCs
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        $forestName

                    Domain =
                        $domainName

                    HostName =
                        $hostName

                    Site =
                        $siteName

                    Status =
                        'Error'

                    ExitCode =
                        ''

                    Issues =
                        [string]$_.Exception.Message
                }
        }
    }


    return @(
        $rows |
            Sort-Object Domain, HostName
    )
}
function Get-DCDNSHealthReport {

    Import-Module ActiveDirectory -ErrorAction Stop


    #
    # Make sure DCDiag exists
    #

    $dcdiagCommand =
        Get-Command `
            -Name 'dcdiag.exe' `
            -ErrorAction SilentlyContinue


    if ($null -eq $dcdiagCommand) {

        throw (
            'DCDiag.exe was not found. ' +
            'Run this utility from a Domain Controller ' +
            'or a computer with the required AD DS/RSAT tools installed.'
        )
    }


    #
    # Discover all DCs across the forest
    #

    $forestDiscovery =
        Get-ForestDomainControllers


    $forestName =
        [string]$forestDiscovery.ForestName


    $domainControllers =
        @($forestDiscovery.DomainControllers)


    if ($domainControllers.Count -eq 0) {

        throw 'No domain controllers were discovered.'
    }


    #
    # Results
    #

    $rows = @()


    #
    # Run DNS diagnostics against each DC
    #

    foreach ($dc in $domainControllers) {

        $hostName =
            [string]$dc.HostName

        $domainName =
            [string]$dc.Domain

        $siteName =
            [string]$dc.Site


        try {

            #
            # Run dedicated DCDiag DNS test
            #
            # /test:DNS = DNS diagnostic test
            # /DnsAll   = run DNS test collection
            #

            $output = @(
                & $dcdiagCommand.Source `
                    "/s:$hostName" `
                    '/test:DNS' `
                    '/DnsAll' `
                    2>&1
            )


            $exitCode =
                $LASTEXITCODE


            #
            # Convert output to text
            #

            $outputText =
                (
                    $output |
                        ForEach-Object {
                            $_.ToString()
                        }
                ) -join ' '


            #
            # Clean whitespace
            #

            $outputText =
                $outputText `
                    -replace '\s+', ' '

            $outputText =
                $outputText.Trim()


            #
            # Look for DNS test failure indication
            #

            $dnsFailureDetected =
                $false


            if (
                $outputText -match
                '(?i)\b(fail|failed|failure)\b'
            ) {

                $dnsFailureDetected =
                    $true
            }


            #
            # Determine status
            #

            if (
                $exitCode -eq 0 -and
                -not $dnsFailureDetected
            ) {

                $status = 'Passed'
                $issues = ''
            }
            else {

                $status = 'Issues Found'

                if (
                    [string]::IsNullOrWhiteSpace(
                        $outputText
                    )
                ) {

                    $issues =
                        "DNS diagnostic returned exit code $exitCode"
                }
                else {

                    $issues =
                        $outputText
                }
            }


            #
            # Result row
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        $forestName

                    Domain =
                        $domainName

                    HostName =
                        $hostName

                    Site =
                        $siteName

                    Status =
                        $status

                    ExitCode =
                        $exitCode

                    Issues =
                        $issues
                }
        }
        catch {

            #
            # One failed DC must not stop
            # the complete forest report
            #

            $rows +=
                [PSCustomObject]@{

                    Forest =
                        $forestName

                    Domain =
                        $domainName

                    HostName =
                        $hostName

                    Site =
                        $siteName

                    Status =
                        'Error'

                    ExitCode =
                        ''

                    Issues =
                        [string]$_.Exception.Message
                }
        }
    }


    return @(
        $rows |
            Sort-Object Domain, HostName
    )
}

function Get-AllDomainControllersReport {

    Import-Module ActiveDirectory -ErrorAction Stop


    $forestDiscovery =
        Get-ForestDomainControllers

    $forestName =
        [string]$forestDiscovery.ForestName


    $rows = foreach (
        $dc in
        @($forestDiscovery.DomainControllers)
    ) {

        [PSCustomObject]@{

            Forest =
                $forestName

            Domain =
                [string]$dc.Domain

            HostName =
                [string]$dc.HostName

            Site =
                [string]$dc.Site

            IPv4Address =
                [string]$dc.IPv4Address

            IPv6Address =
                [string]$dc.IPv6Address

            Enabled =
                $dc.Enabled

            IsGlobalCatalog =
                $dc.IsGlobalCatalog

            IsReadOnly =
                $dc.IsReadOnly

            OperatingSystem =
                [string]$dc.OperatingSystem

            OperatingSystemVersion =
                [string]$dc.OperatingSystemVersion

            LdapPort =
                $dc.LdapPort

            SslPort =
                $dc.SslPort

            OperationMasterRoles =
                (@($dc.OperationMasterRoles) -join ', ')

            ComputerObjectDN =
                [string]$dc.ComputerObjectDN

            ServerObjectDN =
                [string]$dc.ServerObjectDN
        }
    }


    return @(
        $rows |
            Sort-Object Domain, HostName
    )
}

#
# ============================================================
# DC HEALTH REPORT STATE
# ============================================================
#

$script:CurrentDCHealthReport = @()
$script:CurrentDCHealthReportName = ''
$script:SelectedDCHealthColumns = @()


# ============================================================
# DC HEALTH ATTRIBUTE MASTER LIST
# ============================================================

$dcHealthReportColumns = @(

    #
    # Common DC information
    #

    'Forest'
    'Domain'
    'HostName'
    'Site'
    'IPv4Address'
    'IPv6Address'
    'Enabled'
    'IsGlobalCatalog'
    'IsReadOnly'
    'OperatingSystem'
    'OperatingSystemVersion'
    'LdapPort'
    'SslPort'
    'OperationMasterRoles'
    'ComputerObjectDN'
    'ServerObjectDN'


    #
    # DC Health information
    #

    'OverallStatus'
    'ICMP'
    'LDAP389'
    'LDAPS636'
    'RPC135'
    'NTDS'
    'Netlogon'
    'KDC'
    'DNSClient'
    'DNSServer'
    'DFSR'
    'SYSVOLShare'
    'NETLOGONShare'
    'ReplicationStatus'
    'ReplicationPartners'
    'LastReplicationSuccess'
    'ReplicationIssues'
    #
    # Detailed Replication information
    #

    'Server'
    'Partner'
    'Partition'
    'LastReplicationAttempt'
    'LastReplicationResult'
    'ConsecutiveReplicationFailures'
    'Status'
    'Error'
    #
    # FSMO information
    #

    'Scope'
    'Role'
    'RoleHolder'
    'ExitCode'
    'Issues'

)
# ============================================================
# DEFAULT COLUMNS FOR EACH DC HEALTH REPORT
# ============================================================

$dcHealthReportAvailableColumns = @{

    'DC Health Check' = @(

        'Forest'
        'Domain'
        'HostName'
        'Site'
        'IPv4Address'
        'OverallStatus'
        'ICMP'
        'LDAP389'
        'LDAPS636'
        'RPC135'
        'NTDS'
        'Netlogon'
        'KDC'
        'DNSClient'
        'DNSServer'
        'DFSR'
        'SYSVOLShare'
        'NETLOGONShare'
        'ReplicationStatus'
        'ReplicationPartners'
        'LastReplicationSuccess'
        'IsGlobalCatalog'
        'IsReadOnly'
        'Issues'
    )


    'All Domain Controllers' = @(

        'Forest'
        'Domain'
        'HostName'
        'Site'
        'IPv4Address'
        'OperatingSystem'
        'OperatingSystemVersion'
        'IsGlobalCatalog'
        'IsReadOnly'
        'OperationMasterRoles'
    )

    'Replication Status' = @(

    'Forest'
    'Domain'
    'Server'
    'Site'
    'Partner'
    'Partition'
    'LastReplicationAttempt'
    'LastReplicationSuccess'
    'LastReplicationResult'
    'ConsecutiveReplicationFailures'
    'Status'
    'Error'
    )

    'Replication Failures' = @(

    'Forest'
    'Domain'
    'Server'
    'Site'
    'Partner'
    'Partition'
    'LastReplicationAttempt'
    'LastReplicationSuccess'
    'LastReplicationResult'
    'ConsecutiveReplicationFailures'
    'Status'
    'Error'
    )

    'FSMO Role Holders' = @(

    'Forest'
    'Domain'
    'Scope'
    'Role'
    'RoleHolder'
    )

    'DCDiag' = @(

    'Forest'
    'Domain'
    'HostName'
    'Site'
    'Status'
    'ExitCode'
    'Issues'
    )

    'DNS Health' = @(

    'Forest'
    'Domain'
    'HostName'
    'Site'
    'Status'
    'ExitCode'
    'Issues'
    )

}

# ============================================================
# INITIAL SELECTED COLUMNS
# ============================================================

$script:SelectedDCHealthColumns = @(
    $dcHealthReportColumns
)


#
# ============================================================
# DC HEALTH SPLIT CONTAINER
# ============================================================
#

$dcHealthSplit =
    New-Object System.Windows.Forms.SplitContainer

$dcHealthSplit.Dock = 'Fill'
$dcHealthSplit.Orientation = 'Vertical'
$dcHealthSplit.FixedPanel = 'Panel1'
$dcHealthSplit.SplitterWidth = 4


#
# ============================================================
# LEFT PANEL
# ============================================================
#

$dcHealthReportsPanel =
    New-Object System.Windows.Forms.GroupBox

$dcHealthReportsPanel.Text = 'DC Health Reports'
$dcHealthReportsPanel.Dock = 'Fill'


#
# ============================================================
# DC HEALTH REPORT TREE
# ============================================================
#

$dcHealthReports =
    New-Object System.Windows.Forms.TreeView

$dcHealthReports.Dock = 'Fill'
$dcHealthReports.HideSelection = $false
$dcHealthReports.FullRowSelect = $true

$dcHealthReports.ShowLines = $true
$dcHealthReports.ShowPlusMinus = $true
$dcHealthReports.ShowRootLines = $true

$dcHealthReports.Scrollable = $false
$dcHealthReports.BorderStyle = 'None'
$dcHealthReports.ItemHeight = 22

$dcHealthReports.Font =
    New-Object System.Drawing.Font(
        'Segoe UI',
        9
    )


#
# ============================================================
# HEALTH REPORTS
# ============================================================
#

$dcHealthGeneralNode =
    New-Object System.Windows.Forms.TreeNode(
        'Health Reports'
    )

[void]$dcHealthGeneralNode.Nodes.Add(
    'DC Health Check'
)

[void]$dcHealthGeneralNode.Nodes.Add(
    'All Domain Controllers'
)


#
# ============================================================
# REPLICATION
# ============================================================
#

$dcHealthReplicationNode =
    New-Object System.Windows.Forms.TreeNode(
        'Replication'
    )

[void]$dcHealthReplicationNode.Nodes.Add(
    'Replication Status'
)

[void]$dcHealthReplicationNode.Nodes.Add(
    'Replication Failures'
)


#
# ============================================================
# FSMO ROLES
# ============================================================
#

$dcHealthFSMONode =
    New-Object System.Windows.Forms.TreeNode(
        'FSMO Roles'
    )

[void]$dcHealthFSMONode.Nodes.Add(
    'FSMO Role Holders'
)
#
# ============================================================
# DIAGNOSTICS
# ============================================================
#

$dcHealthDiagnosticsNode =
    New-Object System.Windows.Forms.TreeNode(
        'Diagnostics'
    )

[void]$dcHealthDiagnosticsNode.Nodes.Add(
    'DCDiag'
)
[void]$dcHealthDiagnosticsNode.Nodes.Add(
    'DNS Health'
)

#
# ============================================================
# ADD REPORT CATEGORIES
# ============================================================
#

[void]$dcHealthReports.Nodes.Add(
    $dcHealthGeneralNode
)

[void]$dcHealthReports.Nodes.Add(
    $dcHealthReplicationNode
)

[void]$dcHealthReports.Nodes.Add(
    $dcHealthFSMONode
)
[void]$dcHealthReports.Nodes.Add(
    $dcHealthDiagnosticsNode
)

$dcHealthReports.ExpandAll()


#
# Add TreeView to left panel
#

[void]$dcHealthReportsPanel.Controls.Add(
    $dcHealthReports
)

[void]$dcHealthSplit.Panel1.Controls.Add(
    $dcHealthReportsPanel
)


#
# ============================================================
# RIGHT LAYOUT
# ============================================================
#

$dcHealthRightLayout =
    New-Object System.Windows.Forms.TableLayoutPanel

$dcHealthRightLayout.Dock = 'Fill'
$dcHealthRightLayout.RowCount = 2
$dcHealthRightLayout.ColumnCount = 1


[void]$dcHealthRightLayout.ColumnStyles.Add(
    (
        New-Object System.Windows.Forms.ColumnStyle(
            [System.Windows.Forms.SizeType]::Percent,
            100
        )
    )
)


[void]$dcHealthRightLayout.RowStyles.Add(
    (
        New-Object System.Windows.Forms.RowStyle(
            [System.Windows.Forms.SizeType]::Absolute,
            70
        )
    )
)


[void]$dcHealthRightLayout.RowStyles.Add(
    (
        New-Object System.Windows.Forms.RowStyle(
            [System.Windows.Forms.SizeType]::Percent,
            100
        )
    )
)


#
# ============================================================
# DC HEALTH TOOLBAR
# ============================================================
#

$dcHealthToolbar =
    New-Object System.Windows.Forms.FlowLayoutPanel

$dcHealthToolbar.Dock = 'Fill'
$dcHealthToolbar.FlowDirection = 'LeftToRight'
$dcHealthToolbar.WrapContents = $true

$dcHealthToolbar.Padding =
    New-Object System.Windows.Forms.Padding(
        8,
        7,
        0,
        0
    )


#
# ============================================================
# RUN REPORT BUTTON
# ============================================================
#

$btnRunDCHealthReport =
    New-Object System.Windows.Forms.Button

$btnRunDCHealthReport.Text = 'Run Report'
$btnRunDCHealthReport.Width = 90
$btnRunDCHealthReport.Enabled = $false


#
# ============================================================
# SELECT ATTRIBUTES BUTTON
# ============================================================
#

$btnSelectDCHealthAttributes =
    New-Object System.Windows.Forms.Button

$btnSelectDCHealthAttributes.Text =
    'Select Attributes'

$btnSelectDCHealthAttributes.Width = 110


#
# ============================================================
# EXPORT CSV BUTTON
# ============================================================
#

$btnExportDCHealth =
    New-Object System.Windows.Forms.Button

$btnExportDCHealth.Text = 'Export CSV'
$btnExportDCHealth.Width = 85
$btnExportDCHealth.Enabled = $false


#
# ============================================================
# SEARCH BOX
# ============================================================
#

$txtDCHealthSearch =
    New-Object System.Windows.Forms.TextBox

$txtDCHealthSearch.Width = 200


#
# ============================================================
# SEARCH BUTTON
# ============================================================
#

$btnDCHealthSearch =
    New-Object System.Windows.Forms.Button

$btnDCHealthSearch.Text = 'Search'
$btnDCHealthSearch.Width = 65


#
# ============================================================
# CLEAR BUTTON
# ============================================================
#

$btnClearDCHealthSearch =
    New-Object System.Windows.Forms.Button

$btnClearDCHealthSearch.Text = 'Clear'
$btnClearDCHealthSearch.Width = 55


#
# ============================================================
# SELECTED REPORT LABEL
# ============================================================
#

$lblSelectedDCHealthReport =
    New-Object System.Windows.Forms.Label

$lblSelectedDCHealthReport.Text =
    'No report selected'

$lblSelectedDCHealthReport.AutoSize = $true

$lblSelectedDCHealthReport.Margin =
    New-Object System.Windows.Forms.Padding(
        12,
        6,
        0,
        0
    )


#
# ============================================================
# ADD CONTROLS TO TOOLBAR
# ============================================================
#

[void]$dcHealthToolbar.Controls.Add(
    $btnRunDCHealthReport
)

[void]$dcHealthToolbar.Controls.Add(
    $btnSelectDCHealthAttributes
)

[void]$dcHealthToolbar.Controls.Add(
    $btnExportDCHealth
)

[void]$dcHealthToolbar.Controls.Add(
    $txtDCHealthSearch
)

[void]$dcHealthToolbar.Controls.Add(
    $btnDCHealthSearch
)

[void]$dcHealthToolbar.Controls.Add(
    $btnClearDCHealthSearch
)


#
# Force selected-report label onto line 2
#

$dcHealthToolbar.SetFlowBreak(
    $btnClearDCHealthSearch,
    $true
)

[void]$dcHealthToolbar.Controls.Add(
    $lblSelectedDCHealthReport
)


#
# ============================================================
# DC HEALTH RESULTS GRID
# ============================================================
#

$gridDCHealth =
    New-Grid


#
# ============================================================
# ADD TOOLBAR AND GRID TO RIGHT LAYOUT
# ============================================================
#

$dcHealthRightLayout.Controls.Add(
    $dcHealthToolbar,
    0,
    0
)

$dcHealthRightLayout.Controls.Add(
    $gridDCHealth,
    0,
    1
)

$dcHealthSplit.Panel2.Controls.Add(
    $dcHealthRightLayout
)


#
# ============================================================
# ADD SPLIT CONTAINER TO DC HEALTH TAB
# ============================================================
#

$tabDCHealth.Controls.Add(
    $dcHealthSplit
)


#
# ============================================================
# APPLY SAME LEFT PANEL WIDTH
# ============================================================
#

$dcHealthSplit.Panel1MinSize = 210
$dcHealthSplit.SplitterDistance = 210


$tabDCHealth.Add_Enter({

    if ($dcHealthSplit.Width -gt 500) {

        $dcHealthSplit.SplitterDistance = 210
    }
})


#
# ============================================================
# DC HEALTH REPORT SELECTION
# ============================================================
#

$dcHealthReports.Add_AfterSelect({

    if ($null -eq $dcHealthReports.SelectedNode) {
        return
    }


    #
    # Category selected
    #

    if ($dcHealthReports.SelectedNode.Level -eq 0) {

        $btnRunDCHealthReport.Enabled = $false

        $lblSelectedDCHealthReport.Text =
            'Select a report'

        return
    }


    #
    # Actual report selected
    #

    $btnRunDCHealthReport.Enabled = $true

    $selectedDCHealthReport =
        $dcHealthReports.SelectedNode.Text


    $lblSelectedDCHealthReport.Text =
        'Selected Report: ' +
        $selectedDCHealthReport +
        ' - Click Run Report to load data.'


    #
    # Clear previous results when another report is selected
    #

    if (
        $script:CurrentDCHealthReportName -ne
        $selectedDCHealthReport
    ) {

        $script:CurrentDCHealthReport = @()
        $script:CurrentDCHealthReportName = ''

        $gridDCHealth.DataSource = $null
        $gridDCHealth.Columns.Clear()

        $txtDCHealthSearch.Clear()

        $btnExportDCHealth.Enabled = $false
    }
})

#
# ============================================================
# DC HEALTH - RUN REPORT
# ============================================================
#

$btnRunDCHealthReport.Add_Click({

    if ($null -eq $dcHealthReports.SelectedNode) {
        return
    }


    #
    # Category selected
    #

    if ($dcHealthReports.SelectedNode.Level -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Please select a DC Health report first.',
            'DC Health',
            'OK',
            'Information'
        )

        return
    }


    $selectedReport =
        $dcHealthReports.SelectedNode.Text


    try {

        $btnRunDCHealthReport.Enabled = $false
        $btnRunDCHealthReport.Text = 'Running...'

        $lblSelectedDCHealthReport.Text =
            "Running $selectedReport... Please wait."

        $w.UseWaitCursor = $true
        $w.Refresh()

        [System.Windows.Forms.Application]::DoEvents()


        #
        # Run selected report
        #

        switch ($selectedReport) {

        'DC Health Check' {

        $rows =
            Get-DCHealthCheckReport
        }


         'All Domain Controllers' {

        $rows =
            Get-AllDomainControllersReport
         }

         'Replication Status' {
         $rows = Get-DCReplicationStatusReport
         }

         'Replication Failures' {

         $rows =
        Get-DCReplicationFailuresReport
        }

        'FSMO Role Holders' {

        $rows =
        Get-FSMORoleHoldersReport
        }

        'DCDiag' {

         $rows =
        Get-DCDiagReport
        }

        'DNS Health' {

         $rows =
        Get-DCDNSHealthReport
        }

    default {

        [void][System.Windows.Forms.MessageBox]::Show(
            "$selectedReport not implemented yet.",
            'DC Health',
            'OK',
            'Information'
        )

        return
    }
    }


        #
        # Store current report
        #

        $script:CurrentDCHealthReport =
            @($rows)

        $script:CurrentDCHealthReportName =
            $selectedReport


        #
        # Apply report default columns
        #

        if (
            $dcHealthReportAvailableColumns.ContainsKey(
                $selectedReport
            )
        ) {

            $script:SelectedDCHealthColumns = @(
                $dcHealthReportAvailableColumns[
                    $selectedReport
                ]
            )
        }
        else {

            $script:SelectedDCHealthColumns = @(
                $dcHealthReportColumns
            )
        }


        #
        # Display results
        #

        Set-GridRows `
            -Grid $gridDCHealth `
            -Rows $script:CurrentDCHealthReport `
            -Columns $script:SelectedDCHealthColumns


        #
        # Export availability
        #

        $btnExportDCHealth.Enabled = (
            $script:CurrentDCHealthReport.Count -gt 0
        )


        #
        # Result label
        #

        $lblSelectedDCHealthReport.Text = (
            '{0} - {1} record(s)' -f
            $selectedReport,
            $script:CurrentDCHealthReport.Count
        )
    }

    catch {

        [void][System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'DC Health Report Error',
            'OK',
            'Error'
        )
    }

    finally {

        $w.UseWaitCursor = $false

        $btnRunDCHealthReport.Text =
            'Run Report'

        $btnRunDCHealthReport.Enabled =
            $true
    }
})

#
# ============================================================
# DC HEALTH - SELECT ATTRIBUTES
# ============================================================
#

$btnSelectDCHealthAttributes.Add_Click({

    #
    # Make sure a report is loaded
    #

    if (@($script:CurrentDCHealthReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a DC Health report before selecting attributes.',
            'Select DC Health Attributes',
            'OK',
            'Information'
        )

        return
    }


    #
    # Create form
    #

    $f =
        New-Object System.Windows.Forms.Form

    $f.Text =
        'Select DC Health Attributes'

    $f.BackColor =
        [System.Drawing.Color]::White

    $f.StartPosition =
        'CenterParent'

    $f.Size =
        New-Object System.Drawing.Size(
            380,
            520
        )


    #
    # Information label
    #

    $lblInfo =
        New-Object System.Windows.Forms.Label

    $lblInfo.Dock = 'Top'
    $lblInfo.Height = 40

    $lblInfo.Font =
        New-Object System.Drawing.Font(
            'Segoe UI',
            9,
            [System.Drawing.FontStyle]::Bold
        )


    #
    # Attribute list
    #

    $list =
        New-Object System.Windows.Forms.CheckedListBox

    $list.Dock = 'Fill'
    $list.CheckOnClick = $true


    #
    # Add DC Health attributes
    #

    foreach ($col in $dcHealthReportColumns) {

        $index =
            $list.Items.Add(
                $col
            )

        if (
            $script:SelectedDCHealthColumns -contains
            $col
        ) {

            $list.SetItemChecked(
                $index,
                $true
            )
        }
    }


    $lblInfo.Text =
        "Total Attributes: $($list.Items.Count)"


    #
    # Buttons
    #

    $btnSelectAll =
        New-Object System.Windows.Forms.Button

    $btnSelectAll.Text = 'Select All'
    $btnSelectAll.Width = 80


    $btnClearAll =
        New-Object System.Windows.Forms.Button

    $btnClearAll.Text = 'Clear All'
    $btnClearAll.Width = 80


    $btnApply =
        New-Object System.Windows.Forms.Button

    $btnApply.Text = 'Apply'
    $btnApply.Width = 80


    $btnClose =
        New-Object System.Windows.Forms.Button

    $btnClose.Text = 'Close'
    $btnClose.Width = 80


    #
    # Bottom button panel
    #

    $buttonPanel =
        New-Object System.Windows.Forms.FlowLayoutPanel

    $buttonPanel.Dock = 'Bottom'
    $buttonPanel.Height = 50

    $buttonPanel.FlowDirection =
        'LeftToRight'

    $buttonPanel.Padding =
        New-Object System.Windows.Forms.Padding(
            8,
            8,
            0,
            0
        )


    [void]$buttonPanel.Controls.Add(
        $btnSelectAll
    )

    [void]$buttonPanel.Controls.Add(
        $btnClearAll
    )

    [void]$buttonPanel.Controls.Add(
        $btnApply
    )

    [void]$buttonPanel.Controls.Add(
        $btnClose
    )


    #
    # Select All
    #

    $btnSelectAll.Add_Click({

        for (
            $i = 0;
            $i -lt $list.Items.Count;
            $i++
        ) {

            $list.SetItemChecked(
                $i,
                $true
            )
        }
    })


    #
    # Clear All
    #

    $btnClearAll.Add_Click({

        for (
            $i = 0;
            $i -lt $list.Items.Count;
            $i++
        ) {

            $list.SetItemChecked(
                $i,
                $false
            )
        }
    })


    #
    # Apply
    #

    $btnApply.Add_Click({

        $selectedColumns = @(
            $list.CheckedItems |
                ForEach-Object {
                    [string]$_
                }
        )


        if ($selectedColumns.Count -eq 0) {

            [void][System.Windows.Forms.MessageBox]::Show(
                'Select at least one attribute.',
                'Select Attributes',
                'OK',
                'Information'
            )

            return
        }


        $script:SelectedDCHealthColumns =
            @($selectedColumns)


        Set-GridRows `
            -Grid $gridDCHealth `
            -Rows $script:CurrentDCHealthReport `
            -Columns $script:SelectedDCHealthColumns


        $f.Close()
    })


    #
    # Close
    #

    $btnClose.Add_Click({

        $f.Close()
    })


    #
    # Add controls
    #

    $f.Controls.Add(
        $list
    )

    $f.Controls.Add(
        $buttonPanel
    )

    $f.Controls.Add(
        $lblInfo
    )


    [void]$f.ShowDialog($w)
})
#
# ============================================================
# DC HEALTH - EXPORT CSV
# ============================================================
#

$btnExportDCHealth.Add_Click({

    #
    # Make sure data exists
    #

    if (@($script:CurrentDCHealthReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a DC Health report before exporting.',
            'Export DC Health Report',
            'OK',
            'Information'
        )

        return
    }


    #
    # Need at least one selected column
    #

    if (@($script:SelectedDCHealthColumns).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'No attributes are selected for export.',
            'Export DC Health Report',
            'OK',
            'Information'
        )

        return
    }


    #
    # Save dialog
    #

    $saveDialog =
        New-Object System.Windows.Forms.SaveFileDialog

    $saveDialog.Filter =
        'CSV Files (*.csv)|*.csv'

    $saveDialog.DefaultExt =
        'csv'

    $saveDialog.AddExtension =
        $true


    #
    # Safe report name for filename
    #

    $safeReportName =
        $script:CurrentDCHealthReportName `
            -replace '[^\w\-]+','_'


    $saveDialog.FileName = (
        'DCHealth_{0}_{1}.csv' -f
        $safeReportName,
        (Get-Date -Format 'yyyyMMdd_HHmmss')
    )


    if (
        $saveDialog.ShowDialog() -ne
        [System.Windows.Forms.DialogResult]::OK
    ) {

        return
    }


    #
    # Export only selected attributes
    #

    $script:CurrentDCHealthReport |
        Select-Object `
            -Property $script:SelectedDCHealthColumns |
        Export-Csv `
            -NoTypeInformation `
            -Encoding UTF8 `
            -Path $saveDialog.FileName


    [void][System.Windows.Forms.MessageBox]::Show(
        'Export completed successfully.',
        'Export',
        'OK',
        'Information'
    )
})
#
# ============================================================
# DC HEALTH - SEARCH
# ============================================================
#

$btnDCHealthSearch.Add_Click({

    #
    # Make sure a report is loaded
    #

    if (@($script:CurrentDCHealthReport).Count -eq 0) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Run a DC Health report before searching.',
            'Search DC Health Report',
            'OK',
            'Information'
        )

        return
    }


    #
    # Get search text
    #

    $searchText =
        $txtDCHealthSearch.Text.Trim()


    if (
        [string]::IsNullOrWhiteSpace(
            $searchText
        )
    ) {

        return
    }


    #
    # Search all currently selected attributes
    #

    $filteredRows = @(

        $script:CurrentDCHealthReport |

            Where-Object {

                $row = $_
                $matched = $false


                foreach (
                    $column in
                    $script:SelectedDCHealthColumns
                ) {

                    $property =
                        $row.PSObject.Properties[
                            $column
                        ]


                    if (
                        $null -ne $property -and
                        $null -ne $property.Value
                    ) {

                        if (
                            $property.Value.ToString() -like
                            "*$searchText*"
                        ) {

                            $matched = $true
                            break
                        }
                    }
                }


                $matched
            }
    )


    #
    # Display filtered results
    #

    Set-GridRows `
        -Grid $gridDCHealth `
        -Rows $filteredRows `
        -Columns $script:SelectedDCHealthColumns


    #
    # Update status
    #

    $lblSelectedDCHealthReport.Text = (
        '{0} - Search Results: {1}' -f
        $script:CurrentDCHealthReportName,
        $filteredRows.Count
    )
})
#
# ============================================================
# DC HEALTH - CLEAR SEARCH
# ============================================================
#

$btnClearDCHealthSearch.Add_Click({

    #
    # Clear search box
    #

    $txtDCHealthSearch.Clear()


    #
    # Restore original report
    #

    if (
        @($script:CurrentDCHealthReport).Count -gt 0
    ) {

        Set-GridRows `
            -Grid $gridDCHealth `
            -Rows $script:CurrentDCHealthReport `
            -Columns $script:SelectedDCHealthColumns


        #
        # Restore status
        #

        $lblSelectedDCHealthReport.Text = (
            '{0} - {1} record(s)' -f
            $script:CurrentDCHealthReportName,
            $script:CurrentDCHealthReport.Count
        )
    }
})
#
# ============================================================
# DC HEALTH - PRESS ENTER TO SEARCH
# ============================================================
#

$txtDCHealthSearch.Add_KeyDown({

    if (
        $_.KeyCode -eq
        [System.Windows.Forms.Keys]::Enter
    ) {

        $btnDCHealthSearch.PerformClick()

        $_.SuppressKeyPress = $true
    }
})


#
# Manual Fetch Inventory action
#

    $btnFetchInventory.Add_Click({

        try {
            $btnFetchInventory.Enabled = $false
            $tabs.Enabled = $false
            $w.UseWaitCursor = $true

            $lblInventoryStatus.Text =
                'Collecting Active Directory inventory...'

            $statusIndicator.BackColor =
                [System.Drawing.Color]::FromArgb(255,185,0)

            $w.Refresh()

            $summary = Get-InventorySummary

            #
            # Directory information
            #

$dirDomain.Value.Text = [string]$summary.DomainName
$dirForest.Value.Text = [string]$summary.ForestName
$dirPDC.Value.Text = [string]$summary.PDCEmulator
$dirDCCount.Value.Text = [string]$summary.DCCount

            #
            # User counts
            #

            $uTotal.Value.Text = [string]$summary.TotalUsers
            $uActive.Value.Text = [string]$summary.ActiveUsers
            $uDisabled.Value.Text = [string]$summary.DisabledUsers

            #
            # Computer counts
            #

            $cTotal.Value.Text = [string]$summary.TotalComputers
            $cActive.Value.Text = [string]$summary.ActiveComputers
            $cDisabled.Value.Text = [string]$summary.DisabledComputers

            #
            # Group count
            #

            $gTotal.Value.Text = [string]$summary.TotalGroups

            $lblInventoryStatus.Text =
                'Inventory collection completed successfully'

            $statusIndicator.BackColor =
                [System.Drawing.Color]::FromArgb(16,124,16)
        }
        catch {
            $lblInventoryStatus.Text = 'Inventory collection failed'

            $statusIndicator.BackColor =
                [System.Drawing.Color]::FromArgb(196,43,28)

            [void][System.Windows.Forms.MessageBox]::Show(
                (
                    "Inventory collection failed.`r`n`r`n" +
                    "Error: {0}`r`n" +
                    "Line: {1}`r`n" +
                    "Command: {2}" -f
                    $_.Exception.Message,
                    $_.InvocationInfo.ScriptLineNumber,
                    $_.InvocationInfo.Line
                ),
                'Inventory Error',
                'OK',
                'Error'
            )
        }
        finally {
            $w.UseWaitCursor = $false
            $tabs.Enabled = $true
            $btnFetchInventory.Enabled = $true
        }
    })

    #
    # Cleanup
    #

    $w.Add_FormClosed({
        $script:InventoryForm = $null

        try {
            $w.Dispose()
        }
        catch {
        }
    })

    $w.Controls.Add($tabs)

    [void]$w.ShowDialog($form)
}
# ============================================================
# AUTHENTICATION FUNCTIONS
# ============================================================

function Test-ADUtilityCredential {

    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$Password
    )


    $context = $null


    try {

        $context =
            New-Object `
                System.DirectoryServices.AccountManagement.PrincipalContext(
                    [System.DirectoryServices.AccountManagement.ContextType]::Domain,
                    $Domain
                )


        $valid =
            $context.ValidateCredentials(
                $UserName,
                $Password
            )


        return [bool]$valid
    }
    catch {

        return $false
    }
    finally {

        if ($null -ne $context) {

            $context.Dispose()
        }
    }
}
function Get-ADUtilityAuthorization {

    param(
        [Parameter(Mandatory)]
        [string]$UserName
    )


    try {

        if (-not (Get-Module ActiveDirectory)) {

            Import-Module ActiveDirectory `
                -ErrorAction Stop
        }


        #
        # Get AD User
        #

        $user =
            Get-ADUser `
                -Identity $UserName `
                -Properties Enabled `
                -ErrorAction Stop


        #
        # Account must be enabled
        #

        if (-not $user.Enabled) {

            return [PSCustomObject]@{

                Authorized = $false
                Role = ''
                Reason = 'AccountDisabled'
            }
        }


        #
        # Get group memberships
        #

        $groups = @(
            Get-ADPrincipalGroupMembership `
                -Identity $user `
                -ErrorAction Stop
        )


        #
        # Admin membership has priority
        #

        $isAdmin =
            $null -ne (
                $groups |
                    Where-Object {
                        $_.Name -eq
                        $script:ADUtilityAdminGroup
                    } |
                    Select-Object -First 1
            )


        if ($isAdmin) {

            return [PSCustomObject]@{

                Authorized = $true
                Role = 'Admin'
                Reason = ''
            }
        }


        #
        # Helpdesk membership
        #

        $isHelpdesk =
            $null -ne (
                $groups |
                    Where-Object {
                        $_.Name -eq
                        $script:ADUtilityHelpdeskGroup
                    } |
                    Select-Object -First 1
            )


        if ($isHelpdesk) {

            return [PSCustomObject]@{

                Authorized = $true
                Role = 'Helpdesk'
                Reason = ''
            }
        }


        #
        # Valid AD account but not authorized
        #

        return [PSCustomObject]@{

            Authorized = $false
            Role = ''
            Reason = 'NotAuthorized'
        }
    }
    catch {

        return [PSCustomObject]@{

            Authorized = $false
            Role = ''
            Reason = 'AuthorizationFailed'
        }
    }
}

function Show-ADUtilityLogin {

    #
    # Determine current AD domain
    #

    try {

        if (-not (Get-Module ActiveDirectory)) {

            Import-Module ActiveDirectory `
                -ErrorAction Stop
        }


        $domain =
            Get-ADDomain `
                -ErrorAction Stop


        $domainDNS =
            [string]$domain.DNSRoot


        $domainNetBIOS =
            [string]$domain.NetBIOSName
    }
    catch {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Unable to determine the Active Directory domain.',
            'Authentication Error',
            'OK',
            'Error'
        )

        return $false
    }


    #
    # Create Login window
    #

   # ============================================================
# COMPACT MODERN LOGIN WINDOW
# ============================================================

$loginForm = New-Object System.Windows.Forms.Form
$loginForm.Text = 'AD Utility - Authentication'
$loginForm.StartPosition = 'CenterScreen'
$loginForm.Size = New-Object System.Drawing.Size(440,350)
$loginForm.FormBorderStyle = 'FixedDialog'
$loginForm.MaximizeBox = $false
$loginForm.MinimizeBox = $false
$loginForm.BackColor = [System.Drawing.Color]::FromArgb(245,247,250)
$loginForm.Font = New-Object System.Drawing.Font('Segoe UI',9)
$loginForm.ShowInTaskbar = $true


# ============================================================
# HEADER
# ============================================================

$loginHeader = New-Object System.Windows.Forms.Panel
$loginHeader.Dock = 'Top'
$loginHeader.Height = 72
$loginHeader.BackColor = [System.Drawing.Color]::FromArgb(25,42,65)


$lblLoginApp = New-Object System.Windows.Forms.Label
$lblLoginApp.Text = 'AD OPERATIONS CONSOLE'
$lblLoginApp.Left = 25
$lblLoginApp.Top = 13
$lblLoginApp.Width = 360
$lblLoginApp.Height = 28
$lblLoginApp.ForeColor = [System.Drawing.Color]::White
$lblLoginApp.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    14,
    [System.Drawing.FontStyle]::Bold
)


$lblLoginSubtitle = New-Object System.Windows.Forms.Label
$lblLoginSubtitle.Text = "Secure Active Directory Access | $domainNetBIOS"
$lblLoginSubtitle.Left = 26
$lblLoginSubtitle.Top = 42
$lblLoginSubtitle.Width = 360
$lblLoginSubtitle.Height = 18
$lblLoginSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(195,210,225)
$lblLoginSubtitle.Font = New-Object System.Drawing.Font('Segoe UI',8)


[void]$loginHeader.Controls.Add($lblLoginApp)
[void]$loginHeader.Controls.Add($lblLoginSubtitle)
[void]$loginForm.Controls.Add($loginHeader)


# ============================================================
# SIGN IN TITLE
# ============================================================

$lblLoginTitle = New-Object System.Windows.Forms.Label
$lblLoginTitle.Text = 'Sign in'
$lblLoginTitle.Left = 36
$lblLoginTitle.Top = 88
$lblLoginTitle.Width = 350
$lblLoginTitle.Height = 27
$lblLoginTitle.ForeColor = [System.Drawing.Color]::FromArgb(35,45,55)
$lblLoginTitle.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    13,
    [System.Drawing.FontStyle]::Bold
)

[void]$loginForm.Controls.Add($lblLoginTitle)


$lblLoginDescription = New-Object System.Windows.Forms.Label
$lblLoginDescription.Text = 'Authenticate with your Active Directory account.'
$lblLoginDescription.Left = 36
$lblLoginDescription.Top = 116
$lblLoginDescription.Width = 350
$lblLoginDescription.Height = 18
$lblLoginDescription.ForeColor = [System.Drawing.Color]::DimGray
$lblLoginDescription.Font = New-Object System.Drawing.Font('Segoe UI',8)

[void]$loginForm.Controls.Add($lblLoginDescription)


# ============================================================
# USERNAME
# ============================================================

$lblLoginUser = New-Object System.Windows.Forms.Label
$lblLoginUser.Text = 'USERNAME'
$lblLoginUser.Left = 36
$lblLoginUser.Top = 151
$lblLoginUser.Width = 350
$lblLoginUser.Height = 17
$lblLoginUser.ForeColor = [System.Drawing.Color]::FromArgb(70,70,70)
$lblLoginUser.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    7.5,
    [System.Drawing.FontStyle]::Bold
)

[void]$loginForm.Controls.Add($lblLoginUser)


$txtLoginUser = New-Object System.Windows.Forms.TextBox
$txtLoginUser.Left = 36
$txtLoginUser.Top = 170
$txtLoginUser.Width = 350
$txtLoginUser.BorderStyle = 'FixedSingle'
$txtLoginUser.Font = New-Object System.Drawing.Font('Segoe UI',9)

[void]$loginForm.Controls.Add($txtLoginUser)


# ============================================================
# PASSWORD
# ============================================================

$lblLoginPassword = New-Object System.Windows.Forms.Label
$lblLoginPassword.Text = 'PASSWORD'
$lblLoginPassword.Left = 36
$lblLoginPassword.Top = 207
$lblLoginPassword.Width = 350
$lblLoginPassword.Height = 17
$lblLoginPassword.ForeColor = [System.Drawing.Color]::FromArgb(70,70,70)
$lblLoginPassword.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    7.5,
    [System.Drawing.FontStyle]::Bold
)

[void]$loginForm.Controls.Add($lblLoginPassword)


$txtLoginPassword = New-Object System.Windows.Forms.TextBox
$txtLoginPassword.Left = 36
$txtLoginPassword.Top = 226
$txtLoginPassword.Width = 350
$txtLoginPassword.BorderStyle = 'FixedSingle'
$txtLoginPassword.Font = New-Object System.Drawing.Font('Segoe UI',9)
$txtLoginPassword.UseSystemPasswordChar = $true

[void]$loginForm.Controls.Add($txtLoginPassword)


# ============================================================
# STATUS / ERROR MESSAGE
# ============================================================

$lblLoginStatus = New-Object System.Windows.Forms.Label
$lblLoginStatus.Text = ''
$lblLoginStatus.Left = 36
$lblLoginStatus.Top = 256
$lblLoginStatus.Width = 350
$lblLoginStatus.Height = 20
$lblLoginStatus.ForeColor = [System.Drawing.Color]::Firebrick
$lblLoginStatus.Font = New-Object System.Drawing.Font('Segoe UI',8)

[void]$loginForm.Controls.Add($lblLoginStatus)


# ============================================================
# CANCEL BUTTON
# ============================================================

$btnLoginCancel = New-Object System.Windows.Forms.Button
$btnLoginCancel.Text = 'Cancel'
$btnLoginCancel.Left = 186
$btnLoginCancel.Top = 283
$btnLoginCancel.Width = 95
$btnLoginCancel.Height = 32
$btnLoginCancel.FlatStyle = 'Flat'
$btnLoginCancel.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(
    180,
    185,
    190
)
$btnLoginCancel.BackColor = [System.Drawing.Color]::FromArgb(240,242,245)
$btnLoginCancel.ForeColor = [System.Drawing.Color]::FromArgb(45,45,45)
$btnLoginCancel.Cursor = [System.Windows.Forms.Cursors]::Hand

[void]$loginForm.Controls.Add($btnLoginCancel)


# ============================================================
# SIGN IN BUTTON
# ============================================================

$btnLogin = New-Object System.Windows.Forms.Button
$btnLogin.Text = 'Sign in'
$btnLogin.Left = 291
$btnLogin.Top = 283
$btnLogin.Width = 95
$btnLogin.Height = 32
$btnLogin.FlatStyle = 'Flat'
$btnLogin.FlatAppearance.BorderSize = 0
$btnLogin.BackColor = [System.Drawing.Color]::FromArgb(0,120,212)
$btnLogin.ForeColor = [System.Drawing.Color]::White
$btnLogin.Font = New-Object System.Drawing.Font(
    'Segoe UI',
    9,
    [System.Drawing.FontStyle]::Bold
)
$btnLogin.Cursor = [System.Windows.Forms.Cursors]::Hand

[void]$loginForm.Controls.Add($btnLogin)


    #
    # Login Button action
    #

    $btnLogin.Add_Click({

        $userName =
            $txtLoginUser.Text.Trim()


        $password =
            $txtLoginPassword.Text


        #
        # Username required
        #

        if (
            [string]::IsNullOrWhiteSpace(
                $userName
            )
        ) {

            $lblLoginStatus.ForeColor =
                [System.Drawing.Color]::Firebrick


            $lblLoginStatus.Text =
                'Enter your username.'


            $txtLoginUser.Focus()

            return
        }


        #
        # Password required
        #

        if (
            [string]::IsNullOrWhiteSpace(
                $password
            )
        ) {

            $lblLoginStatus.ForeColor =
                [System.Drawing.Color]::Firebrick


            $lblLoginStatus.Text =
                'Enter your password.'


            $txtLoginPassword.Focus()

            return
        }


        #
        # Disable Login temporarily
        #

        $btnLogin.Enabled =
            $false


        $lblLoginStatus.ForeColor =
            [System.Drawing.Color]::DimGray


        $lblLoginStatus.Text =
            'Authenticating...'


        $loginForm.Refresh()


        #
        # Validate credentials against AD
        #

        $valid =
            Test-ADUtilityCredential `
                -Domain $domainDNS `
                -UserName $userName `
                -Password $password


        #
        # Remove password from our temporary variables/UI
        #

        $password =
            $null


        $txtLoginPassword.Clear()


        #
        # Successful login
        #

       if ($valid) {

    #
    # Check whether authenticated user
    # is authorized to use the utility
    #

    $authorization =
        Get-ADUtilityAuthorization `
            -UserName $userName


    #
    # Authorization failed
    #

    if (-not $authorization.Authorized) {

        $script:IsAuthenticated =
            $false

        $script:AuthenticatedRole =
            ''


        $lblLoginStatus.ForeColor =
            [System.Drawing.Color]::Firebrick


        switch ($authorization.Reason) {

            'AccountDisabled' {

                $lblLoginStatus.Text =
                    'This account is disabled.'
            }


            'NotAuthorized' {

                $lblLoginStatus.Text =
                    'You are not authorized to use this utility.'
            }


            default {

                $lblLoginStatus.Text =
                    'Unable to verify application access.'
            }
        }


        $btnLogin.Enabled =
            $true


        $txtLoginPassword.Focus()

        return
    }


    #
    # Authentication + authorization succeeded
    #

    $script:IsAuthenticated =
        $true


    $script:AuthenticatedUser =
        $userName


    $script:AuthenticatedDomain =
        $domainNetBIOS


    $script:AuthenticatedRole =
        [string]$authorization.Role


    $loginForm.DialogResult =
        [System.Windows.Forms.DialogResult]::OK


    $loginForm.Close()

    return
}


        #
        # Invalid credentials
        #

        $script:IsAuthenticated =
            $false


        $lblLoginStatus.ForeColor =
            [System.Drawing.Color]::Firebrick


        $lblLoginStatus.Text =
            'Invalid username or password.'


        $btnLogin.Enabled =
            $true


        $txtLoginPassword.Focus()
    })


    #
    # Cancel action
    #

    $btnLoginCancel.Add_Click({

        $script:IsAuthenticated =
            $false


        $txtLoginPassword.Clear()


        $loginForm.DialogResult =
            [System.Windows.Forms.DialogResult]::Cancel


        $loginForm.Close()
    })


    #
    # Enter key = Login
    #

    $loginForm.AcceptButton =
        $btnLogin


    #
    # Escape key = Cancel
    #

    $loginForm.CancelButton =
        $btnLoginCancel


    #
    # Focus Username when shown
    #

    $loginForm.Add_Shown({

        $txtLoginUser.Focus()
    })


    #
    # Show Login
    #

    $result =
        $loginForm.ShowDialog()


    #
    # Cleanup
    #

    $txtLoginPassword.Clear()


    $loginForm.Dispose()


    return (
        $result -eq
        [System.Windows.Forms.DialogResult]::OK -and
        $script:IsAuthenticated
    )
}

$targets=Get-MonitorTargets
$form=New-Object System.Windows.Forms.Form;$form.Text='AD Authentication & Lockout Dashboard';
$form.StartPosition='CenterScreen';$form.Size=New-Object System.Drawing.Size(1280,800);$form.MinimumSize=New-Object System.Drawing.Size(1050,650);$form.Font=New-Object System.Drawing.Font('Segoe UI',9);$form.BackColor=[System.Drawing.Color]::FromArgb(230,235,241)
$root=New-Object System.Windows.Forms.TableLayoutPanel;$root.Dock='Fill';$root.RowCount=4;Add-RowStyle $root 'Absolute' 62;Add-RowStyle $root 'Absolute' 110;Add-RowStyle $root 'Absolute' 48;Add-RowStyle $root 'Percent' 100;$form.Controls.Add($root)
$header=New-Object System.Windows.Forms.Panel;$header.Dock='Fill';$header.BackColor=[System.Drawing.Color]::FromArgb(25,42,65);$title=New-Object System.Windows.Forms.Label;$title.Text='ACTIVE DIRECTORY SECURITY MONITOR';$title.ForeColor='White';$title.Font=New-Object System.Drawing.Font('Segoe UI',16,[System.Drawing.FontStyle]::Bold);$title.Left=20;$title.Top=16;$title.Width=520;$title.Height=32;$status=New-Object System.Windows.Forms.Label;$status.Text='Starting...';$status.ForeColor='LightGreen';$status.AutoSize=$false;$status.TextAlign='MiddleRight';$status.Anchor='Top,Right';$status.Left=560;$status.Top=17;$status.Width=670;$status.Height=28;$header.Controls.Add($title);$header.Controls.Add($status);$root.Controls.Add($header,0,0)
$cards=New-Object System.Windows.Forms.TableLayoutPanel;$cards.Dock='Fill';$cards.ColumnCount=5;$cards.Padding=New-Object System.Windows.Forms.Padding(8);1..5|ForEach-Object{Add-ColumnStyle $cards 'Percent' 20};$mFailed=New-MetricCard 'Failed authentications';$mSuccess=New-MetricCard 'Successful sessions';$mLock=New-MetricCard 'Account lockouts';$mAlerts=New-MetricCard 'Active alerts';$mSystems=New-MetricCard 'Domain controllers';$metricCards=@($mFailed,$mSuccess,$mLock,$mAlerts,$mSystems);for($i=0;$i-lt$metricCards.Count;$i++){$cards.Controls.Add($metricCards[$i].Panel,$i,0)};$root.Controls.Add($cards,0,1)
$toolbar=New-Object System.Windows.Forms.FlowLayoutPanel
$toolbar.Dock='Fill'
$toolbar.WrapContents=$false
$toolbar.Padding=New-Object System.Windows.Forms.Padding(12,8,0,0)

$inventory=New-Object System.Windows.Forms.Button
$inventory.Text='AD Inventory'
$inventory.Width=110
$inventory.Height=30

$refresh=New-Object System.Windows.Forms.Button
$refresh.Text='Refresh'
$refresh.Width=90
$refresh.Height=30
$refresh.Enabled = $false

$fetch = New-Object System.Windows.Forms.Button
$fetch.Text = 'Fetch'
$fetch.Width = 90
$fetch.Height = 30
$fetch.Enabled = $true

$export=New-Object System.Windows.Forms.Button
$export.Text='Export CSV'
$export.Width=90
$export.Height=30
$export.Enabled = $false

$searchLabel=New-Object System.Windows.Forms.Label
$searchLabel.Text='SamAccountName:'
$searchLabel.AutoSize=$true
$searchLabel.Margin=New-Object System.Windows.Forms.Padding(18,7,3,0)

$searchBox=New-Object System.Windows.Forms.TextBox
$searchBox.Width=160

$searchButton=New-Object System.Windows.Forms.Button
$searchButton.Text='Search last 1 day'
$searchButton.Width=120
$searchButton.Height=30

$searchProgress=New-Object System.Windows.Forms.ProgressBar
$searchProgress.Width=100
$searchProgress.Height=18
$searchProgress.Style='Marquee'
$searchProgress.MarqueeAnimationSpeed=30
$searchProgress.Visible=$false
$searchProgress.Margin=New-Object System.Windows.Forms.Padding(8,4,0,0)

$info=New-Object System.Windows.Forms.Label
$info.AutoSize=$true
$info.Margin=New-Object System.Windows.Forms.Padding(14,7,0,0)
$info.Text = "Event window: Last $LookbackMinutes minutes | Refresh: Manual"

$toolbar.Controls.Add($inventory)
$toolbar.Controls.Add($refresh)
$toolbar.Controls.Add($fetch)
$toolbar.Controls.Add($export)
$toolbar.Controls.Add($searchLabel)
$toolbar.Controls.Add($searchBox)
$toolbar.Controls.Add($searchButton)
$toolbar.Controls.Add($searchProgress)
$toolbar.Controls.Add($info)

$root.Controls.Add($toolbar,0,2)
$overview=New-Object System.Windows.Forms.TableLayoutPanel;$overview.Dock='Fill';$overview.ColumnCount=2;$overview.RowCount=2;$overview.Padding=New-Object System.Windows.Forms.Padding(8);Add-ColumnStyle $overview 'Percent' 50;Add-ColumnStyle $overview 'Percent' 50;Add-RowStyle $overview 'Percent' 50;Add-RowStyle $overview 'Percent' 50;$gridUsers=New-Grid;$gridSources=New-Grid;$gridSystems=New-Grid;$gridRecent=New-Grid;$overview.Controls.Add((New-OverviewGroup 'Top failed users' 'Accounts with the most failed authentications in the selected window.' $gridUsers),0,0);$overview.Controls.Add((New-OverviewGroup 'Top failure sources' 'Source IP addresses or workstations producing the most failures.' $gridSources),1,0);$overview.Controls.Add((New-OverviewGroup 'Domain controller summary' 'Collection status and authentication-event volume from each domain controller.' $gridSystems),0,1);$overview.Controls.Add((New-OverviewGroup 'Recent authentication activity' 'Grouped sessions, failed attempts and lockouts for quick triage.' $gridRecent),1,1);$root.Controls.Add($overview,0,3)


$userSearchTimer=New-Object System.Windows.Forms.Timer
$userSearchTimer.Interval=250
$userSearchTimer.Add_Tick({
    if ($null -eq $script:UserSearchPowerShell -or $null -eq $script:UserSearchAsync) {
        $userSearchTimer.Stop()
        return
    }

if (-not $script:UserSearchAsync.IsCompleted) {
    $script:UserSearchDots = ($script:UserSearchDots + 1) % 4
    $dots = '.' * $script:UserSearchDots

   $elapsed = [int]((Get-Date)-$script:UserSearchStarted).TotalSeconds
    $status.Text = (
        'Searching last {0} hours for {1}{2} | Elapsed: {3}s' -f
        $UserSearchLookbackHours,
        $script:UserSearchName,
        $dots,
        $elapsed
    )

    return
}

    $userSearchTimer.Stop()
    try {
        $output = @($script:UserSearchPowerShell.EndInvoke($script:UserSearchAsync))
        $streamErrors = @($script:UserSearchPowerShell.Streams.Error | ForEach-Object { $_.ToString() })
        $rows = @($output | Where-Object { $_.RecordType -eq 'Event' } | Sort-Object Time -Descending)
        $dcErrors = @($output | Where-Object { $_.RecordType -eq 'Error' })

        if ($streamErrors.Count -gt 0 -and $rows.Count -eq 0) { throw ($streamErrors -join ' | ') }

        foreach ($row in $rows) {
            $row | Add-Member -NotePropertyName DisplayName -NotePropertyValue (Get-UserDisplayName -SamAccountName $script:UserSearchName) -Force
        }

        $purpose = ('User activity for {0} during the last {1} hours. Events: 4624, 4625, 4740, 4768, 4771 and 4776. Records: {2}. DC query errors: {3}.' -f $script:UserSearchName,$UserSearchLookbackHours,$rows.Count,$dcErrors.Count)
        Set-UserSearchBusyState $false
        $status.Text = ('User search completed: {0} record(s), {1} DC error(s).' -f $rows.Count,$dcErrors.Count)

        Show-DetailWindow -Title ('User activity - {0}' -f $script:UserSearchName) -Purpose $purpose -Rows $rows -Columns @(
            'Time','EventId','Activity','Result','SamAccountName','DisplayName','Source',
           'CallerComputer','AuthenticationDC','LogonType','LogonTypeName','Status'
        ) -EmptyMessage ('No matching activity found for {0} in the last {1} hours.' -f $script:UserSearchName,$UserSearchLookbackHours) -EnableReportFilters

        if ($dcErrors.Count -gt 0) {
            $errorText = ($dcErrors | ForEach-Object { '{0}: {1}' -f $_.AuthenticationDC,$_.Error }) -join "`r`n"
            [void][System.Windows.Forms.MessageBox]::Show(
                ("Search completed with DC query errors:`r`n`r`n{0}" -f $errorText),
                'User search warnings','OK','Warning'
            )
        }
    }
    catch {
        Set-UserSearchBusyState $false
        $status.Text='User search failed'
        [void][System.Windows.Forms.MessageBox]::Show(
            ("User search failed.`r`n`r`n{0}" -f $_.Exception.Message),
            'User search error','OK','Error'
        )
    }
    finally {
        if ($null -ne $script:UserSearchPowerShell) { try { $script:UserSearchPowerShell.Dispose() } catch { } }
        $script:UserSearchPowerShell=$null
        $script:UserSearchAsync=$null
        $searchBox.Focus()
    }
})
function Update-Dashboard {

    if ($script:Busy) {
        return
    }

    $script:Busy = $true

    $fetch.Enabled = $false
    $refresh.Enabled = $false
    $export.Enabled = $false

    $status.Text = 'Collecting security events...'
    $form.UseWaitCursor = $true
    $form.Refresh()
    $fetch.Text = 'Fetching...'
    $refresh.Text = 'Refreshing...'

    try {

        #
        # Collect current monitoring window
        #

        $script:LastCollection = Get-AuthenticationData `
            -Targets $targets `
            -StartTime ((Get-Date).AddMinutes(-$LookbackMinutes))

        $script:LastAnalysis = Get-Analysis `
            -Events $script:LastCollection.Events

        #
        # Calculate counts
        #

        $fc = Get-SafeCount $script:LastAnalysis.Failed
        $sc = Get-SafeCount $script:LastAnalysis.SuccessSessions
        $lc = Get-SafeCount $script:LastAnalysis.Lockouts
        $ac = Get-SafeCount $script:LastAnalysis.Alerts
        $tc = Get-SafeCount $script:LastCollection.Systems
        $ec = Get-SafeCount $script:LastCollection.Errors

        #
        # Update metric cards
        #

        $mFailed.Value.Text = [string]$fc
        $mSuccess.Value.Text = [string]$sc
        $mLock.Value.Text = [string]$lc
        $mAlerts.Value.Text = [string]$ac
        $mSystems.Value.Text = [string]$tc

        if ($fc -gt 0) {
            $mFailed.Value.ForeColor = 'DarkOrange'
        }
        else {
            $mFailed.Value.ForeColor = 'ForestGreen'
        }

        $mSuccess.Value.ForeColor = 'ForestGreen'

        if ($lc -gt 0) {
            $mLock.Value.ForeColor = 'DarkOrange'
        }
        else {
            $mLock.Value.ForeColor = 'ForestGreen'
        }

        if ($ac -gt 0) {
            $mAlerts.Value.ForeColor = 'Crimson'
        }
        else {
            $mAlerts.Value.ForeColor = 'ForestGreen'
        }

        if ($ec -gt 0) {
            $mSystems.Value.ForeColor = 'Crimson'
        }
        else {
            $mSystems.Value.ForeColor = 'DodgerBlue'
        }

        #
        # Update dashboard grids
        #

        Set-GridRows `
            -Grid $gridUsers `
            -Rows $script:LastAnalysis.TopUsers `
            -Columns @(
                'User',
                'Failures'
            )

        Set-GridRows `
            -Grid $gridSources `
            -Rows $script:LastAnalysis.TopSources `
            -Columns @(
                'Source',
                'Failures'
            )

        Set-GridRows `
            -Grid $gridSystems `
            -Rows $script:LastCollection.Systems `
            -Columns @(
                'Computer',
                'Status',
                'Success',
                'Failure',
                'Lockouts',
                'LastQuery',
                'Error'
            )

        Set-GridRows `
            -Grid $gridRecent `
            -Rows @(
                $script:LastAnalysis.RecentActivity |
                    Select-Object -First 20
            ) `
            -Columns @(
                'LastSeen',
                'User',
                'Source',
                'Activity',
                'Count',
                'AuthenticatedDC'
            )

        #
        # Mark initial collection complete
        #

        $script:DashboardDataLoaded = $true

        $status.Text = (
            'Last update: {0:yyyy-MM-dd HH:mm:ss} | Alerts: {1} | Collection errors: {2}' -f
            (Get-Date),
            $ac,
            $ec
        )
    }
    catch {

        $status.Text = 'Collection failed'

        [void][System.Windows.Forms.MessageBox]::Show(
            (
                "Dashboard collection failed.`r`n`r`n" +
                "Error: {0}`r`n" +
                "Line: {1}" -f
                $_.Exception.Message,
                $_.InvocationInfo.ScriptLineNumber
            ),
            'Dashboard error',
            'OK',
            'Error'
        )
    }
    finally {

    $script:Busy = $false
    $form.UseWaitCursor = $false

    $fetch.Text = 'Fetch'
    $refresh.Text = 'Refresh'

    if ($script:DashboardDataLoaded) {

        $fetch.Enabled = $false
        $refresh.Enabled = $true
        $export.Enabled = $true
    }
    else {

        $fetch.Enabled = $true
        $refresh.Enabled = $false
        $export.Enabled = $false
    }
}
}

$showFailed={if($script:LastAnalysis){Show-DetailWindow 'Failed authentication summary' 'Failures grouped by SAM account name, source IP and authenticating DC.' @($script:LastAnalysis.FailureSummary|Sort-Object LastSeen -Descending) @('SamAccountName','DisplayName','SourceIP','AuthenticatedDC','FirstSeen','LastSeen','Attempts')}}
$showSuccess={if($script:LastAnalysis){Show-DetailWindow 'Successful sessions' 'All successful Event 4624 logon types are included. Use LogonTypeName to identify Interactive, Network, Batch, Service, RDP and other activity.' @($script:LastAnalysis.SuccessSessions|Sort-Object LastSeen -Descending) @('User','DisplayName','Source','AuthenticatedDC','LogonType','LogonTypeName','FirstSeen','LastSeen','RawEvents')}}
$showLock={if($script:LastAnalysis){Show-DetailWindow 'Account lockouts' 'Locked SAM account, display name, caller computer and DC recording Event 4740.' @($script:LastAnalysis.Lockouts|Sort-Object Time -Descending) @('Time','SamAccountName','DisplayName','CallerComputer','AuthenticatedDC')}}
$showAlerts={if($script:LastAnalysis){Show-DetailWindow 'Active security alerts' 'Threshold detections. Validate activity before containment.' @($script:LastAnalysis.Alerts|Sort-Object Count -Descending) @('Severity','Type','User','Source','Count','Details') 'No activity crossed the configured thresholds.'}}
$showSystems = {
    if($script:LastCollection){
        Show-DetailWindow `
            -Title 'Domain controllers' `
            -Purpose 'DC reachability and authentication statistics.' `
            -Rows $script:LastCollection.Systems `
            -Columns @(
                'Computer',
                'Status',
                'Success',
                'Failure',
                'Lockouts',
                'LastQuery',
                'Error'
            )
    }
}
foreach($c in @($mFailed.Panel,$mFailed.Caption,$mFailed.Value)){$c.Add_Click($showFailed)};foreach($c in @($mSuccess.Panel,$mSuccess.Caption,$mSuccess.Value)){$c.Add_Click($showSuccess)};foreach($c in @($mLock.Panel,$mLock.Caption,$mLock.Value)){$c.Add_Click($showLock)};foreach($c in @($mAlerts.Panel,$mAlerts.Caption,$mAlerts.Value)){$c.Add_Click($showAlerts)};foreach($c in @($mSystems.Panel,$mSystems.Caption,$mSystems.Value)){$c.Add_Click($showSystems)}

#
# User activity search
#

$searchButton.Add_Click({

    Start-UserSearch `
        -SamAccountName $searchBox.Text
})

$searchBox.Add_KeyDown({

    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {

        $_.SuppressKeyPress = $true

        Start-UserSearch `
            -SamAccountName $searchBox.Text
    }
})

#
# Open AD Inventory
#

$inventory.Add_Click({
    Show-InventoryWindow
})

#
# Initial security dashboard collection
#

$fetch.Add_Click({

    if ($script:Busy) {
        return
    }

    if ($script:DashboardDataLoaded) {
        return
    }

    Update-Dashboard
})

#
# Manual subsequent collection
#

$refresh.Add_Click({

    if ($script:Busy) {
        return
    }

    if (-not $script:DashboardDataLoaded) {

        [void][System.Windows.Forms.MessageBox]::Show(
            'Click Fetch before using Refresh.',
            'Dashboard',
            'OK',
            'Information'
        )

        return
    }

    Update-Dashboard
})

$export.Add_Click({
    if(-not$script:LastAnalysis){[void][System.Windows.Forms.MessageBox]::Show('No dashboard data is available to export.','Export','OK','Information');return}
    try{if(-not(Test-Path -LiteralPath $ExportFolder)){[void](New-Item -ItemType Directory -Path $ExportFolder -Force -ErrorAction Stop)};$stamp=Get-Date -Format 'yyyyMMdd-HHmmss';$sets=@{'Alerts'=$script:LastAnalysis.Alerts;'Failures'=$script:LastAnalysis.Failed;'Successes'=$script:LastAnalysis.Success;'SuccessSessions'=$script:LastAnalysis.SuccessSessions;'FailureSummary'=$script:LastAnalysis.FailureSummary;'Lockouts'=$script:LastAnalysis.Lockouts;'Systems'=$script:LastCollection.Systems};foreach($name in $sets.Keys){$sets[$name]|Export-Csv -LiteralPath (Join-Path $ExportFolder "$name-$stamp.csv") -NoTypeInformation -Encoding UTF8};[void][System.Windows.Forms.MessageBox]::Show("Exported to $ExportFolder",'Export complete','OK','Information')}
    catch{[void][System.Windows.Forms.MessageBox]::Show(("Export failed.`r`n`r`n{0}`r`nLine: {1}"-f$_.Exception.Message,$_.InvocationInfo.ScriptLineNumber),'Export error','OK','Error')}
})
$form.Add_Shown({

    $script:DashboardDataLoaded = $false

    $fetch.Enabled = $true
    $refresh.Enabled = $false
    $export.Enabled = $false

    $status.Text =
        'Ready - click Fetch to collect the latest security events'
})
$form.Add_FormClosed({

    $userSearchTimer.Stop()
    $userSearchTimer.Dispose()

    if ($null -ne $script:UserSearchPowerShell) {

        try {
            $script:UserSearchPowerShell.Stop()
        }
        catch {
        }

        try {
            $script:UserSearchPowerShell.Dispose()
        }
        catch {
        }
    }
})
# ============================================================
# APPLICATION AUTHENTICATION
# ============================================================

$loginSuccessful =
    Show-ADUtilityLogin


if (-not $loginSuccessful) {

    return
}
# ============================================================
# APPLY ROLE-BASED GUI ACCESS
# ============================================================

if ($script:AuthenticatedRole -eq 'Helpdesk') {

    #
    # HelpDesk cannot access AD Inventory / Reporting
    #

    $inventory.Visible = $false
}


if ($script:AuthenticatedRole -eq 'Admin') {

    #
    # Admin has full application access
    #

    $inventory.Visible = $true
}
# ============================================================
# SHOW MAIN APPLICATION
# ============================================================

[void]$form.ShowDialog()
