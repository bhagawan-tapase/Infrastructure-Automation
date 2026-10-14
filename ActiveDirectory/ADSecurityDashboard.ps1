<#

  On-premises Active Directory authentication security dashboard.
  lockouts and threshold alerts, and supports CSV export and optional email alerts.
#>
[CmdletBinding()]
param(
    [int]$LookbackMinutes = 15,
    [int]$RefreshSeconds = 60,
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
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:UserDisplayNameCache = @{}
$script:DnsCache = @{}
$script:DCInventoryCache = @{}
$script:DCInventoryCacheMinutes = 30
$script:LastCollection = $null
$script:LastAnalysis = $null
$script:Busy = $false
$script:Paused = $false
$script:UserSearchPowerShell = $null
$script:UserSearchAsync = $null
$script:UserSearchName = ''
$script:UserSearchStarted = $null
$script:UserSearchDots = 0

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

function Get-DCInventoryCounts {
    param(
        [string]$DomainController
    )

    # Return cached result if still valid
    if ($script:DCInventoryCache.ContainsKey($DomainController)) {
        $cached = $script:DCInventoryCache[$DomainController]

        if (
            $null -ne $cached -and
            $cached.Time -ge (Get-Date).AddMinutes(-$script:DCInventoryCacheMinutes)
        ) {
            return $cached.Result
        }

        $script:DCInventoryCache.Remove($DomainController)
    }

    $result = [ordered]@{
        Reachable       = $false
        DirectoryStatus = 'Unavailable'
        ActiveUsers     = 0
        TotalGroups     = 0
        ActiveComputers = 0
        Error           = ''
    }

    try {

        if (-not (Get-Module -Name ActiveDirectory)) {
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        $rootDse = Get-ADRootDSE `
            -Server $DomainController `
            -ErrorAction Stop

       if (-not $rootDse.defaultNamingContext) {
    throw "The domain controller did not return a valid RootDSE response."
}

        $result.Reachable = $true
        $result.DirectoryStatus = 'Active and reachable'

        $result.ActiveUsers = @(
            Get-ADUser `
                -Filter 'Enabled -eq $true' `
                -Server $DomainController `
                -ResultSetSize $null `
                -ErrorAction Stop
        ).Count

        $result.TotalGroups = @(
            Get-ADGroup `
                -Filter * `
                -Server $DomainController `
                -ResultSetSize $null `
                -ErrorAction Stop
        ).Count

        $result.ActiveComputers = @(
            Get-ADComputer `
                -Filter 'Enabled -eq $true' `
                -Server $DomainController `
                -ResultSetSize $null `
                -ErrorAction Stop
        ).Count
    }
    catch {
        $result.Reachable = $false
        $result.DirectoryStatus = 'Unavailable'
        $result.Error = $_.Exception.Message
    }

    $finalResult = [pscustomobject]$result

    $script:DCInventoryCache[$DomainController] = @{
        Time   = Get-Date
        Result = $finalResult
    }

    return $finalResult
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

        $inventory = Get-DCInventoryCounts -DomainController $target

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
                    Computer        = [string]$target
                    Status          = if ($inventory.Reachable) {
                        'Active and reachable'
                    }
                    else {
                        'Security query successful; AD inventory unavailable'
                    }
                    Success         = Get-SafeCount @(
                        $local | Where-Object { $_.Kind -eq 'Success' }
                    )
                    Failure         = Get-SafeCount @(
                        $local | Where-Object { $_.Kind -eq 'Failure' }
                    )
                    Lockouts        = Get-SafeCount @(
                        $local | Where-Object { $_.EventId -eq 4740 }
                    )
                    LastQuery       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    ActiveUsers     = [int]$inventory.ActiveUsers
                    TotalGroups     = [int]$inventory.TotalGroups
                    ActiveComputers = [int]$inventory.ActiveComputers
                    Error           = [string]$inventory.Error
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
                    Computer        = [string]$target
                    Status          = 'Unavailable'
                    Success         = 0
                    Failure         = 0
                    Lockouts        = 0
                    LastQuery       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                    ActiveUsers     = [int]$inventory.ActiveUsers
                    TotalGroups     = [int]$inventory.TotalGroups
                    ActiveComputers = [int]$inventory.ActiveComputers
                    Error           = ($message + ' | ' + [string]$inventory.Error).Trim(' ','|')
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
    param([bool]$Busy)

    $searchButton.Enabled = -not $Busy
    $searchBox.Enabled = -not $Busy
    $refresh.Enabled = -not $Busy
    $pause.Enabled = -not $Busy
    $export.Enabled = -not $Busy
    $searchProgress.Visible = $Busy

    if ($Busy) {
        $searchButton.Text = 'Searching...'
        $form.UseWaitCursor = $true
        $timer.Stop()
    }
    else {
        $searchButton.Text = 'Search last 1 day'
        $form.UseWaitCursor = $false
        if (-not $script:Paused -and -not $form.IsDisposed) { $timer.Start() }
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
    $g.ColumnHeadersDefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(25,42,65);$g.ColumnHeadersDefaultCellStyle.ForeColor='White';$g.RowsDefaultCellStyle.ForeColor='Black';$g.AlternatingRowsDefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(242,246,250);$g.GridColor='LightGray';return $g
}
function Set-GridRows { param([System.Windows.Forms.DataGridView]$Grid,$Rows,[string[]]$Columns)
    $Grid.SuspendLayout();try{$Grid.DataSource=$null;$Grid.AutoSizeColumnsMode='None';$Grid.AutoGenerateColumns=$false;$Grid.Rows.Clear();$Grid.Columns.Clear()
        foreach($name in $Columns){$c=New-Object System.Windows.Forms.DataGridViewTextBoxColumn;$c.Name=$name;$c.HeaderText=$name;$c.MinimumWidth=75;$c.SortMode='Automatic';[void]$Grid.Columns.Add($c)}
        foreach($item in @($Rows)){if($null-eq$item){continue};$values=New-Object 'System.Collections.Generic.List[object]';foreach($name in $Columns){$p=$item.PSObject.Properties[$name];if($p-and$null-ne$p.Value){if($p.Value-is[datetime]){[void]$values.Add(([datetime]$p.Value).ToString('yyyy-MM-dd HH:mm:ss'))}else{[void]$values.Add([string]$p.Value)}}else{[void]$values.Add('')}};[void]$Grid.Rows.Add($values.ToArray())}
        $Grid.AutoSizeColumnsMode='Fill';if($Grid.Rows.Count-gt0){$Grid.ClearSelection()};$Grid.Refresh()
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

$targets=Get-MonitorTargets
$form=New-Object System.Windows.Forms.Form;$form.Text='AD Authentication & Lockout Dashboard';$form.StartPosition='CenterScreen';$form.Size=New-Object System.Drawing.Size(1280,800);$form.MinimumSize=New-Object System.Drawing.Size(1050,650);$form.Font=New-Object System.Drawing.Font('Segoe UI',9);$form.BackColor=[System.Drawing.Color]::FromArgb(230,235,241)
$root=New-Object System.Windows.Forms.TableLayoutPanel;$root.Dock='Fill';$root.RowCount=4;Add-RowStyle $root 'Absolute' 62;Add-RowStyle $root 'Absolute' 110;Add-RowStyle $root 'Absolute' 48;Add-RowStyle $root 'Percent' 100;$form.Controls.Add($root)
$header=New-Object System.Windows.Forms.Panel;$header.Dock='Fill';$header.BackColor=[System.Drawing.Color]::FromArgb(25,42,65);$title=New-Object System.Windows.Forms.Label;$title.Text='ACTIVE DIRECTORY SECURITY MONITOR';$title.ForeColor='White';$title.Font=New-Object System.Drawing.Font('Segoe UI',16,[System.Drawing.FontStyle]::Bold);$title.Left=20;$title.Top=16;$title.Width=520;$title.Height=32;$status=New-Object System.Windows.Forms.Label;$status.Text='Starting...';$status.ForeColor='LightGreen';$status.AutoSize=$false;$status.TextAlign='MiddleRight';$status.Anchor='Top,Right';$status.Left=560;$status.Top=17;$status.Width=670;$status.Height=28;$header.Controls.Add($title);$header.Controls.Add($status);$root.Controls.Add($header,0,0)
$cards=New-Object System.Windows.Forms.TableLayoutPanel;$cards.Dock='Fill';$cards.ColumnCount=5;$cards.Padding=New-Object System.Windows.Forms.Padding(8);1..5|ForEach-Object{Add-ColumnStyle $cards 'Percent' 20};$mFailed=New-MetricCard 'Failed authentications';$mSuccess=New-MetricCard 'Successful sessions';$mLock=New-MetricCard 'Account lockouts';$mAlerts=New-MetricCard 'Active alerts';$mSystems=New-MetricCard 'Domain controllers';$metricCards=@($mFailed,$mSuccess,$mLock,$mAlerts,$mSystems);for($i=0;$i-lt$metricCards.Count;$i++){$cards.Controls.Add($metricCards[$i].Panel,$i,0)};$root.Controls.Add($cards,0,1)
$toolbar=New-Object System.Windows.Forms.FlowLayoutPanel;$toolbar.Dock='Fill';$toolbar.WrapContents=$false;$toolbar.Padding=New-Object System.Windows.Forms.Padding(12,7,0,0);$refresh=New-Object System.Windows.Forms.Button;$refresh.Text='Refresh now';$pause=New-Object System.Windows.Forms.Button;$pause.Text='Pause';$export=New-Object System.Windows.Forms.Button;$export.Text='Export CSV';$searchLabel=New-Object System.Windows.Forms.Label;$searchLabel.Text='SamAccountName:';$searchLabel.AutoSize=$true;$searchLabel.Margin=New-Object System.Windows.Forms.Padding(18,7,3,0);$searchBox=New-Object System.Windows.Forms.TextBox;$searchBox.Width=160;$searchButton=New-Object System.Windows.Forms.Button;$searchButton.Text='Search last 1 day';$searchButton.Width=120;$searchProgress=New-Object System.Windows.Forms.ProgressBar;$searchProgress.Width=100;$searchProgress.Height=18;$searchProgress.Style='Marquee';$searchProgress.MarqueeAnimationSpeed=30;$searchProgress.Visible=$false;$searchProgress.Margin=New-Object System.Windows.Forms.Padding(8,4,0,0);$info=New-Object System.Windows.Forms.Label;$info.AutoSize=$true;$info.Margin=New-Object System.Windows.Forms.Padding(14,7,0,0);$info.Text="Live window: $LookbackMinutes min | Refresh: $RefreshSeconds sec";$toolbar.Controls.Add($refresh);$toolbar.Controls.Add($pause);$toolbar.Controls.Add($export);$toolbar.Controls.Add($searchLabel);$toolbar.Controls.Add($searchBox);$toolbar.Controls.Add($searchButton);$toolbar.Controls.Add($searchProgress);$toolbar.Controls.Add($info);$root.Controls.Add($toolbar,0,2)
$overview=New-Object System.Windows.Forms.TableLayoutPanel;$overview.Dock='Fill';$overview.ColumnCount=2;$overview.RowCount=2;$overview.Padding=New-Object System.Windows.Forms.Padding(8);Add-ColumnStyle $overview 'Percent' 50;Add-ColumnStyle $overview 'Percent' 50;Add-RowStyle $overview 'Percent' 50;Add-RowStyle $overview 'Percent' 50;$gridUsers=New-Grid;$gridSources=New-Grid;$gridSystems=New-Grid;$gridRecent=New-Grid;$overview.Controls.Add((New-OverviewGroup 'Top failed users' 'Accounts with the most failed authentications in the selected window.' $gridUsers),0,0);$overview.Controls.Add((New-OverviewGroup 'Top failure sources' 'Source IP addresses or workstations producing the most failures.' $gridSources),1,0);$overview.Controls.Add((New-OverviewGroup 'Domain controller summary' 'Collection status and authentication-event volume from each domain controller.' $gridSystems),0,1);$overview.Controls.Add((New-OverviewGroup 'Recent authentication activity' 'Grouped sessions, failed attempts and lockouts for quick triage.' $gridRecent),1,1);$root.Controls.Add($overview,0,3)


$timer=New-Object System.Windows.Forms.Timer;$timer.Interval=[Math]::Max(5,$RefreshSeconds)*1000
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
    if($script:Busy-or$script:Paused){return};$script:Busy=$true;$refresh.Enabled=$false;$timer.Stop();$status.Text='Collecting Security events...';$form.Refresh()
    try{
        $script:LastCollection=Get-AuthenticationData -Targets $targets -StartTime ((Get-Date).AddMinutes(-$LookbackMinutes));$script:LastAnalysis=Get-Analysis $script:LastCollection.Events
        $fc=Get-SafeCount $script:LastAnalysis.Failed;$sc=Get-SafeCount $script:LastAnalysis.SuccessSessions;$lc=Get-SafeCount $script:LastAnalysis.Lockouts;$ac=Get-SafeCount $script:LastAnalysis.Alerts;$tc=Get-SafeCount $script:LastCollection.Systems;$ec=Get-SafeCount $script:LastCollection.Errors
        $mFailed.Value.Text=[string]$fc;$mSuccess.Value.Text=[string]$sc;$mLock.Value.Text=[string]$lc;$mAlerts.Value.Text=[string]$ac;$mSystems.Value.Text=[string]$tc
        if($fc-gt0){$mFailed.Value.ForeColor='DarkOrange'}else{$mFailed.Value.ForeColor='ForestGreen'};$mSuccess.Value.ForeColor='ForestGreen';if($lc-gt0){$mLock.Value.ForeColor='DarkOrange'}else{$mLock.Value.ForeColor='ForestGreen'};if($ac-gt0){$mAlerts.Value.ForeColor='Crimson'}else{$mAlerts.Value.ForeColor='ForestGreen'};if($ec-gt0){$mSystems.Value.ForeColor='Crimson'}else{$mSystems.Value.ForeColor='DodgerBlue'}
        Set-GridRows $gridUsers $script:LastAnalysis.TopUsers @('User','Failures');Set-GridRows $gridSources $script:LastAnalysis.TopSources @('Source','Failures');Set-GridRows $gridSystems $script:LastCollection.Systems @('Computer','Status','Success','Failure','Lockouts','LastQuery','ActiveUsers','TotalGroups','ActiveComputers');Set-GridRows $gridRecent `
    @($script:LastAnalysis.RecentActivity | Select-Object -First 20) `
    @('LastSeen','User','Source','Activity','Count','AuthenticatedDC')
        $status.Text = (
    'Last update: {0:yyyy-MM-dd HH:mm:ss} | Alerts: {1} | Collection errors: {2}' -f
    (Get-Date),
    $ac,
    $ec
)
    }
    catch{$status.Text='Refresh failed';[void][System.Windows.Forms.MessageBox]::Show(("{0}`r`nLine: {1}"-f$_.Exception.Message,$_.InvocationInfo.ScriptLineNumber),'Dashboard error','OK','Error')}
    finally{$script:Busy=$false;$refresh.Enabled=$true;if(-not$script:Paused-and-not$form.IsDisposed){$timer.Start()}}
}

$showFailed={if($script:LastAnalysis){Show-DetailWindow 'Failed authentication summary' 'Failures grouped by SAM account name, source IP and authenticating DC.' @($script:LastAnalysis.FailureSummary|Sort-Object LastSeen -Descending) @('SamAccountName','DisplayName','SourceIP','AuthenticatedDC','FirstSeen','LastSeen','Attempts')}}
$showSuccess={if($script:LastAnalysis){Show-DetailWindow 'Successful sessions' 'All successful Event 4624 logon types are included. Use LogonTypeName to identify Interactive, Network, Batch, Service, RDP and other activity.' @($script:LastAnalysis.SuccessSessions|Sort-Object LastSeen -Descending) @('User','DisplayName','Source','AuthenticatedDC','LogonType','LogonTypeName','FirstSeen','LastSeen','RawEvents')}}
$showLock={if($script:LastAnalysis){Show-DetailWindow 'Account lockouts' 'Locked SAM account, display name, caller computer and DC recording Event 4740.' @($script:LastAnalysis.Lockouts|Sort-Object Time -Descending) @('Time','SamAccountName','DisplayName','CallerComputer','AuthenticatedDC')}}
$showAlerts={if($script:LastAnalysis){Show-DetailWindow 'Active security alerts' 'Threshold detections. Validate activity before containment.' @($script:LastAnalysis.Alerts|Sort-Object Count -Descending) @('Severity','Type','User','Source','Count','Details') 'No activity crossed the configured thresholds.'}}
$showSystems={if($script:LastCollection){Show-DetailWindow 'Domain controllers' 'DC reachability, authentication counts and Active Directory enabled-account inventory. Enabled user accounts, all groups, and enabled computer accounts are queried through each DC.' $script:LastCollection.Systems @('Computer','Status','Success','Failure','Lockouts','LastQuery','ActiveUsers','TotalGroups','ActiveComputers','Error')}}
foreach($c in @($mFailed.Panel,$mFailed.Caption,$mFailed.Value)){$c.Add_Click($showFailed)};foreach($c in @($mSuccess.Panel,$mSuccess.Caption,$mSuccess.Value)){$c.Add_Click($showSuccess)};foreach($c in @($mLock.Panel,$mLock.Caption,$mLock.Value)){$c.Add_Click($showLock)};foreach($c in @($mAlerts.Panel,$mAlerts.Caption,$mAlerts.Value)){$c.Add_Click($showAlerts)};foreach($c in @($mSystems.Panel,$mSystems.Caption,$mSystems.Value)){$c.Add_Click($showSystems)}
$searchButton.Add_Click({Start-UserSearch -SamAccountName $searchBox.Text});$searchBox.Add_KeyDown({if($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter){$_.SuppressKeyPress=$true;Start-UserSearch -SamAccountName $searchBox.Text}});$refresh.Add_Click({Update-Dashboard});$pause.Add_Click({$script:Paused=-not$script:Paused;if($script:Paused){$pause.Text='Resume';$status.Text='Paused';$timer.Stop()}else{$pause.Text='Pause';Update-Dashboard}})
$export.Add_Click({
    if(-not$script:LastAnalysis){[void][System.Windows.Forms.MessageBox]::Show('No dashboard data is available to export.','Export','OK','Information');return}
    try{if(-not(Test-Path -LiteralPath $ExportFolder)){[void](New-Item -ItemType Directory -Path $ExportFolder -Force -ErrorAction Stop)};$stamp=Get-Date -Format 'yyyyMMdd-HHmmss';$sets=@{'Alerts'=$script:LastAnalysis.Alerts;'Failures'=$script:LastAnalysis.Failed;'Successes'=$script:LastAnalysis.Success;'SuccessSessions'=$script:LastAnalysis.SuccessSessions;'FailureSummary'=$script:LastAnalysis.FailureSummary;'Lockouts'=$script:LastAnalysis.Lockouts;'Systems'=$script:LastCollection.Systems};foreach($name in $sets.Keys){$sets[$name]|Export-Csv -LiteralPath (Join-Path $ExportFolder "$name-$stamp.csv") -NoTypeInformation -Encoding UTF8};[void][System.Windows.Forms.MessageBox]::Show("Exported to $ExportFolder",'Export complete','OK','Information')}
    catch{[void][System.Windows.Forms.MessageBox]::Show(("Export failed.`r`n`r`n{0}`r`nLine: {1}"-f$_.Exception.Message,$_.InvocationInfo.ScriptLineNumber),'Export error','OK','Error')}
})
$timer.Add_Tick({Update-Dashboard});$form.Add_Shown({Update-Dashboard;$timer.Start()});$form.Add_FormClosed({$timer.Stop();$timer.Dispose();$userSearchTimer.Stop();$userSearchTimer.Dispose();if($null-ne$script:UserSearchPowerShell){try{$script:UserSearchPowerShell.Stop()}catch{};try{$script:UserSearchPowerShell.Dispose()}catch{}}});[void]$form.ShowDialog()
