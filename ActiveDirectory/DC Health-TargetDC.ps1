
<# 
Domain Controller Health Report
Owner: Bhagawan Tapase
You run it like : .\DCHealth.ps1 -TargetDC DC01 or After running the script, you can enter the hostname in TargetDC
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$TargetDC
)
# ------------------------------
# Global variables
# ------------------------------
$now = Get-Date
$date = $now.ToShortDateString()
[array]$allDomainControllers = @()
[array]$allTestedDomainControllers = @()
$reportEmailSubject = "Domain Controller Health Report"

# ------------------------------
# Functions
# ------------------------------

# Forest domains
Function Get-AllDomains() {
    Write-Verbose "..running function Get-AllDomains"
    (Get-ADForest).Domains
}

# Domain controllers by domain
Function Get-AllDomainControllers($DomainNameInput) {
    Write-Verbose "..running function Get-AllDomainControllers"
    Get-ADDomainController -Filter * -Server $DomainNameInput
}

# DNS A-record
Function Get-DomainControllerNSLookup($DomainNameInput) {
    Write-Verbose "..running function Get-DomainControllerNSLookup"
    try { Resolve-DnsName $DomainNameInput -Type A -ErrorAction Stop | Out-Null; 'Success' } catch { 'Fail' }
}

# Ping
Function Get-DomainControllerPingStatus($DomainNameInput) {
    Write-Verbose "..running function Get-DomainControllerPingStatus"
    if (Test-Connection $DomainNameInput -Count 1 -Quiet) { "Success" } else { "Fail" }
}

# Last boot time (string)
Function Get-DomainControllerUpTime {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DomainNameInput)
    Write-Verbose "..running function Get-DomainControllerUpTime"
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $DomainNameInput -ErrorAction Stop
        $bootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        return $bootTime.ToString("MM/dd/yyyy hh:mm:ss tt")
    } catch {
        try {
            $w32 = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $DomainNameInput -ErrorAction Stop
            $bootTime = $w32.ConvertToDateTime($w32.LastBootUpTime)
            return $bootTime.ToString("MM/dd/yyyy hh:mm:ss tt")
        } catch { return 'Fail' } # mark as Fail to color red
    }
}

# DNS/NTDS/NetLogon services
Function Get-DomainControllerServices($DomainNameInput) {
    Write-Verbose "..running function Get-DomainControllerServices"
    $res = New-Object PSObject
    $res | Add-Member NoteProperty -Name DNSService -Value $null
    $res | Add-Member NoteProperty -Name NTDSService -Value $null
    $res | Add-Member NoteProperty -Name NETLOGONService -Value $null
    if (Test-Connection $DomainNameInput -Count 1 -Quiet) {
        try {
            $res.DNSService       = if ((Get-Service -ComputerName $DomainNameInput -Name DNS       -ErrorAction SilentlyContinue).Status -eq 'Running') { 'Success' } else { 'Fail' }
            $res.NTDSService      = if ((Get-Service -ComputerName $DomainNameInput -Name NTDS      -ErrorAction SilentlyContinue).Status -eq 'Running') { 'Success' } else { 'Fail' }
            $res.NETLOGONService  = if ((Get-Service -ComputerName $DomainNameInput -Name NetLogon  -ErrorAction SilentlyContinue).Status -eq 'Running') { 'Success' } else { 'Fail' }
        } catch {
            $res.DNSService='Fail'; $res.NTDSService='Fail'; $res.NETLOGONService='Fail'
        }
    } else {
        $res.DNSService='Fail'; $res.NTDSService='Fail'; $res.NETLOGONService='Fail'
    }
    $res
}

# Robust DCDIAG parser
Function Get-DomainControllerDCDiagTestResults($DomainNameInput) {
    Write-Verbose "..running function Get-DomainControllerDCDiagTestResults"
    $DCDiagTestResults = New-Object PSObject
    $DCDiagTestResults | Add-Member -Type NoteProperty -Name "ServerName" -Value $DomainNameInput
    $DCDiagTestResults | Add-Member -Type NoteProperty -Name "Advertising" -Value $null
    $DCDiagTestResults | Add-Member -Type NoteProperty -Name "Replications" -Value $null
    $DCDiagTestResults | Add-Member -Type NoteProperty -Name "KnowsOfRoleHolders" -Value $null
    $DCDiagTestResults | Add-Member -Type NoteProperty -Name "FSMOCheck" -Value $null
    $DCDiagTestResults | Add-Member -Type NoteProperty -Name "Services" -Value $null
    if (Test-Connection $DomainNameInput -Count 1 -Quiet) {
        try {
            $lines = (dcdiag /s:$DomainNameInput /test:services /test:FSMOCheck /test:KnowsOfRoleHolders /test:Advertising /test:Replications 2>&1) -split "`r?`n"
            $currentTest = $null
            foreach ($line in $lines) {
                if ($line -match 'Starting test:\s*(\S+)') { $currentTest = $Matches[1]; continue }
                if ($currentTest -and $line -match '(?i)passed test') { $DCDiagTestResults | Add-Member -Force -Type NoteProperty -Name $currentTest -Value 'Passed'; $currentTest=$null; continue }
                if ($currentTest -and $line -match '(?i)failed test') { $DCDiagTestResults | Add-Member -Force -Type NoteProperty -Name $currentTest -Value 'Failed'; $currentTest=$null; continue }
            }
            foreach ($name in 'Advertising','Replications','KnowsOfRoleHolders','FSMOCheck','Services') {
                if (-not $DCDiagTestResults.PSObject.Properties[$name].Value) {
                    $DCDiagTestResults | Add-Member -Force -Type NoteProperty -Name $name -Value 'Failed'
                }
            }
        } catch {
            foreach ($name in 'Advertising','Replications','KnowsOfRoleHolders','FSMOCheck','Services') {
                $DCDiagTestResults | Add-Member -Force -Type NoteProperty -Name $name -Value 'Failed'
            }
        }
    } else {
        foreach ($name in 'Advertising','Replications','KnowsOfRoleHolders','FSMOCheck','Services') {
            $DCDiagTestResults | Add-Member -Force -Type NoteProperty -Name $name -Value 'Failed'
        }
    }
    $DCDiagTestResults
}

# OS caption
Function Get-DomainControllerOSVersion($DomainNameInput) {
    Write-Verbose "..running function Get-DomainControllerOSVersion"
    try {
        (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $DomainNameInput -ErrorAction Stop).Caption
    } catch { 'Fail' } # mark red when unavailable
}

# System drive free (GB)
Function Get-DomainControllerOSDriveFreeSpaceGB($DomainNameInput) {
    Write-Verbose "..running function Get-DomainControllerOSDriveFreeSpaceGB"
    if (Test-Connection $DomainNameInput -Count 1 -Quiet) {
        try {
            $drive = (Get-WmiObject Win32_OperatingSystem -ComputerName $DomainNameInput -ErrorAction Stop).SystemDrive
            $disk  = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $DomainNameInput -ErrorAction Stop | Where-Object { $_.DeviceID -eq $drive }
            if ($disk -and $disk.FreeSpace) { [math]::Round(([double]$disk.FreeSpace) / 1GB, 1) } else { 'Fail' }
        } catch { 'Fail' } # mark red when unavailable
    } else { 'Fail' }     # mark red when offline
}

# Status badge cell (DNS/Ping etc.) — APPLY COLOR TO <td>
Function New-StatusCell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$value,
        [Parameter(Mandatory = $false)] [int] $maxWidthPx = 120,
        [Parameter(Mandatory = $false)] [string]$textAlign = 'center',
        [Parameter(Mandatory = $false)] [string]$cellClass = ''
    )
    $bg = '#eeeeee'; $fg = '#333333'
    switch -Regex ($value) {
        '^(Success|Passed|Pass)$' { $bg = '#e9f9e5'; $fg = '#0a7f00'; break }
        '^(Warn|Warning)$'        { $bg = '#fff4cc'; $fg = '#8a6d00'; break }
        '^(Fail|Failed|Access Denied)$' { $bg = '#ffe2e2'; $fg = '#a20000'; break }
    }
    $tdStyle   = 'white-space:nowrap;word-break:normal;' +
                 "text-align:$textAlign;" +
                 "max-width:${maxWidthPx}px;" +
                 'overflow:hidden;text-overflow:ellipsis;' +
                 'padding:4px 6px;line-height:1.2;' +
                 "background:$bg;color:$fg;"
    # IMPORTANT: darker pill border via currentColor (inherits TD text color)
    $spanStyle = 'display:inline-block;padding:2px 8px;border-radius:999px;' +
                 'font-size:11px;font-weight:600;border:1px solid currentColor;'
    $openTd = '<td'
    if ($cellClass -and $cellClass.Trim() -ne '') { $openTd += " class='$cellClass'" }
    $openTd += " style='$tdStyle'>"
    $badge  = "<span style='$spanStyle'>$value</span>"
    $closeTd = '</td>'
    return ($openTd + $badge + $closeTd)
}

# Numeric badge cell (Processing Time) — APPLY COLOR TO <td>
Function New-NumberBadgeCell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [double]$value,
        [Parameter(Mandatory = $true)] [double]$averageThreshold,
        [Parameter(Mandatory = $false)] [string]$cellClass = '',
        [Parameter(Mandatory = $false)] [int] $maxWidthPx = 120,
        [Parameter(Mandatory = $false)] [string]$textAlign = 'center',
        [Parameter(Mandatory = $false)] [string]$labelFormat = '{0}'
    )
    $badgeBg = '#e9f9e5'; $badgeFg = '#0a7f00'
    if ($value -gt $averageThreshold) { $badgeBg = '#fff4cc'; $badgeFg = '#8a6d00' }
    $tdStyle   = 'white-space:nowrap;word-break:normal;' +
                 "text-align:$textAlign;" +
                 "max-width:${maxWidthPx}px;" +
                 'overflow:hidden;text-overflow:ellipsis;' +
                 'padding:4px 6px;line-height:1.2;' +
                 "background:$badgeBg;color:$badgeFg;"
    # IMPORTANT: darker pill border via currentColor (inherits TD text color)
    $spanStyle = 'display:inline-block;padding:2px 8px;border-radius:999px;' +
                 'font-size:11px;font-weight:600;border:1px solid currentColor;'
    $openTd = '<td'
    if ($cellClass -and $cellClass.Trim() -ne '') { $openTd += " class='$cellClass'" }
    $openTd += " style='$tdStyle'>"
    $label = [string]::Format($labelFormat, $value)
    $badge = "<span style='$spanStyle'>$label</span>"
    $closeTd = '</td>'
    return ($openTd + $badge + $closeTd)
}

# Authoritative FSMO role holders
Function Get-FSMORoleHolders {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$DomainName)
    $forest = Get-ADForest -ErrorAction Stop
    $domain = Get-ADDomain -Server $DomainName -ErrorAction Stop
    [ordered]@{
        SchemaMaster         = $forest.SchemaMaster
        DomainNamingMaster   = $forest.DomainNamingMaster
        RIDMaster            = $domain.RIDMaster
        PDCEmulator          = $domain.PDCEmulator
        InfrastructureMaster = $domain.InfrastructureMaster
    }
}

# --- Last Patch Date & KB resolver (DISM-first, KB via WU event log, fallback to HotFix/QFE) ---
Function Get-DomainControllerPatchInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerNameInput)

    Write-Verbose "..running function Get-DomainControllerPatchInfo (CU-only; KB + install date bound to same source)"
    $info = [pscustomobject]@{
        'Last Patch Date'     = $null
        'Latest KB Installed' = $null
        'Source'              = $null
        'Detail'              = $null
    }

    if (-not (Test-Connection $ComputerNameInput -Count 1 -Quiet)) {
        $info.'Last Patch Date'     = 'Fail'
        $info.'Latest KB Installed' = 'Fail'
        $info.Source                = 'Offline'
        return $info
    }

    # Helper to run locally/remotely
    $InvokeSB = {
        param($sb, $Computer)
        if ($Computer -eq $env:COMPUTERNAME) { & $sb } else { Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ErrorAction Stop }
    }

    # 1) WU COM history
    try {
        $sbWU = {
            $searcher = New-Object -ComObject Microsoft.Update.Searcher
            $count    = $searcher.GetTotalHistoryCount()
            if ($count -le 0) { return $null }

            $batch = [math]::Min(200, $count)
            $hist  = $searcher.QueryHistory(0, $batch)

            $cu = $hist |
                Where-Object { $_.Title -match '(?i)\bCumulative Update\b' } |
                Where-Object { $_.Title -notmatch '(?i)Preview|Defender|Security Intelligence|Malicious Software Removal Tool' } |
                Sort-Object Date -Descending |
                Select-Object -First 1

            if (-not $cu) { return $null }

            $kb = $null
            $m  = [regex]::Match($cu.Title, '(?i)\bKB\d+\b')
            if ($m.Success) { $kb = $m.Value.ToUpper() }

            [pscustomobject]@{
                KB      = $kb
                Date    = [datetime]$cu.Date
                Title   = $cu.Title
                Result  = $cu.ResultCode
                HResult = $cu.HResult
                Op      = $cu.Operation
            }
        }

        $cuHist = & $InvokeSB $sbWU $ComputerNameInput
        if ($cuHist -and $cuHist.KB) {
            $info.'Latest KB Installed' = $cuHist.KB
            $info.'Last Patch Date'     = $cuHist.Date
            $info.Source                = 'WUHistory(COM)'
            $info.Detail                = $cuHist.Title
            return $info
        }
    } catch {
        Write-Verbose ("WU COM history failed on {0}: {1}" -f $ComputerNameInput, $_)
    }

    # 2) WU Operational Events
    try {
        $events = Get-WinEvent -ComputerName $ComputerNameInput -FilterHashtable @{
            LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'
            Id      = 19, 44
        } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending

        $cuEvents = $events |
            Where-Object { $_.Message -match '(?i)\bCumulative Update\b' } |
            Where-Object { $_.Message -notmatch '(?i)Preview|Defender|Security Intelligence|Malicious Software Removal Tool' }

        $latest = $cuEvents | Select-Object -First 1
        if ($latest) {
            # Extract KB robustly
            $kb = $null
            $kb = (($latest.Message -split '\s+') | Where-Object { $_ -match '(?i)^KB\d{7,}$' } | Select-Object -First 1)
            if (-not $kb) {
                $m = [regex]::Match($latest.Message, '(?i)\bKB\d+\b')
                if ($m.Success) { $kb = $m.Value }
            }
            if ($kb) { $kb = $kb.ToUpper() }

            $info.'Latest KB Installed' = if ($kb) { $kb } else { 'Fail' }
            $info.'Last Patch Date'     = [datetime]$latest.TimeCreated
            $info.Source                = 'WUEvent'
            $info.Detail                = $latest.Message

            if ($kb) { return $info }
        }
    } catch {
        Write-Verbose ("WU event lookup failed on {0}: {1}" -f $ComputerNameInput, $_)
    }

    # 3) DISM LCU package
    try {
        $sbDISM = {
            Get-WindowsPackage -Online -ErrorAction Stop |
                Where-Object { $_.PackageState -eq 'Installed' -and $_.InstallTime -and $_.PackageName -match 'Package_for_RollupFix' } |
                Sort-Object InstallTime -Descending |
                Select-Object -First 1
        }
        $lcu = & $InvokeSB $sbDISM $ComputerNameInput
        if ($lcu) {
            $kbFromPkg = (( $lcu.PackageName -split '[^A-Za-z0-9]' ) | Where-Object { $_ -match '^KB\d+$' } | Select-Object -First 1)
            if ($kbFromPkg) { $kbFromPkg = $kbFromPkg.ToUpper() }

            if (-not $info.'Last Patch Date' -or $info.'Last Patch Date' -is [string]) {
                $info.'Last Patch Date' = [datetime]$lcu.InstallTime
            }

            $info.'Latest KB Installed' = if ($kbFromPkg) { $kbFromPkg } else { 'Unknown' }
            if (-not $info.Source) { $info.Source = 'DISM' }
            $info.Detail = $lcu.PackageName
            return $info
        }
    } catch {
        Write-Verbose ("DISM lookup failed on {0}: {1}" -f $ComputerNameInput, $_)
    }

    # 4) No CU found -> Fail
    if (-not $info.'Last Patch Date')     { $info.'Last Patch Date'     = 'Fail' }
    if (-not $info.'Latest KB Installed') { $info.'Latest KB Installed' = 'Fail' }
    if (-not $info.Source)                { $info.Source                = 'None' }
    return $info
}

# SYSVOL / NETLOGON shares presence
Function Get-SYSVOLNetLogonShareStatus($DomainNameInput) {
    Write-Verbose "..running function Get-SYSVOLNetLogonShareStatus"
    $shares = New-Object PSObject
    $shares | Add-Member NoteProperty -Name "SYSVOL Share" -Value $null
    $shares | Add-Member NoteProperty -Name "NETLOGON Share" -Value $null
    if (Test-Connection $DomainNameInput -Count 1 -Quiet) {
        try {
            $shareList   = Get-WmiObject Win32_Share -ComputerName $DomainNameInput -ErrorAction SilentlyContinue
            $hasSysvol   = ($shareList | Where-Object { $_.Name -eq 'SYSVOL' })
            $hasNetlogon = ($shareList | Where-Object { $_.Name -eq 'NETLOGON' })
            $shares."SYSVOL Share"   = if ($hasSysvol)   { 'Success' } else { 'Fail' }
            $shares."NETLOGON Share" = if ($hasNetlogon) { 'Success' } else { 'Fail' }
        } catch {
            $shares."SYSVOL Share"   = 'Fail'
            $shares."NETLOGON Share" = 'Fail'
        }
    } else {
        $shares."SYSVOL Share"   = 'Fail'
        $shares."NETLOGON Share" = 'Fail'
    }
    $shares
}

# ------------------------------
# AD Replication health (new)
# ------------------------------
Function Get-ReplicationStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)

    try {
        $meta = Get-ADReplicationPartnerMetadata -Target $ComputerName -Scope Server -ErrorAction Stop
        $bad = $meta | Where-Object {
            ($_.ConsecutiveReplicationFailures -gt 0) -or
            ($_.LastReplicationResult -ne 0)
        }
        if ($bad) { 'Fail' } else { 'Success' }
    }
    catch { 'Fail' }
}

# ------------------------------
# GPO health (new)
# ------------------------------
Function Get-GPOHealth {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)

    try {
        $domainDnsRoot = (Get-ADDomain -Server $ComputerName -ErrorAction Stop).DNSRoot
        $policiesPath  = "\\$ComputerName\SYSVOL\$domainDnsRoot\Policies"

        if (-not (Test-Path $policiesPath)) { return 'Fail' }

        $policyFolders = Get-ChildItem -Path $policiesPath -Directory -ErrorAction Stop
        $hasIni        = $policyFolders | Where-Object { Test-Path (Join-Path $_.FullName 'GPT.INI') }

        if ($policyFolders.Count -gt 0 -and $hasIni) { 'Success' } else { 'Fail' }
    }
    catch { 'Fail' }
}

# ------------------------------
# Domains & report file
# ------------------------------
Import-Module ActiveDirectory -ErrorAction Stop

$DCObject = Get-ADDomainController -Identity $TargetDC -ErrorAction Stop

$allDomains = @($DCObject.Domain)

$reportFileName = 'D:\DC_Health_Report_' +
                  $DCObject.HostName.Split('.')[0] +
                  '_' +
                  (Get-Date -Format "yyyyMMdd_HHmmss") +
                  '.html'

# ------------------------------
# Main collection
# ------------------------------
$holdersCache = @{} # per-domain FSMO holders cache
foreach ($domain in $allDomains) {
    Write-Host "..testing domain" $domain -ForegroundColor Green
    if (-not $holdersCache.ContainsKey($domain)) {
        try { $holdersCache[$domain] = Get-FSMORoleHolders -DomainName $domain }
        catch { Write-Warning "Unable to read FSMO holders for domain '$domain': $_"; $holdersCache[$domain] = @{} }
    }
    $holders = $holdersCache[$domain]
    $allDomainControllers = @($DCObject)
    $totalDCProcessCount        = ($allDomainControllers | Measure-Object).Count
    $idx = 0

    foreach ($domainController in $allDomainControllers) {
        $idx++
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()
        $shortName = $domainController.HostName.Split('.')[0]
        Write-Host "..testing domain controller" "($idx of $totalDCProcessCount)" $shortName -ForegroundColor Cyan

        $DCDiagTestResults = Get-DomainControllerDCDiagTestResults $domainController.HostName

        $thisDomainController = New-Object PSObject
        $thisDomainController | Add-Member NoteProperty -Name Server -Value $null
        $thisDomainController | Add-Member NoteProperty -Name IPAddress -Value $null
        $thisDomainController | Add-Member NoteProperty -Name Site -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "OS Version" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name Domain -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Operation Master Roles" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DNS" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Ping" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Last Boot Time" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "System Drive Free (GB)" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Last Patch Date" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Latest KB Installed" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "GPO Health" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Replication Status" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "SYSVOL Share" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "NETLOGON Share" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DNS Service" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "NTDS Service" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "NetLogon Service" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DCDIAG: Advertising" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DCDIAG: Replications" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DCDIAG: FSMO KnowsOfRoleHolders" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DCDIAG: FSMO Check" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "DCDIAG: Services" -Value $null
        $thisDomainController | Add-Member NoteProperty -Name "Processing Time" -Value $null

        # Populate fields
        $thisDomainController.Server                = $shortName.ToUpper()
        $thisDomainController.IPAddress             = if ($domainController.IPv4Address) { [string]$domainController.IPv4Address } else { 'Fail' } # mark red if unknown
        $thisDomainController.Site                  = $domainController.Site
        $thisDomainController."OS Version"          = (Get-DomainControllerOSVersion $domainController.HostName)
        $thisDomainController.DNS                   = Get-DomainControllerNSLookup $domainController.HostName
        $thisDomainController.Ping                  = Get-DomainControllerPingStatus $domainController.HostName
        $thisDomainController."Last Boot Time"      = Get-DomainControllerUpTime -DomainNameInput $domainController.HostName
        $thisDomainController."System Drive Free (GB)" = Get-DomainControllerOSDriveFreeSpaceGB $domainController.HostName
        $thisDomainController.Domain                = $domain

        $svc = Get-DomainControllerServices $domainController.HostName
        $thisDomainController."DNS Service"         = $svc.DNSService
        $thisDomainController."NTDS Service"        = $svc.NTDSService
        $thisDomainController."NetLogon Service"    = $svc.NETLOGONService

        # Patch info (DISM-first, KB via WU event log)
        $patch = Get-DomainControllerPatchInfo $domainController.HostName
        $thisDomainController."Last Patch Date"     = $patch."Last Patch Date"     # keep DateTime where available, else 'Fail'
        $thisDomainController."Latest KB Installed" = $patch."Latest KB Installed"

        # Health (new functions)
        try { $thisDomainController."GPO Health"         = Get-GPOHealth        $domainController.HostName } catch { $thisDomainController."GPO Health"         = 'Fail' }
        try { $thisDomainController."Replication Status" = Get-ReplicationStatus $domainController.HostName } catch { $thisDomainController."Replication Status" = 'Fail' }

        # Shares
        $shareStatus = Get-SYSVOLNetLogonShareStatus $domainController.HostName
        $thisDomainController."SYSVOL Share"   = $shareStatus."SYSVOL Share"
        $thisDomainController."NETLOGON Share" = $shareStatus."NETLOGON Share"

        # DCDIAG mapped
        $thisDomainController."DCDIAG: Advertising"             = $DCDiagTestResults.Advertising
        $thisDomainController."DCDIAG: Replications"            = $DCDiagTestResults.Replications
        $thisDomainController."DCDIAG: FSMO KnowsOfRoleHolders" = $DCDiagTestResults.KnowsOfRoleHolders
        $thisDomainController."DCDIAG: FSMO Check"              = $DCDiagTestResults.FSMOCheck
        $thisDomainController."DCDIAG: Services"                = $DCDiagTestResults.Services

        # *** FSMO LOGIC (kept as in your original script) ***
        $dcFqdn = $domainController.HostName.ToLower()
        $rolesHeldByThisDC = New-Object System.Collections.Generic.List[string]
        foreach ($kv in $holders.GetEnumerator()) {
            $role        = $kv.Key
            $holderFqdn  = ($kv.Value -as [string]).ToLower()
            if ($holderFqdn -eq $dcFqdn) { $rolesHeldByThisDC.Add($role) }
        }
        $thisDomainController."Operation Master Roles" = $rolesHeldByThisDC.ToArray()

        # Processing time
        $thisDomainController."Processing Time" = [int][math]::Round($stopWatch.Elapsed.TotalSeconds)
        $allTestedDomainControllers += $thisDomainController
    }
}

# Optional sort
$allTestedDomainControllers = $allTestedDomainControllers | Sort-Object Site, Server

# ------------------------------
# Build HTML
# ------------------------------
$reportTime = Get-Date
$forestName = (Get-ADDomain).NetBIOSName

# HEAD
$htmlHead = @"
<html>
<style>
 BODY { font-family: Verdana; font-size: 8pt; }
 H1 { font-size: 16px; }
 H2 { font-size: 14px; }
 H3 { font-size: 12px; }
 TABLE { border: 1px solid black; border-collapse: collapse; font-size: 8pt; width: 100%; table-layout: auto; }
 TH { border: 1px solid black; background: #dddddd; padding: 5px; color: #000000; text-align: left; }
 TD { border: 1px solid black; padding: 5px; vertical-align: top; }
 TH, TD { white-space: normal; word-break: break-word; }
 th.server-name, td.server-name { white-space: nowrap; width: auto; max-width: none; }
 th.ipaddress { white-space: nowrap; }
 th.dns, td.dns, th.ping, td.ping {
  white-space: nowrap !important;
  word-break: normal !important;
  text-align: center;
 }
 td.dns, td.ping {
  max-width: 110px;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 4px 6px;
 }
 th.status, td.status {
  white-space: nowrap !important;
  word-break: normal !important;
  text-align: left;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 4px 6px;
  line-height: 1.2;
 }
 th.fsmo, td.fsmo {
  text-align: left;
  white-space: pre-line;
  word-break: normal;
  overflow-wrap: break-word;
  width: auto;
  min-width: unset;
  max-width: unset;
 }
 th.patch, td.patch,
 th.kb, td.kb {
  white-space: nowrap;
  text-align: left;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 4px 6px;
  line-height: 1.2;
 }

 /* Site and OS: wrap by words only (no mid-word breaks, no hyphenation) */
 th.site, td.site,
 th.os, td.os {
  white-space: normal !important;     /* allow wrapping */
  word-break: normal !important;      /* do not split inside words */
  overflow-wrap: normal !important;   /* break only at spaces */
  hyphens: none !important;
  text-align: left;
  max-width: 180px;                   /* tune as you like (160–220px) */
 }

 td.patch.pass, td.patch.warn, td.patch.fail,
 td.kb.pass, td.kb.warn, td.kb.fail { padding: 4px 6px; }
 th.ipaddress, td.ipaddress { width: auto; white-space: nowrap; text-align: left; }
 .table-wrapper { overflow-x: auto; }
</style>
<body>
<h1>Domain Controller Health Status Report</h1>
<h3>Generated: $reportTime<br> Developed &amp; Validated by: Bhagawan Tapase</h3>
"@

# Header
$htmlTableHeader = @"
<h3>Domain: $forestName</h3>
<div class=""table-wrapper"">
<table>
 <tr>
 <th class=""server-name"">Name</th>
 <th class=""ipaddress"">IP Address</th>
 <th class=""site"">Site</th>
 <th class=""os"">OS</th>
 <th class=""fsmo"">FSMO Roles</th>
 <th>Last Boot</th>
 <th>OS Free Space</th>
 <th class=""patch"">Last Patched</th>
 <th class=""kb"">KB Installed</th>
 <th class=""dns"">DNS</th>
 <th class=""ping"">Ping</th>
 <th>GPO Health</th>
 <th>Replication Status</th>
 <th>SYSVOL Share</th>
 <th>NETLOGON Share</th>
 <th>DNS Service</th>
 <th>NTDS Service</th>
 <th>NetLogon Service</th>
 <th>DCDIAG: Advertising</th>
 <th>DCDIAG: Replications</th>
 <th>DCDIAG: FSMO KnowsOfRoleHolders</th>
 <th>DCDIAG: FSMO Check</th>
 <th>DCDIAG: Services</th>
 <th>Scan Time (sec)</th>
 </tr>
"@
$serverHealthHtmlTable = $htmlTableHeader

# Average processing time for badge coloring
$averageProcessingTime = ($allTestedDomainControllers | Measure-Object -Property 'Processing Time' -Average).Average

foreach ($reportline in $allTestedDomainControllers) {
    $htmlTableRow = '<tr>'
    # Identity
    $htmlTableRow += "<td class='server-name'>$($reportline.Server)</td>"
    $htmlTableRow += "<td class='ipaddress' style='white-space:nowrap;text-align:left;width:auto;'>$([string]$reportline.IPAddress)</td>"
    $htmlTableRow += "<td class='site'>$($reportline.Site)</td>"
    $htmlTableRow += "<td class='os'>$($reportline.'OS Version')</td>"

    # FSMO roles
    $held = $reportline.'Operation Master Roles'
    if ($held -and $held.Count -gt 0) { $htmlTableRow += "<td class='fsmo'>$([string]::Join('<br>', $held))</td>" }
    else { $htmlTableRow += "<td class='fsmo'>None</td>" }

    # Last Boot cell
    $bootStr  = $reportline.'Last Boot Time'
    $bootFail = $false
    $bootDt   = $null
    if ([string]::IsNullOrWhiteSpace($bootStr) -or $bootStr -eq 'Fail') { $bootFail = $true }
    if (-not $bootFail) {
        $cult = [System.Globalization.CultureInfo]::InvariantCulture
        $fmtPrimary = 'MM/dd/yyyy hh:mm:ss tt'
        try { $bootDt = [datetime]::ParseExact($bootStr, $fmtPrimary, $cult) } catch {
            $fallbackFormats = @('MM/dd/yyyy hh:mm tt','MM/dd/yyyy HH:mm:ss','MM/dd/yyyy HH:mm','M/d/yyyy h:mm tt','yyyy-MM-dd HH:mm:ss','yyyy-MM-ddTHH:mm:ss')
            foreach ($f in $fallbackFormats) { try { $bootDt = [datetime]::ParseExact($bootStr, $f, $cult); break } catch {} }
            if (-not $bootDt) { try { $bootDt = [datetime]::Parse($bootStr, $cult) } catch { $bootFail = $true } }
        }
    }
    if ($bootFail -or -not $bootDt) {
        $tdStyle   = "word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:#ffe2e2;color:#a20000;"
        # pill span with border matching color
        $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
        $htmlTableRow += "<td class='fail' style='$tdStyle'><span style='$spanStyle'>Fail</span></td>"
    } else {
        $hoursSinceBoot = ((Get-Date) - $bootDt).TotalHours
        $bg = '#e9f9e5'; $fg = '#0a7f00'
        if ($hoursSinceBoot -le 24) { $bg = '#fff4cc'; $fg = '#8a6d00' }
        $datePart = $bootDt.ToString('MM/dd/yyyy')
        $timePart = $bootDt.ToString('hh:mm tt')
        $tdStyle   = "word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:$bg;color:$fg;"
        # pill span with border matching color
        $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
        $htmlTableRow += "<td style='$tdStyle'><span style='$spanStyle'>$datePart<br />$timePart</span></td>"
    }

    # System drive free (GB)
    $freeStr       = $reportline.'System Drive Free (GB)'
    $tdStyleBase   = "word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;"
    # pill span with border matching color
    $spanStyleBase = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
    $bg = '#e9f9e5'; $fg = '#0a7f00'; $label = $null
    $failFree = $false
    if ($freeStr -is [string]) {
        if ($freeStr -in @('Fail','Offline','Unknown','WMI Failure')) { $failFree = $true }
    }
    if (-not $failFree) {
        try {
            $gb = [int][math]::Round([double]$freeStr, 0)
            if ($gb -lt 10) { $bg='#fff4cc'; $fg='#8a6d00' } else { $bg='#e9f9e5'; $fg='#0a7f00' }
            $label = "{0} GB" -f $gb
        } catch { $failFree = $true }
    }
    if ($failFree) { $bg='#ffe2e2'; $fg='#a20000'; $label='Fail' }
    $htmlTableRow += ("<td style='{0}background:{1};color:{2};'><span style='{3}'>{4}</span></td>" -f $tdStyleBase, $bg, $fg, $spanStyleBase, $label)

    # Last Patched cell (DateTime)
    $ageDays   = $null
    $patchVal  = $reportline.'Last Patch Date'
    $patchFail = $false
    if ($patchVal -is [string] -and $patchVal -eq 'Fail') { $patchFail = $true }
    if (-not $patchFail) {
        try {
            $patchDate = [datetime]$patchVal
            $ageDays   = [math]::Floor(((Get-Date) - $patchDate).TotalDays)
            $datePart  = $patchDate.ToString('MM/dd/yyyy')
            $timePart  = $patchDate.ToString('hh:mm tt')
            $bg = '#e9f9e5'; $fg = '#0a7f00'
            if     ($ageDays -le 25) { $bg='#e9f9e5'; $fg='#0a7f00' }
            elseif ($ageDays -le 44) { $bg='#fff4cc'; $fg='#8a6d00' }
            elseif ($ageDays -le 89) { $bg='#ffe7cc'; $fg='#9a5a00' }
            else                     { $bg='#ffe2e2'; $fg='#a20000' }
            $tdStyle   = "word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:$bg;color:$fg;"
            # pill span with border matching color
            $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
            $htmlTableRow += "<td class='patch' style='$tdStyle'><span style='$spanStyle'>$datePart<br />$timePart</span></td>"
        } catch { $patchFail = $true }
    }
    if ($patchFail) {
        $tdStyle   = "word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:#ffe2e2;color:#a20000;"
        # pill span with border matching color
        $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
        $htmlTableRow += "<td class='patch' style='$tdStyle'><span style='$spanStyle'>Fail</span></td>"
        $ageDays = $null
    }

    # KB Installed
    $kbVal = [string]$reportline.'Latest KB Installed'
    if ([string]::IsNullOrWhiteSpace($kbVal) -or $kbVal -eq 'Fail') { $bg='#ffe2e2'; $fg='#a20000' }
    else {
        if ($ageDays -eq $null) {
            try { $ageDays = [math]::Floor(((Get-Date) - [datetime]$reportline.'Last Patch Date').TotalDays) } catch { $ageDays = 0 }
        }
        $bg = '#e9f9e5'; $fg = '#0a7f00'
        if     ($ageDays -le 25) { $bg='#e9f9e5'; $fg='#0a7f00' }
        elseif ($ageDays -le 44) { $bg='#fff4cc'; $fg='#8a6d00' }
        elseif ($ageDays -le 89) { $bg='#ffe7cc'; $fg='#9a5a00' }
        else                     { $bg='#ffe2e2'; $fg='#a20000' }
    }
    $tdStyle   = "white-space:nowrap;word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:$bg;color:$fg;"
    # pill span with border matching color
    $spanStyle = "display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;"
    $labelKb   = if ([string]::IsNullOrWhiteSpace($kbVal)) { 'Fail' } else { $kbVal }
    $htmlTableRow += "<td class='kb' style='$tdStyle'><span style='$spanStyle'>$labelKb</span></td>"

    # DNS / Ping and the rest (span borders are handled in function via currentColor)
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.DNS)                        -cellClass 'dns')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.Ping)                       -cellClass 'ping')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'GPO Health')               -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'Replication Status')       -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'SYSVOL Share')             -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'NETLOGON Share')           -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'DNS Service')              -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'NTDS Service')             -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'NetLogon Service')         -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'DCDIAG: Advertising')      -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'DCDIAG: Replications')     -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'DCDIAG: FSMO KnowsOfRoleHolders') -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'DCDIAG: FSMO Check')       -cellClass 'status')
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.'DCDIAG: Services')         -cellClass 'status')

    # Processing Time cell
    try { $proc = [double]$reportline.'Processing Time'; $htmlTableRow += (New-NumberBadgeCell -value $proc -averageThreshold $averageProcessingTime -labelFormat '{0}') }
    catch { $htmlTableRow += (New-NumberBadgeCell -value 0     -averageThreshold $averageProcessingTime -labelFormat '{0}') }

    $htmlTableRow += '</tr>'
    $serverHealthHtmlTable += $htmlTableRow
}
$serverHealthHtmlTable += '</table></div>'

# Tail
$htmlTail = @"
<hr>
<p style='font-size:08pt;'>
* Generated by PowerShell for Active Directory health monitoring.<br>
* Provides comprehensive checks including FSMO role holders, replication status, service health, and OS health metrics.<br>
* Designed for administrators to quickly assess domain controller health and identify potential issues.
</p>
</body>
</html>
"@

# Compose and write
$htmlReport     = $htmlHead + $serverHealthHtmlTable + $htmlTail
$reportFileName = ('D:\DC-Health_Report\DC_Health_Report_Internal_{0}.html' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$htmlReport | Out-File -FilePath $reportFileName -Encoding UTF8
Write-Host "Report written to: $reportFileName" -ForegroundColor Green

# ===============================
# EMAIL: DC Health Report (embed table + attach HTML)
# ===============================

$SmtpServer = 'YourRelayServer'
$SmtpPort   = 25
$UseSsl     = $false

$FromEmail  = 'noreply@yourdomain.com'
$FromName   = 'AD DC Health'
$ToEmail    = 'admin@yourdomain.com'
$CcEmail    = 'dl-admin@yourdomain.com'  # optional

# Subject fixed as requested
$subject = "Domain Controller Health Report - $forestName"

# Build HTML body
$emailBodyHeader = @"
<html>
<head>
<meta charset="utf-8">
<style>
 body { font-family: Verdana, Arial, sans-serif; font-size: 10pt; color: #000; }
 h2 { font-size: 16px; margin: 0 0 8px 0; }
 p.meta { font-size: 9pt; color: #555; margin: 4px 0 10px 0; }
 table { border-collapse: collapse; width: 100%; font-size: 9pt; }
 th, td { border: 1px solid #999; padding: 4px 6px; vertical-align: top; }
 .table-wrapper { overflow-x: auto; }

 /* Site and OS word-wrapping in email body too */
 th.site, td.site,
 th.os, td.os {
  white-space: normal !important;
  word-break: normal !important;
  overflow-wrap: normal !important;
  hyphens: none !important;
  text-align: left;
  max-width: 180px;
 }
 
 /* Keep Name column on one line in email body */
 th.server-name,
 td.server-name {
  white-space: nowrap !important;
  word-break: normal !important;
  overflow-wrap: normal !important;
  hyphens: none !important;
  width: auto !important;
  max-width: none !important;
 }

 .table-wrapper table tr > th:first-child,
 .table-wrapper table tr > td:first-child {
  white-space: nowrap !important;
  word-break: normal !important;
  overflow-wrap: normal !important;
 }
 
/* Light gray background for header cells in email body */
th {
  background-color: #dddddd !important; /* light gray */
  color: #000000 !important;            /* black text */
  text-align: left !important;        /* center horizontally */
  vertical-align: middle !important;    /* center vertically */

}

</style>
</head>
<body>
<h2>Domain Controller Health Status Report</h2>
<p class="meta">
Generated: $reportTime (Local)<br/>
</p>
"@

$emailBodyFooter = @"
<p style="font-size:9pt;color:#000000;margin-top:10px;">
* Attached: $([IO.Path]::GetFileName($reportFileName))<br/>
* Generated by PowerShell for Active Directory health monitoring.<br>
* Designed for administrators to quickly assess domain controller health and identify potential issues.<br>
</p>
</body>
</html>
"@

$emailBodyHtml = $emailBodyHeader + $serverHealthHtmlTable + $emailBodyFooter

# Send email (no DSN notifications)
Send-MailMessage `
    -From "$FromName <$FromEmail>" `
    -To $ToEmail `
    -Cc $CcEmail `
    -Subject $subject `
    -Body $emailBodyHtml `
    -BodyAsHtml `
    -SmtpServer $SmtpServer `
    -Port $SmtpPort `
    -Attachments $reportFileName
