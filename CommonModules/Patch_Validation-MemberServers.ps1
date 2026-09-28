<# 
Member Server Health Report post patching activity
Owner: Bhagawan Tapase
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "D:\servers.csv",  # default CSV path (column: ServerName)

    [Parameter(Mandatory = $false)]
    [string[]]$ComputerName,              # optional overrides / additions

    [Parameter(Mandatory = $false)]
    [switch]$ReportFile                   # kept for compatibility; report always saved & mailed
)

# ------------------------------
# Email Settings 
# ------------------------------
$SmtpServer = '10.100.48.132'
$SmtpPort   = 25
$UseSsl     = $false

$FromEmail  = 'noreply@yourdomain.com'
$FromName   = 'Member Server Health'
$ToEmail    = 'admin@yourdomain.com'
$CcEmail    = 'dl-admin@yourdomain.com'

# Subject
$subject    = "Member Server Health Report"

# ------------------------------
# Global variables
# ------------------------------
$reportTime = Get-Date
[array]$allTestedServers = @()

# ------------------------------
# Utilities: status/number badge cells
# ------------------------------
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
        '^(Success|Passed|Pass|Online|Available)$' { $bg = '#e9f9e5'; $fg = '#0a7f00'; break }
        '^(Warn|Warning)$'                          { $bg = '#fff4cc'; $fg = '#8a6d00'; break }
        '^(Fail|Failed|Offline|Access Denied)$'     { $bg = '#ffe2e2'; $fg = '#a20000'; break }
    }
    $tdStyle   = 'white-space:nowrap;word-break:normal;' +
                 "text-align:$textAlign;" +
                 "max-width:${maxWidthPx}px;" +
                 'overflow:hidden;text-overflow:ellipsis;' +
                 'padding:4px 6px;line-height:1.2;' +
                 "background:$bg;color:$fg;"
    $spanStyle = 'display:inline-block;padding:2px 8px;border-radius:999px;' +
                 'font-size:11px;font-weight:600;border:1px solid currentColor;'
    $openTd = '<td'
    if ($cellClass -and $cellClass.Trim() -ne '') { $openTd += " class='$cellClass'" }
    $openTd += " style='$tdStyle'>"
    $badge  = "<span style='$spanStyle'>$value</span>"
    $closeTd = '</td>'
    return ($openTd + $badge + $closeTd)
}

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

# ------------------------------
# Helpers
# ------------------------------
Import-Module CimCmdlets -ErrorAction SilentlyContinue

Function Test-ServerPing {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    try { if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) { 'Success' } else { 'Fail' } }
    catch { 'Fail' }
}

Function Get-ServerIP {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    try {
        $a = Resolve-DnsName -Name $ComputerName -Type A -ErrorAction Stop |
             Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($a) { $a.IPAddress } else { 'Fail' }
    } catch { 'Fail' }
}

Function Get-ServerOSVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    try {
        (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop).Caption
    } catch {
        try { (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop).Caption }
        catch { 'Fail' }
    }
}

# ⭐Always render the server-local boot time by parsing raw WMI DMTF string (no timezone shift)
Function Get-ServerBootTime {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    try {
        $os  = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        $raw = $os.LastBootUpTime  # e.g. 20260118025844.000000+300
        if ($raw -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})') {
            $year=$matches[1];$month=$matches[2];$day=$matches[3];$hour=$matches[4];$min=$matches[5];$sec=$matches[6]
            $dtString = "$month/$day/$year $hour`:$min`:$sec"
            $dt = [datetime]::ParseExact($dtString, 'MM/dd/yyyy HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
            return $dt.ToString('MM/dd/yyyy hh:mm:ss tt')
        } else { 'Fail' }
    }
    catch {
        try {
            # Fallback to CIM (may include local TZ conversion) — still better than no value
            $osCim = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            $dt    = [datetime]$osCim.LastBootUpTime
            return $dt.ToString('MM/dd/yyyy hh:mm:ss tt')
        } catch { 'Fail' }
    }
}

Function Get-ServerOSDriveFreeSpaceGB {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)
    if ((Test-ServerPing $ComputerName) -ne 'Success') { return 'Fail' }
    try {
        $drive = (Get-CimInstance Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop).SystemDrive
        $disk  = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction Stop |
                 Where-Object { $_.DeviceID -eq $drive }
        if ($disk -and $disk.FreeSpace) { [math]::Round(([double]$disk.FreeSpace)/1GB,1) } else { 'Fail' }
    } catch {
        try {
            $drive = (Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop).SystemDrive
            $disk  = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction Stop |
                     Where-Object { $_.DeviceID -eq $drive }
            if ($disk -and $disk.FreeSpace) { [math]::Round(([double]$disk.FreeSpace)/1GB,1) } else { 'Fail' }
        } catch { 'Fail' }
    }
}

# --- Last Patch Date & KB resolver (CU-only; KB + install) ---
Function Get-ServerPatchInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ComputerName)

    Write-Verbose "..running Get-ServerPatchInfo (CU-only)"
    $info = [pscustomobject]@{
        'Last Patch Date'     = $null
        'Latest KB Installed' = $null
        'Source'              = $null
        'Detail'              = $null
    }

    # Quick availability
    try {
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            $info.'Last Patch Date'     = 'Fail'
            $info.'Latest KB Installed' = 'Fail'
            $info.Source                = 'Offline'
            return $info
        }
    } catch {
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

    # 1) Windows Update COM History (CU-only, exclude Preview/Defender/MSRT)
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
                KB    = $kb
                Date  = [datetime]$cu.Date
                Title = $cu.Title
            }
        }

        $cuHist = & $InvokeSB $sbWU $ComputerName
        if ($cuHist -and $cuHist.KB) {
            $info.'Latest KB Installed' = $cuHist.KB
            $info.'Last Patch Date'     = $cuHist.Date
            $info.Source                = 'WUHistory(COM)'
            $info.Detail                = $cuHist.Title
            return $info
        }
    } catch {}

    # 2) Windows Update Operational Events (CU-only, exclude Preview/Defender/MSRT)
    try {
        $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'
            Id      = 19, 44
        } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending

        $cuEvent = $events |
            Where-Object { $_.Message -match '(?i)\bCumulative Update\b' } |
            Where-Object { $_.Message -notmatch '(?i)Preview|Defender|Security Intelligence|Malicious Software Removal Tool' } |
            Select-Object -First 1

        if ($cuEvent) {
            $kb = $null
            $kb = ((($cuEvent.Message -split '\s+') | Where-Object { $_ -match '(?i)^KB\d{7,}$' } | Select-Object -First 1))
            if (-not $kb) {
                $m = [regex]::Match($cuEvent.Message, '(?i)\bKB\d+\b')
                if ($m.Success) { $kb = $m.Value }
            }
            if ($kb) { $kb = $kb.ToUpper() }

            $info.'Latest KB Installed' = if ($kb) { $kb } else { 'Unknown' }
            $info.'Last Patch Date'     = [datetime]$cuEvent.TimeCreated
            $info.Source                = 'WUEvent'
            $info.Detail                = $cuEvent.Message
            return $info
        }
    } catch {}

    # 3) DISM: Installed LCU package (Package_for_RollupFix)
    try {
        $sbDISM = {
            Get-WindowsPackage -Online -ErrorAction Stop |
                Where-Object { $_.PackageState -eq 'Installed' -and $_.InstallTime -and $_.PackageName -match 'Package_for_RollupFix' } |
                Sort-Object InstallTime -Descending |
                Select-Object -First 1
        }
        $lcu = & $InvokeSB $sbDISM $ComputerName
        if ($lcu) {
            $kbFromPkg = (( $lcu.PackageName -split '[^A-Za-z0-9]' ) | Where-Object { $_ -match '^KB\d+$' } | Select-Object -First 1)
            if ($kbFromPkg) { $kbFromPkg = $kbFromPkg.ToUpper() }

            $info.'Last Patch Date'     = [datetime]$lcu.InstallTime
            $info.'Latest KB Installed' = if ($kbFromPkg) { $kbFromPkg } else { 'Unknown' }
            $info.Source                = 'DISM'
            $info.Detail                = $lcu.PackageName
            return $info
        }
    } catch {}

    # 4) No LCU found -> mark as Fail
    if (-not $info.'Last Patch Date')     { $info.'Last Patch Date'     = 'Fail' }
    if (-not $info.'Latest KB Installed') { $info.'Latest KB Installed' = 'Fail' }
    if (-not $info.Source)                { $info.Source                = 'None' }
    return $info
}

# ------------------------------
# Load servers (CSV first, then -ComputerName)
# ------------------------------
$Servers = @()
if (Test-Path $CsvPath) {
    Write-Host "Importing servers from CSV: $CsvPath" -ForegroundColor Yellow
    try {
        $Servers += (Import-Csv -Path $CsvPath).ServerName
    } catch {
        Write-Host "ERROR: Unable to parse CSV at $CsvPath" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "CSV not found at $CsvPath" -ForegroundColor Yellow
}

if ($ComputerName) {
    Write-Host "Adding servers from -ComputerName" -ForegroundColor Yellow
    $Servers += $ComputerName
}

$Servers = $Servers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
if (-not $Servers -or $Servers.Count -eq 0) {
    Write-Host "No servers to process. Provide D:\\servers.csv or -ComputerName." -ForegroundColor Red
    exit 1
}

# ------------------------------
# Scan loop
# ------------------------------
foreach ($srv in $Servers) {
    $short = $srv
    Write-Host ("..scanning server {0}" -f $short) -ForegroundColor Cyan
    $stopWatch = [system.diagnostics.stopwatch]::StartNew()

    $row = New-Object PSObject
    $row | Add-Member NoteProperty -Name Server -Value $short.ToUpper()
    $row | Add-Member NoteProperty -Name IPAddress -Value $null
    $row | Add-Member NoteProperty -Name "OS Version" -Value $null
    $row | Add-Member NoteProperty -Name "Last Boot Time" -Value $null
    $row | Add-Member NoteProperty -Name "System Drive Free (GB)" -Value $null
    $row | Add-Member NoteProperty -Name "Last Patch Date" -Value $null
    $row | Add-Member NoteProperty -Name "Latest KB Installed" -Value $null
    $row | Add-Member NoteProperty -Name "Patch Source" -Value $null      # tooltip
    $row | Add-Member NoteProperty -Name "Patch Detail" -Value $null      # tooltip
    $row | Add-Member NoteProperty -Name "Availability" -Value $null
    $row | Add-Member NoteProperty -Name "Processing Time" -Value $null

    $row.IPAddress                 = Get-ServerIP              -ComputerName $srv
    $row."OS Version"              = Get-ServerOSVersion       -ComputerName $srv
    $row."Last Boot Time"          = Get-ServerBootTime        -ComputerName $srv
    $row."System Drive Free (GB)"  = Get-ServerOSDriveFreeSpaceGB -ComputerName $srv
    $row.Availability              = Test-ServerPing           -ComputerName $srv

    $patch                         = Get-ServerPatchInfo       -ComputerName $srv
    $row."Last Patch Date"         = $patch."Last Patch Date"
    $row."Latest KB Installed"     = $patch."Latest KB Installed"
    $row."Patch Source"            = $patch.Source
    $row."Patch Detail"            = $patch.Detail

    $row."Processing Time"         = [int][math]::Round($stopWatch.Elapsed.TotalSeconds)
    $allTestedServers             += $row
}

# Optional sort
$allTestedServers = $allTestedServers | Sort-Object Server

# ------------------------------
# HTML helpers
# ------------------------------
Function ConvertTo-HtmlAttrSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $Text.Replace('&','&amp;').Replace('"','&quot;').Replace('<','&lt;').Replace('>','&gt;')
}

# ------------------------------
# Build HTML 
# ------------------------------
# Ensure output directory
$outDir = 'D:\Member-Health_Report'
if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
$reportFileName = Join-Path $outDir ('Member_Server_Health_Internal_{0}.html' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

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
 th.os, td.os {
  white-space: normal !important;
  word-break: normal !important;
  overflow-wrap: normal !important;
  hyphens: none !important;
  text-align: left;
  max-width: 220px;
 }
 th.patch, td.patch, th.kb, td.kb {
  white-space: nowrap;
  text-align: left;
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  padding: 4px 6px;
  line-height: 1.2;
 }
 th.ipaddress, td.ipaddress { width: auto; white-space: nowrap; text-align: left; }
 .table-wrapper { overflow-x: auto; }
</style>
<body>
<h1>Member Server Health Status Report</h1>
<h3>Generated: $reportTime<br> Developed by: Bhagawan Tapase</h3>
"@

# Header
$htmlTableHeader = @"
<div class=""table-wrapper"">
<table>
 <tr>
  <th class=""server-name"">Name</th>
  <th class=""ipaddress"">IP Address</th>
  <th class=""os"">OS</th>
  <th>Last Boot</th>
  <th>OS Free Space</th>
  <th class=""patch"">Last Patched</th>
  <th class=""kb"">KB Installed</th>
  <th>Availability</th>
  <th>Scan Time (sec)</th>
 </tr>
"@

$serverHealthHtmlTable = $htmlTableHeader

# Average processing time for badge coloring
$averageProcessingTime = ($allTestedServers | Measure-Object -Property 'Processing Time' -Average).Average

foreach ($reportline in $allTestedServers) {
    $htmlTableRow = '<tr>'

    # Identity
    $htmlTableRow += "<td class='server-name'>$($reportline.Server)</td>"
    $htmlTableRow += "<td class='ipaddress' style='white-space:nowrap;text-align:left;width:auto;'>$([string]$reportline.IPAddress)</td>"
    $htmlTableRow += "<td class='os'>$($reportline.'OS Version')</td>"

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
        $tdStyle   = "word-break:normal;text-align:left;max-width:160px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:#ffe2e2;color:#a20000;"
        $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
        $htmlTableRow += "<td class='fail' style='$tdStyle'><span style='$spanStyle'>Fail</span></td>"
    } else {
        $hoursSinceBoot = ((Get-Date) - $bootDt).TotalHours
        $bg = '#e9f9e5'; $fg = '#0a7f00'
        if ($hoursSinceBoot -le 24) { $bg = '#fff4cc'; $fg = '#8a6d00' }
        $datePart = $bootDt.ToString('MM/dd/yyyy')
        $timePart = $bootDt.ToString('hh:mm tt')
        $tdStyle   = "word-break:normal;text-align:left;max-width:160px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:$bg;color:$fg;"
        $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
        $htmlTableRow += "<td style='$tdStyle'><span style='$spanStyle'>$datePart<br />$timePart</span></td>"
    }

    # System drive free (GB)
    $freeStr       = $reportline.'System Drive Free (GB)'
    $tdStyleBase   = "word-break:normal;text-align:left;max-width:140px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;"
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

    # Last Patched cell with patch-age color
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
            $tdStyle   = "word-break:normal;text-align:left;max-width:160px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:$bg;color:$fg;"
            $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
            $htmlTableRow += "<td class='patch' style='$tdStyle'><span style='$spanStyle'>$datePart<br />$timePart</span></td>"
        } catch { $patchFail = $true }
    }
    if ($patchFail) {
        $tdStyle   = "word-break:normal;text-align:left;max-width:160px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:#ffe2e2;color:#a20000;"
        $spanStyle = "display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;white-space:normal;text-align:center;"
        $htmlTableRow += "<td class='patch' style='$tdStyle'><span style='$spanStyle'>Fail</span></td>"
        $ageDays = $null
    }

    # KB Installed cell (with tooltip of Source + Detail)
    $kbVal   = [string]$reportline.'Latest KB Installed'
    $src     = ConvertTo-HtmlAttrSafe -Text ([string]$reportline.'Patch Source')
    # truncate detail for attribute sanity
    $detailRaw = [string]$reportline.'Patch Detail'
    if ($detailRaw -and $detailRaw.Length -gt 512) { $detailRaw = $detailRaw.Substring(0,512) + '…' }
    $det     = ConvertTo-HtmlAttrSafe -Text $detailRaw
    
$title = ""
if ($src -or $det) {
    # $src and $det are already HTML-attribute-safe via ConvertTo-HtmlAttrSafe
    $title = "title=`"$src $det`""
}


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
    $tdStyle   = "white-space:nowrap;word-break:normal;text-align:left;max-width:160px;overflow:hidden;text-overflow:ellipsis;padding:4px 6px;line-height:1.2;background:$bg;color:$fg;"
    $spanStyle = "display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid currentColor;"
    $labelKb   = if ([string]::IsNullOrWhiteSpace($kbVal)) { 'Fail' } else { $kbVal }
    $htmlTableRow += "<td class='kb' style='$tdStyle'><span $title style='$spanStyle'>$labelKb</span></td>"

    # Availability (Ping)
    $htmlTableRow += (New-StatusCell -value ([string]$reportline.Availability) -cellClass 'status')

    # Processing Time
    try {
        $proc = [double]$reportline.'Processing Time'
        $htmlTableRow += (New-NumberBadgeCell -value $proc -averageThreshold $averageProcessingTime -labelFormat '{0}')
    }
    catch {
        $htmlTableRow += (New-NumberBadgeCell -value 0 -averageThreshold $averageProcessingTime -labelFormat '{0}')
    }

    $htmlTableRow += '</tr>'
    $serverHealthHtmlTable += $htmlTableRow
}
$serverHealthHtmlTable += '</table></div>'

# Tail
$htmlTail = @"
<hr>
<p style='font-size:08pt;'>
* Generated by PowerShell for Member Server health monitoring.<br>
* Cumulative Update logic: WU COM → WU Operational Events → DISM (LCU), excluding Preview/Defender/MSRT.<br>
</p>
</body>
</html>
"@

# Compose and write
$htmlReport = $htmlHead + $serverHealthHtmlTable + $htmlTail
$htmlReport | Out-File -FilePath $reportFileName -Encoding UTF8
Write-Host "Report written to: $reportFileName" -ForegroundColor Green

# ------------------------------
# EMAIL: Member Server Health Report (embed table + attach HTML)
# ------------------------------

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

 th.os, td.os {
  white-space: normal !important;
  word-break: normal !important;
  overflow-wrap: normal !important;
  hyphens: none !important;
  text-align: left;
  max-width: 220px;
 }

 th.server-name, td.server-name {
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
 
 th {
  background-color: #dddddd !important;
  color: #000000 !important;
  text-align: left !important;
  vertical-align: middle !important;
 }
</style>
</head>
<body>
<h2>Member Server Health Status Report</h2>
<p class="meta">
Generated: $reportTime (Local)<br/>
</p>
"@

$emailBodyFooter = @"
<p style="font-size:9pt;color:#000000;margin-top:10px;">
* Attached: $([IO.Path]::GetFileName($reportFileName))<br/>
* Generated by PowerShell for member server health monitoring.<br>
</p>
</body>
</html>
"@

$emailBodyHtml = $emailBodyHeader + $serverHealthHtmlTable + $emailBodyFooter

# Guard subject
if ([string]::IsNullOrWhiteSpace($subject)) {
    $subject = "Member Server Health Report"
}

# Build parameters using splatting 
$mailParams = @{
    From        = "$FromName <$FromEmail>"
    To          = $ToEmail
    Subject     = $subject
    Body        = $emailBodyHtml
    BodyAsHtml  = $true
    SmtpServer  = $SmtpServer
    Port        = $SmtpPort
    Attachments = $reportFileName
}

# Add CC only if populated
if (-not [string]::IsNullOrWhiteSpace($CcEmail)) {
    $mailParams.Cc = $CcEmail
}

Write-Host ("Email Subject: {0}" -f $mailParams.Subject) -ForegroundColor Yellow

try {
    Send-MailMessage @mailParams
    Write-Host "Email sent successfully." -ForegroundColor Green
}
catch {
    Write-Warning ("Failed to send email: {0}" -f $_.Exception.Message)
}
