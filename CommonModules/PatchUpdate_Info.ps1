
# ==========================
# TARGET MACHINE(S) - EDIT ME
# ==========================
$TargetMachines = @($env:COMPUTERNAME)      # current server
 #$TargetMachines = @('XYZ','ABC')

# Optional credentials for remote targets (uncomment if needed)
# $Credential = Get-Credential

# ==========================
# CONFIG - adjust as needed
# ==========================
$TopUpdates    = 1     # last N cumulative updates to show
$WindowHours   = 6     # primary correlation window
$FallbackHours = 24    # automatic wider window if nothing found
$HistoryCount  = 200   # scan this many Windows Update history entries on target
$MaxEvents     = 3000  # scan this many System events on target

# ================
# Helper (shared): shape rows for the table
# ================
function New-CUDisplayRows {
    param(
        [Parameter(Mandatory)][object[]]$Rows
    )
    foreach ($row in $Rows) {
        $firstLine = $null
        if ($row.InitiatorMessage) {
            $firstLine = ($row.InitiatorMessage -split "(`r`n|`n)")[0]
        }

        [PSCustomObject]@{
            Computer   = $row.ComputerName
            KB         = $row.KB
            Patch_Installed = $row.InstalledLocal
            Rebooted    = $row.RebootLocal
            Provider   = $row.InitiatorProvider
            Message    = $firstLine
        }
    }
}

# ==========================
# LOCAL CORE (no remoting)
# ==========================
function Get-CUInstalledAndRebootLocal {
    param(
        [int]$TopUpdates,
        [int]$WindowHours,
        [int]$FallbackHours,
        [int]$HistoryCount,
        [int]$MaxEvents
    )

    function Get-KBFromTitle([string]$Title) {
        if ([string]::IsNullOrWhiteSpace($Title)) { return $null }
        $m = [regex]::Matches($Title, '(KB\d{6,8})', 'IgnoreCase')
        if ($m.Count -gt 0) { return ($m.Value | Select-Object -Unique) }
        return $null
    }

    # ---- Windows Update History (COM) ----
    $Session  = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    $entries  = $Searcher.QueryHistory(0, $HistoryCount)

    $ResultCodeMap = @{
        0='NotStarted';1='InProgress';2='Succeeded';3='SucceededWithErrors';4='Failed';5='Aborted'
    }

    # Filter to "Cumulative Update" entries, newest first, take TopUpdates
    $cumulativeUpdates =
        
$entries | Where-Object {
    $_.Title -match 'KB\d{6,8}' -and (
        $_.Title -match 'Cumulative' -or       # English
        $_.Title -match 'Samlet' -or           # Danish / Scandinavian
        $_.Title -match 'Acumulativa' -or      # Spanish / Portuguese
        $_.Title -match 'Cumulate' -or         # German ("kumulative")
        $_.Title -match 'Mise à jour' -or      # French
        $_.Title -match '累積'                 # Japanese/Chinese (cumulative)
    )
} |
        ForEach-Object {
            $kbArr = Get-KBFromTitle $_.Title
            [PSCustomObject]@{
                InstalledLocal = [datetime]$_.Date
                KB             = $kbArr -join ', '
                Result         = $ResultCodeMap[[int]$_.ResultCode]
                Title          = $_.Title
            }
        } | Sort-Object InstalledLocal -Descending |
          Select-Object -First $TopUpdates

    if (-not $cumulativeUpdates -or $cumulativeUpdates.Count -eq 0) {
        return ,([PSCustomObject]@{
            ComputerName       = $env:COMPUTERNAME
            KB                 = '—'
            InstalledLocal     = $null
            RebootLocal        = $null
            InitiatorProvider  = $null
            InitiatorMessage   = "No cumulative updates found in last $HistoryCount entries."
        })
    }

    # ---- Events needed: 1074 (initiator), 13 (shutdown start), 6006 (EventLog stopped) ----
    $ids = 1074,13,6006
    $sysEvents =
        Get-WinEvent -FilterHashtable @{ LogName='System'; Id=$ids } -MaxEvents $MaxEvents |
        Sort-Object TimeCreated

    $out = @()
    foreach ($lcu in $cumulativeUpdates) {

        # A small helper that tries to resolve initiator and reboot within a given window
        function Resolve-InitiatorAndReboot([datetime]$center, [int]$hours) {
            $start = $center.AddHours(-$hours)
            $end   = $center.AddHours($hours)

            $initiator = $sysEvents | Where-Object {
                $_.TimeCreated -ge $start -and $_.TimeCreated -le $end -and $_.Id -eq 1074
            } | Select-Object -Last 1

            $shutdownCandidates = $sysEvents | Where-Object {
                $_.TimeCreated -ge $start -and $_.TimeCreated -le $end -and $_.Id -in 13,6006
            }

            $shutdown =
                if ($initiator) {
                    # first 13/6006 after the initiator
                    $shutdownCandidates | Where-Object { $_.TimeCreated -ge $initiator.TimeCreated } | Select-Object -First 1
                } else {
                    # nearest 13/6006 to the center
                    $shutdownCandidates | Sort-Object @{Expression={ [math]::Abs( ($_.TimeCreated - $center).TotalSeconds ) }} | Select-Object -First 1
                }

            $rebootLocal   = if ($shutdown)  { $shutdown.TimeCreated } else { $null }
            $providerLocal = if ($initiator) { $initiator.ProviderName } else { $null }
            $messageLocal  = if ($initiator) { $initiator.Message } else { $null }

            return [PSCustomObject]@{
                RebootLocal      = $rebootLocal
                InitiatorProvider= $providerLocal
                InitiatorMessage = $messageLocal
            }
        }

        # Try primary window; if empty, try wider fallback window
        $resolved = Resolve-InitiatorAndReboot -center $lcu.InstalledLocal -hours $WindowHours
        if (-not $resolved.RebootLocal -and -not $resolved.InitiatorProvider) {
            $resolved = Resolve-InitiatorAndReboot -center $lcu.InstalledLocal -hours $FallbackHours
            if (-not $resolved.RebootLocal -and -not $resolved.InitiatorProvider) {
                # still nothing; put a friendly note
                $resolved.InitiatorMessage = "No Event ID 1074 initiator found within ±$WindowHours h (tried ±$FallbackHours h)."
            }
        }

        $out += [PSCustomObject]@{
            ComputerName       = $env:COMPUTERNAME
            KB                 = $lcu.KB
            InstalledLocal     = $lcu.InstalledLocal
            RebootLocal        = $resolved.RebootLocal
            InitiatorProvider  = $resolved.InitiatorProvider
            InitiatorMessage   = $resolved.InitiatorMessage
        }
    }

    return $out
}

# ==============================================
# REMOTE SCRIPT (self-contained for Invoke-Command)
# ==============================================
$RemoteScript = {
    param($TopUpdates, $WindowHours, $FallbackHours, $HistoryCount, $MaxEvents)

    function Get-KBFromTitle([string]$Title) {
        if ([string]::IsNullOrWhiteSpace($Title)) { return $null }
        $m = [regex]::Matches($Title, '(KB\d{6,8})', 'IgnoreCase')
        if ($m.Count -gt 0) { return ($m.Value | Select-Object -Unique) }
        return $null
    }

    # ---- Windows Update History (COM) ----
    $Session  = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    $entries  = $Searcher.QueryHistory(0, $HistoryCount)

    $ResultCodeMap = @{
        0='NotStarted';1='InProgress';2='Succeeded';3='SucceededWithErrors';4='Failed';5='Aborted'
    }

    $cumulativeUpdates =
        $entries | Where-Object { $_.Title -match 'Cumulative Update' } |
        ForEach-Object {
            $kbArr = Get-KBFromTitle $_.Title
            [PSCustomObject]@{
                InstalledLocal = [datetime]$_.Date
                KB             = $kbArr -join ', '
                Result         = $ResultCodeMap[[int]$_.ResultCode]
                Title          = $_.Title
            }
        } | Sort-Object InstalledLocal -Descending |
          Select-Object -First $TopUpdates

    if (-not $cumulativeUpdates -or $cumulativeUpdates.Count -eq 0) {
        return [PSCustomObject]@{
            ComputerName       = $env:COMPUTERNAME
            KB                 = '—'
            InstalledLocal     = $null
            RebootLocal        = $null
            InitiatorProvider  = $null
            InitiatorMessage   = "No cumulative updates found in last $HistoryCount entries."
        }
    }

    # ---- Events needed ----
    $ids = 1074,13,6006
    $sysEvents =
        Get-WinEvent -FilterHashtable @{ LogName='System'; Id=$ids } -MaxEvents $MaxEvents |
        Sort-Object TimeCreated

    function Resolve-InitiatorAndReboot([datetime]$center, [int]$hours) {
        $start = $center.AddHours(-$hours)
        $end   = $center.AddHours($hours)

        $initiator = $sysEvents | Where-Object {
            $_.TimeCreated -ge $start -and $_.TimeCreated -le $end -and $_.Id -eq 1074
        } | Select-Object -Last 1

        $shutdownCandidates = $sysEvents | Where-Object {
            $_.TimeCreated -ge $start -and $_.TimeCreated -le $end -and $_.Id -in 13,6006
        }

        $shutdown =
            if ($initiator) {
                $shutdownCandidates | Where-Object { $_.TimeCreated -ge $initiator.TimeCreated } | Select-Object -First 1
            } else {
                $shutdownCandidates | Sort-Object @{Expression={ [math]::Abs( ($_.TimeCreated - $center).TotalSeconds ) }} | Select-Object -First 1
            }

        $rebootLocal   = if ($shutdown)  { $shutdown.TimeCreated } else { $null }
        $providerLocal = if ($initiator) { $initiator.ProviderName } else { $null }
        $messageLocal  = if ($initiator) { $initiator.Message } else { $null }

        return [PSCustomObject]@{
            RebootLocal      = $rebootLocal
            InitiatorProvider= $providerLocal
            InitiatorMessage = $messageLocal
        }
    }

    $out = @()
    foreach ($lcu in $cumulativeUpdates) {
        $resolved = Resolve-InitiatorAndReboot -center $lcu.InstalledLocal -hours $WindowHours
        if (-not $resolved.RebootLocal -and -not $resolved.InitiatorProvider) {
            $resolved = Resolve-InitiatorAndReboot -center $lcu.InstalledLocal -hours $FallbackHours
            if (-not $resolved.RebootLocal -and -not $resolved.InitiatorProvider) {
                $resolved.InitiatorMessage = "No Event ID 1074 initiator found within ±$WindowHours h (tried ±$FallbackHours h)."
            }
        }

        $out += [PSCustomObject]@{
            ComputerName       = $env:COMPUTERNAME
            KB                 = $lcu.KB
            InstalledLocal     = $lcu.InstalledLocal
            RebootLocal        = $resolved.RebootLocal
            InitiatorProvider  = $resolved.InitiatorProvider
            InitiatorMessage   = $resolved.InitiatorMessage
        }
    }

    return $out
}

# ==========================================
# RUN LOCALLY OR REMOTELY & PRINT AS TABLE
# ==========================================
foreach ($cn in $TargetMachines) {
    try {
        if ($cn -eq $env:COMPUTERNAME -or $cn -eq 'localhost') {
            $rows = Get-CUInstalledAndRebootLocal -TopUpdates $TopUpdates -WindowHours $WindowHours -FallbackHours $FallbackHours -HistoryCount $HistoryCount -MaxEvents $MaxEvents
        } else {
            $invokeParams = @{
                ComputerName = $cn
                ScriptBlock  = $RemoteScript
                ArgumentList = @($TopUpdates, $WindowHours, $FallbackHours, $HistoryCount, $MaxEvents)
            }
            if ($PSBoundParameters.ContainsKey('Credential') -and $Credential) {
                $invokeParams.Credential = $Credential
            }
            $rows = Invoke-Command @invokeParams
        }

        $tableRows = New-CUDisplayRows -Rows $rows

        Write-Host "`n================== $cn :: Cumulative Updates (Last $TopUpdates) ==================" -ForegroundColor Cyan
        $tableRows |
            Format-Table Computer, KB, Patch_Installed, Rebooted, Provider, Message -AutoSize -Wrap |
            Out-Host
    }
    catch {
        Write-Host "`n[$cn] ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}
