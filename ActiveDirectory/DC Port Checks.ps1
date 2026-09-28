
<#
.SYNOPSIS
  Traceroute (max 4 hops) + AD/DC port checks to a specified Domain Controller.
  Outputs CSVs to C:\Temp\.
#>

# ======= EDIT THIS VALUE =======
$DCName    = "FQDN"   # <-- Set your DC FQDN/hostname here
# =================================

# ---- Settings ----
$MaxHops    = 4          # TTL limit for traceroute
$ResolveDNS = $false     # set $true to include reverse DNS names (removes -d)
$OutDir     = "C:\Temp"  # output folder for CSVs
$TimeoutMs  = 3000       # placeholder for future per-port timeouts

# Ensure output directory exists
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

# Timestamp & output files
$ts         = (Get-Date).ToString('yyyyMMdd_HHmmss')
$TraceCsv   = Join-Path $OutDir "Traceroute_$($DCName)_$ts.csv"
$TraceRaw   = Join-Path $OutDir "Traceroute_RAW_$($DCName)_$ts.txt"
$PortsCsv   = Join-Path $OutDir "DCPorts_$($DCName)_$ts.csv"

# ---- Port definitions (client ↔ DC / DC ↔ DC) ----
$Ports = @(
    @{Service='DNS';                 Port=53;     Proto='TCP,UDP';   Notes='Name resolution';                Critical=$true}
    @{Service='Kerberos';            Port=88;     Proto='TCP,UDP';   Notes='Authentication';                 Critical=$true}
    @{Service='W32Time/NTP';         Port=123;    Proto='UDP';       Notes='Time sync (skew breaks auth)';   Critical=$true}
    @{Service='RPC Endpoint Mapper'; Port=135;    Proto='TCP';       Notes='RPC bootstrap';                  Critical=$true}
    @{Service='LDAP';                Port=389;    Proto='TCP,UDP';   Notes='Directory queries';              Critical=$true}
    @{Service='LDAPS';               Port=636;    Proto='TCP';       Notes='LDAP over SSL/TLS';              Critical=$false}
    @{Service='SMB';                 Port=445;    Proto='TCP';       Notes='Auth, GP, SYSVOL/NETLOGON';      Critical=$true}
    @{Service='Global Catalog';      Port=3268;   Proto='TCP';       Notes='GC LDAP';                        Critical=$true}
    @{Service='Global Catalog SSL';  Port=3269;   Proto='TCP';       Notes='GC LDAP over SSL/TLS';           Critical=$false}
    @{Service='AD Web Services';     Port=9389;   Proto='TCP';       Notes='ADWS (AD Admin Center/AD module)';Critical=$false}
    @{Service='Dynamic RPC';         Port='49152-65535'; Proto='TCP';Notes='RPC high ports (DC/client comm)';Critical=$true}
)

# ---- Helpers ----

function Test-TcpPort {
    param(
        [string] $ComputerName,
        [int]    $Port,
        [int]    $TimeoutMs = 3000
    )
    try {
        $res = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningAction SilentlyContinue -InformationLevel Quiet
        return [bool]$res
    } catch { return $false }
}

function Test-UdpPort {
    param(
        [string] $ComputerName,
        [int]    $Port,
        [int]    $TimeoutMs = 3000
    )
    # UDP is connectionless; do service-aware probes where feasible
    switch ($Port) {
        53  { try { $null = Resolve-DnsName -Name $ComputerName -ErrorAction Stop; return $true } catch { return $false } }
        88  { return $null }   # Kerberos UDP indeterminate via generic probe
        123 { try { $null = w32tm /stripchart /computer:$ComputerName /samples:1 /dataonly 2>$null; return ($LASTEXITCODE -eq 0) } catch { return $false } }
        389 { return $null }   # LDAP UDP: rely on TCP primarily
        default { return $null }
    }
}

function Test-RpcHighPorts {
    param(
        [string] $ComputerName,
        [int[]]  $SamplePorts = @(49160, 49200, 49300, 49400, 49500, 50000, 55000, 60000, 65000),
        [int]    $TimeoutMs = 3000
    )
    foreach ($p in $SamplePorts) {
        $ok = Test-TcpPort -ComputerName $ComputerName -Port $p -TimeoutMs $TimeoutMs
        $statusText = if ($ok) { 'OPEN' } else { 'CLOSED' }
        $color      = if ($ok) { 'Green' } else { 'Yellow' }

        Write-Host ("{0,-16} {1,6}/{2,-4} -> {3}" -f 'Dynamic RPC',$p,'TCP',$statusText) -ForegroundColor $color

        [PSCustomObject]@{
            ComputerName = $ComputerName
            Service      = 'Dynamic RPC'
            Port         = $p
            Protocol     = 'TCP'
            TestPassed   = $ok
            Critical     = $true
            Notes        = 'Sampled high port in 49152–65535'
        }
    }
}

function Invoke-TracerouteLimited {
    param(
        [string] $Target,
        [int]    $MaxHops = 4,
        [bool]   $ResolveDNS = $false
    )
    Write-Host "Running traceroute (max $MaxHops hops) to $Target ..." -ForegroundColor Cyan
    $args = @('-h', $MaxHops)
    if (-not $ResolveDNS) { $args += '-d' }
    $args += $Target

    $raw = & tracert.exe @args 2>&1
    if ($raw) { $raw | Out-File -FilePath $TraceRaw -Encoding UTF8 -Force }

    $results = New-Object System.Collections.Generic.List[object]
    if (-not $raw) { return $results }

    foreach ($line in $raw) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match 'Tracing route|over a maximum|Trace complete') { continue }

        $l = ($line -replace '\s{2,}', ' ').Trim()

        # Handle timeouts: "n *  *  *  Request timed out."
        if ($l -match '^\d+\s+\*\s+\*\s+\*\s+Request timed out\.?$') {
            $hop = ($l -split ' ')[0]
            $results.Add([PSCustomObject]@{
                Hop    = [int]$hop
                RTT1   = $null
                RTT2   = $null
                RTT3   = $null
                IP     = $null
                Host   = $null
                Status = 'Timeout'
            })
            continue
        }

        # Standard hop (IPv4 or IPv6), tolerate "<1 ms" RTTs
        $rttPat = '(?<r1><?\d+)\s*ms\s+(?<r2><?\d+)\s*ms\s+(?<r3><?\d+)\s*ms'
        $ipPat  = '(?<ip>(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+))'
        $m = [regex]::Match($l, "^(?<hop>\d+)\s+$rttPat\s+$ipPat$")
        if ($m.Success) {
            $results.Add([PSCustomObject]@{
                Hop    = [int]$m.Groups['hop'].Value
                RTT1   = $m.Groups['r1'].Value
                RTT2   = $m.Groups['r2'].Value
                RTT3   = $m.Groups['r3'].Value
                IP     = $m.Groups['ip'].Value
                Host   = $null
                Status = 'OK'
            })
            continue
        }

        # Fallback for lines including hostnames (when ResolveDNS=$true)
        $m2 = [regex]::Match($l, "^(?<hop>\d+)\s+$rttPat\s+(?<hostip>.+)$")
        if ($m2.Success) {
            $hostip = $m2.Groups['hostip'].Value
            $ipMatch = [regex]::Match($hostip, '(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]+)')
            $ip = if ($ipMatch.Success) { $ipMatch.Value } else { $null }
            $results.Add([PSCustomObject]@{
                Hop    = [int]$m2.Groups['hop'].Value
                RTT1   = $m2.Groups['r1'].Value
                RTT2   = $m2.Groups['r2'].Value
                RTT3   = $m2.Groups['r3'].Value
                IP     = $ip
                Host   = $hostip
                Status = 'OK'
            })
            continue
        }
    }

    return $results
}

function Invoke-TraceRouteFallback {
    param([string] $Target)
    try {
        $tnc = Test-NetConnection -ComputerName $Target -TraceRoute -WarningAction SilentlyContinue
        $hops = $tnc.TraceRoute
        $i = 0
        foreach ($h in $hops) {
            $i++
            [PSCustomObject]@{
                Hop    = $i
                RTT1   = $null
                RTT2   = $null
                RTT3   = $null
                IP     = $null
                Host   = $h
                Status = 'OK'
            }
        }
    } catch { @() }
}

# ---- Run traceroute (TTL = 4) ----
$traceResults = Invoke-TracerouteLimited -Target $DCName -MaxHops $MaxHops -ResolveDNS:$ResolveDNS
if ($traceResults.Count -eq 0) {
    Write-Warning "Traceroute produced no parseable results. Raw output saved to: $TraceRaw"
    $traceResults = Invoke-TraceRouteFallback -Target $DCName
}
if ($traceResults.Count -gt 0) {
    $traceResults | Sort-Object Hop | Export-Csv -Path $TraceCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Saved traceroute CSV: $TraceCsv" -ForegroundColor Green
    $traceResults | Sort-Object Hop | Format-Table Hop, RTT1, RTT2, RTT3, IP, Host, Status -AutoSize
}

# ---- Run port checks ----
Write-Host "`nChecking ports on $DCName ..." -ForegroundColor Cyan
$portReport = New-Object System.Collections.Generic.List[object]

foreach ($item in $Ports) {
    $service  = $item.Service
    $port     = $item.Port
    $proto    = $item.Proto
    $critical = $item.Critical
    $notes    = $item.Notes

    if ($port -is [string] -and $port -like '*-*') {
        # Dynamic RPC range – sample representative ports
        $rpcSamples = Test-RpcHighPorts -ComputerName $DCName -TimeoutMs $TimeoutMs
        foreach ($r in $rpcSamples) { $portReport.Add($r) }
        continue
    }

    # ----- TCP test (safe cast) -----
    $portInt = [int]$port
    if ($proto -match 'TCP') {
        $tcpPassed  = Test-TcpPort -ComputerName $DCName -Port $portInt -TimeoutMs $TimeoutMs
        $statusText = if ($tcpPassed) { 'OPEN' } else { 'CLOSED' }
        $color      = if ($tcpPassed) { 'Green' } else { 'Yellow' }

        Write-Host ("{0,-16} {1,6}/{2,-4} -> {3}" -f $service,$portInt,'TCP',$statusText) -ForegroundColor $color

        $portReport.Add([PSCustomObject]@{
            ComputerName = $DCName
            Service      = $service
            Port         = $portInt
            Protocol     = 'TCP'
            TestPassed   = $tcpPassed
            Critical     = $critical
            Notes        = $notes
        })
    }

    # ----- UDP test (best-effort) -----
    if ($proto -match 'UDP') {
        $udpPassed  = Test-UdpPort -ComputerName $DCName -Port $portInt -TimeoutMs $TimeoutMs
        $statusText = if ($udpPassed -eq $null) { 'N/A' } elseif ($udpPassed) { 'OPEN' } else { 'CLOSED' }
        $color      = if ($udpPassed) { 'Green' } elseif ($udpPassed -eq $null) { 'Gray' } else { 'Yellow' }

        Write-Host ("{0,-16} {1,6}/{2,-4} -> {3}" -f $service,$portInt,'UDP',$statusText) -ForegroundColor $color

        $portReport.Add([PSCustomObject]@{
            ComputerName = $DCName
            Service      = $service
            Port         = $portInt
            Protocol     = 'UDP'
            TestPassed   = $udpPassed
            Critical     = $critical
            Notes        = if ($udpPassed -eq $null) { "UDP check indeterminate (use service-specific tests)" } else { $notes }
        })
    }
}

# Save ports CSV
$portReport | Export-Csv -Path $PortsCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nSaved ports CSV: $PortsCsv" -ForegroundColor Green

Write-Host "`nLegend: OPEN = reachable, CLOSED = not reachable, N/A = UDP indeterminate." -ForegroundColor DarkGray
Write-Host "Note: Dynamic RPC uses random high TCP ports in 49152–65535; sampled subset is shown." -ForegroundColor DarkGray
Write-Host "Done." -ForegroundColor DarkGray
