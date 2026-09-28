# ============================
# Bulk create required /24 reverse zones
# from CIDR entries in CSV
# Supports: /22, /23, /24, /25, /27, /29
# Skips existing zones
# ============================

$CsvPath = "D:\zones.csv"
$LogPath = "C:\Temp\zone_creation_log.txt"

# Ensure log folder exists
$logFolder = Split-Path $LogPath -Parent
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

# Clear old log / create new log file
"" | Set-Content -Path $LogPath

# ----------------------------
# Function: Convert IP string to UInt32
# ----------------------------
function Convert-IPToUInt32 {
    param([string]$IpAddress)

    $bytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    [array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

# ----------------------------
# Function: Convert UInt32 to IP string
# ----------------------------
function Convert-UInt32ToIP {
    param([UInt32]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    [array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

# ----------------------------
# Function: Get all required /24 networks for a CIDR
# Example:
#   10.115.4.0/23 -> 10.115.4.0/24, 10.115.5.0/24
#   10.115.8.0/25 -> 10.115.8.0/24
#   10.115.6.0/22 -> 10.115.6.0/24 ... 10.115.9.0/24
# ----------------------------
function Get-Required24Networks {
    param([string]$Cidr)

    if ($Cidr -notmatch '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        throw "Invalid CIDR format: $Cidr"
    }

    $parts  = $Cidr.Split('/')
    $ip     = $parts[0]
    $prefix = [int]$parts[1]

    if ($prefix -lt 0 -or $prefix -gt 32) {
        throw "Invalid prefix length in: $Cidr"
    }

    $ipInt = [uint64](Convert-IPToUInt32 $ip)

    # Safe 32-bit all-ones mask as UInt64
    $fullMask = [uint64]4294967295

    # Build subnet mask
    if ($prefix -eq 0) {
        $mask = [uint64]0
    }
    else {
        $mask = (($fullMask -shl (32 - $prefix)) -band $fullMask)
    }

    $networkInt   = $ipInt -band $mask
    $wildcardMask = $fullMask -bxor $mask
    $broadcastInt = $networkInt -bor $wildcardMask

    # Find the /24 boundaries covered by this CIDR
    $start24 = $networkInt -band [uint64]4294967040   # 0xFFFFFF00
    $end24   = $broadcastInt -band [uint64]4294967040 # 0xFFFFFF00

    $result = @()
    for ($current = $start24; $current -le $end24; $current += 256) {
        $result += "$(Convert-UInt32ToIP ([uint32]$current))/24"
    }

    return $result
}

# ----------------------------
# Function: Build reverse zone name from /24
# Example: 10.115.4.0/24 -> 4.115.10.in-addr.arpa
# ----------------------------
function Get-ReverseZoneNameFrom24 {
    param([string]$Network24)

    $ip = $Network24.Split('/')[0]
    $octets = $ip.Split('.')
    return "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
}

# ----------------------------
# Main
# ----------------------------
try {
    $rows = Import-Csv $CsvPath -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Unable to read CSV file $CsvPath : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if (-not $rows) {
    Write-Host "ERROR: CSV file is empty or has no readable rows." -ForegroundColor Red
    exit 1
}

# Collect all unique /24 networks required by the CSV input
$all24Networks = @()

foreach ($row in $rows) {

    if (-not $row.PSObject.Properties.Name.Contains('NetworkID')) {
        $msg = "INVALID CSV: Missing 'NetworkID' column."
        Write-Host $msg -ForegroundColor Red
        Add-Content -Path $LogPath -Value $msg
        exit 1
    }

    $cidr = $row.NetworkID.Trim()

    if ([string]::IsNullOrWhiteSpace($cidr)) {
        continue
    }

    try {
        $required24s = Get-Required24Networks -Cidr $cidr
        $all24Networks += $required24s
    }
    catch {
        $msg = "INVALID ENTRY: $cidr | $($_.Exception.Message)"
        Write-Host $msg -ForegroundColor Red
        Add-Content -Path $LogPath -Value $msg
    }
}

$unique24Networks = $all24Networks | Sort-Object -Unique

foreach ($net24 in $unique24Networks) {
    $zoneName = Get-ReverseZoneNameFrom24 -Network24 $net24

    try {
        $existing = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue

        if ($existing) {
            $msg = "SKIP: $zoneName already exists"
            Write-Host $msg -ForegroundColor Yellow
            Add-Content -Path $LogPath -Value $msg
            continue
        }

        Add-DnsServerPrimaryZone `
            -NetworkId $net24 `
            -ReplicationScope Domain `
            -DynamicUpdate Secure `
            -ErrorAction Stop

        $msg = "SUCCESS: Created $zoneName from $net24"
        Write-Host $msg -ForegroundColor Green
        Add-Content -Path $LogPath -Value $msg
    }
    catch {
        $msg = "ERROR: $zoneName | $($_.Exception.Message)"
        Write-Host $msg -ForegroundColor Red
        Add-Content -Path $LogPath -Value $msg
    }
}

Write-Host "Completed. Log file: $LogPath" -ForegroundColor Cyan
