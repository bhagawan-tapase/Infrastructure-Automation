# ============================
# SAFE PTR AUTO CREATION SCRIPT
# ============================

# CONFIG
$DnsServer   = $null                     # or "Hostname"
$ForwardZone = "YourDomainFQDN"

# ----------------------------
# Logging
# ----------------------------
function Write-Log {
    param($msg,$color="White")
    Write-Host $msg -ForegroundColor $color
}

Write-Log "===== PTR SAFE UPDATE START =====" "Cyan"

if ($DnsServer) {
    Write-Log "DNS Server: $DnsServer" "Cyan"
} else {
    Write-Log "DNS Server: LOCAL" "Cyan"
}

# ----------------------------
# Get all A records
# ----------------------------
if ($DnsServer) {
    $aRecords = Get-DnsServerResourceRecord `
        -ComputerName $DnsServer `
        -ZoneName $ForwardZone `
        -RRType A
} else {
    $aRecords = Get-DnsServerResourceRecord `
        -ZoneName $ForwardZone `
        -RRType A
}

# ----------------------------
# Process records
# ----------------------------
foreach ($rec in $aRecords) {

    try {
        # ✅ FIX: do NOT use $host (reserved variable)
        $hostname = $rec.HostName
        $fqdn     = "$hostname.$ForwardZone"
        $ip       = $rec.RecordData.IPv4Address.IPAddressToString

        # Build reverse zone
        $ipParts  = $ip.Split('.')
        $zoneName = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
        $ptrName  = $ipParts[3]

        # ----------------------------
        # Check reverse zone exists
        # ----------------------------
        if ($DnsServer) {
            $zone = Get-DnsServerZone -ComputerName $DnsServer -Name $zoneName -ErrorAction SilentlyContinue
        } else {
            $zone = Get-DnsServerZone -Name $zoneName -ErrorAction SilentlyContinue
        }

        if (-not $zone) {
            Write-Log "SKIP ZONE: $zoneName not found (IP: $ip)" "Yellow"
            continue
        }

        # ----------------------------
        # Check existing PTR
        # ----------------------------
        if ($DnsServer) {
            $ptr = Get-DnsServerResourceRecord `
                -ComputerName $DnsServer `
                -ZoneName $zoneName `
                -Name $ptrName `
                -RRType PTR `
                -ErrorAction SilentlyContinue
        } else {
            $ptr = Get-DnsServerResourceRecord `
                -ZoneName $zoneName `
                -Name $ptrName `
                -RRType PTR `
                -ErrorAction SilentlyContinue
        }

        if ($ptr) {
            $existingFqdn = $ptr.RecordData.PtrDomainName.TrimEnd(".")

            if ($existingFqdn -ieq $fqdn) {
                Write-Log "SKIP OK: PTR correct for $ip -> $fqdn" "Green"
            }
            else {
                Write-Log "SKIP WRONG: PTR exists ($existingFqdn) for IP $ip" "Yellow"
            }

            continue
        }

        # ----------------------------
        # Create missing PTR
        # ----------------------------
        if ($DnsServer) {
            Add-DnsServerResourceRecordPtr `
                -ComputerName $DnsServer `
                -ZoneName $zoneName `
                -Name $ptrName `
                -PtrDomainName $fqdn `
                -ErrorAction Stop
        } else {
            Add-DnsServerResourceRecordPtr `
                -ZoneName $zoneName `
                -Name $ptrName `
                -PtrDomainName $fqdn `
                -ErrorAction Stop
        }

        Write-Log "CREATED: PTR for $ip -> $fqdn" "Cyan"
    }
    catch {
        Write-Log "ERROR: $($rec.HostName) | $($_.Exception.Message)" "Red"
    }
}

Write-Log "===== PTR SAFE UPDATE COMPLETE =====" "Cyan"
