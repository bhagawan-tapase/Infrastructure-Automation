
# =========================
# Disable policy with accurate logging-by-diff
# - Add to Disabled Users (direct or recognize primary)
# - Set PrimaryGroupID to Disabled Users RID
# - Remove all other direct group memberships
# - Disable account if enabled
# =========================

# --- Constants (edit to your environment) ---
$disabledGroup   = "CN=Disabled Users,OU=Groups,OU=Test OU,DC=Domain,DC=com"
$targetOU        = "OU=Admins,OU=Test OU,DC=Domain,DC=com"
$currentDate     = Get-Date -Format "yyyy-MM-dd"
$csvFilePath     = "D:\Report_Disabled_Users\Disabled_users_bulk_report_$currentDate.csv"

function Test-InOU {
    param(
        [Parameter(Mandatory=$true)][string]$DistinguishedName,
        [Parameter(Mandatory=$true)][string]$OuDistinguishedName
    )
    return $DistinguishedName -like "*,$OuDistinguishedName" -or $DistinguishedName -eq $OuDistinguishedName
}

# Resolve Disabled Users group (DN + RID)
try {
    $disabledGroupObj = Get-ADGroup -Identity $disabledGroup -ErrorAction Stop
    $disabledGroupDN  = $disabledGroupObj.DistinguishedName
    $sidParts         = $disabledGroupObj.SID.Value.Split('-')
    $disabledGroupRID = [int]$sidParts[$sidParts.Length - 1]
} catch {
    Write-Error "Failed to resolve Disabled Users group: $($disabledGroup). $($_.Exception.Message)"
    exit 1
}

# Ensure export directory exists
$dir = Split-Path -Parent $csvFilePath
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

# Get users in target OU
try {
    $users = Get-ADUser -SearchBase $targetOU -SearchScope Subtree -Filter * `
             -Properties MemberOf, DistinguishedName, sAMAccountName, Enabled, PrimaryGroupID -ErrorAction Stop
} catch {
    Write-Error "Failed to enumerate users from Target OU ($targetOU): $($_.Exception.Message)"
    exit 1
}

$reportData = @()

foreach ($u in $users) {
    $sam = $u.sAMAccountName

    # Re-fetch fresh
    try {
        $user = Get-ADUser -Identity $sam -Properties MemberOf, DistinguishedName, Enabled, PrimaryGroupID -ErrorAction Stop
    } catch {
        $reportData += [PSCustomObject]@{
            sAMAccountName = $sam
            Action         = "Error: failed to re-fetch user. $($_.Exception.Message)"
            Status         = "Error"
        }
        continue
    }

    # OU guardrail
    if (-not (Test-InOU -DistinguishedName $user.DistinguishedName -OuDistinguishedName $targetOU)) {
        $reportData += [PSCustomObject]@{
            sAMAccountName = $sam
            Action         = "Skipped: user not currently in the target OU."
            Status         = "Skipped"
        }
        continue
    }

    # --- Capture BEFORE state (direct groups only) ---
    $beforeEnabled  = $user.Enabled
    $beforePGID     = $user.PrimaryGroupID
    $beforeGroups   = @()
    if ($user.MemberOf) { $beforeGroups = @($user.MemberOf) }

    # --- Desired end-state actions ---
    $addErr = $null
    $setPGErr = $null
    $disableErr = $null
    $cleanupErr = $null
    $removeErrs = $null

    # A) Ensure Disabled Users membership (consider primary counts as membership)
    $hasDisabledUsersDirect = $beforeGroups -contains $disabledGroupDN
    $isPrimaryDisabledUsers = ($beforePGID -eq $disabledGroupRID)

    if (-not $hasDisabledUsersDirect -and -not $isPrimaryDisabledUsers) {
        try {
            Add-ADGroupMember -Identity $disabledGroupDN -Members $user -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -notmatch 'already a member') {
                $addErr = $_.Exception.Message
            }
        }
    }

    # B) Set PrimaryGroupID to Disabled Users RID (ensure membership first)
    try {
        $userRefresh = Get-ADUser -Identity $sam -Properties MemberOf, PrimaryGroupID -ErrorAction Stop
        $hasDirectNow = $userRefresh.MemberOf -contains $disabledGroupDN
        $isPrimaryNow = ($userRefresh.PrimaryGroupID -eq $disabledGroupRID)

        if (-not $isPrimaryNow) {
            if (-not $hasDirectNow) {
                try { Add-ADGroupMember -Identity $disabledGroupDN -Members $user -ErrorAction Stop } catch { }
            }
            Set-ADUser -Identity $user -Replace @{PrimaryGroupID = $disabledGroupRID} -ErrorAction Stop
        }
    } catch {
        $setPGErr = $_.Exception.Message
    }

    # C) Disable if enabled
    try {
        if ($user.Enabled -eq $true) {
            Disable-ADAccount -Identity $user -ErrorAction Stop
        }
    } catch {
        $disableErr = $_.Exception.Message
    }

    # D) Remove all other direct group memberships (keep Disabled Users)
    try {
        $userAfterStep = Get-ADUser -Identity $sam -Properties MemberOf -ErrorAction Stop
        $toRemove = @()
        if ($userAfterStep.MemberOf) {
            $toRemove = @($userAfterStep.MemberOf | Where-Object { $_ -ne $disabledGroupDN })
        }
        foreach ($grp in $toRemove) {
            try {
                Remove-ADGroupMember -Identity $grp -Members $user -Confirm:$false -ErrorAction Stop
            } catch {
                $removeErrs += "Failed to remove from $grp ($($_.Exception.Message)). "
            }
        }
    } catch {
        $cleanupErr = $_.Exception.Message
    }

    # --- Capture AFTER state ---
    $afterUser     = Get-ADUser -Identity $sam -Properties MemberOf, Enabled, PrimaryGroupID -ErrorAction SilentlyContinue
    $afterEnabled  = $afterUser.Enabled
    $afterPGID     = $afterUser.PrimaryGroupID
    $afterGroups   = @()
    if ($afterUser.MemberOf) { $afterGroups = @($afterUser.MemberOf) }

    # --- Compute diffs for accurate logging ---
    $messages = @()

    # Errors (informational)
    if ($addErr)     { $messages += "Failed to add to Disabled Users ($addErr)." }
    if ($setPGErr)   { $messages += "Failed to set PrimaryGroupID ($setPGErr)." }
    if ($disableErr) { $messages += "Failed to disable account ($disableErr)." }
    if ($cleanupErr) { $messages += "Group membership cleanup failed ($cleanupErr)." }
    if ($removeErrs) { $messages += $removeErrs.Trim() }

    # Actual changes
    if ($beforeEnabled -and -not $afterEnabled)     { $messages += "Account disabled." }
    if ($beforePGID -ne $afterPGID -and $afterPGID -eq $disabledGroupRID) {
        $messages += "Primary group set to Disabled Users (RID $disabledGroupRID)."
    }

    # Group diffs (direct memberships only)
    $removed = $beforeGroups | Where-Object { $_ -notin $afterGroups }
    $added   = $afterGroups  | Where-Object { $_ -notin $beforeGroups }
    foreach ($g in $added)   { $messages += "Added to group: $g." }
    foreach ($g in $removed) { $messages += "Removed from group: $g." }

    # If primary was Disabled Users and no direct membership, clarify
    if ($isPrimaryDisabledUsers -and -not $hasDisabledUsersDirect) {
        $messages += "Already in Disabled Users (via primary)."
    } elseif ($hasDisabledUsersDirect -and -not ($added | Where-Object { $_ -eq $disabledGroupDN })) {
        $messages += "Already in Disabled Users."
    }

    # Status
    $changesExist = $false
    if ($beforeEnabled -ne $afterEnabled) { $changesExist = $true }
    if ($beforePGID -ne $afterPGID)       { $changesExist = $true }
    if ($removed.Count -gt 0 -or $added.Count -gt 0) { $changesExist = $true }

    if (-not $changesExist -and ($messages.Count -eq 0 -or ($messages -join " ") -notmatch 'Failed|Error|Removed|Added|disabled|Primary group set')) {
        $messages += "No changes to be made."
    }

    $status = if ($changesExist) { "Success" } else { "NoChange" }
    if (($messages -join " ") -match 'Failed|Error') { $status = "Partial" }

    $reportData += [PSCustomObject]@{
        sAMAccountName = $sam
        Action         = ($messages -join " ")
        Status         = $status
    }
}

$reportData | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
Write-Host "Report exported to $csvFilePath"
