#Step 1: Check Forest Functional Level

Get-ADForest | Select ForestMode

#Step 2: Enable PAM Optional Feature

    Enable-ADOptionalFeature `
      -Identity "Privileged Access Management Feature" `
      -Scope ForestOrConfigurationSet `
      -Target yourdomain.com

#Verify:

Get-ADOptionalFeature `
  -Filter 'Name -like "*Privileged*"'

#Step 3: Add Temporary Domain Admin Access

#Example: 10 Days
Add-ADGroupMember `
  -Identity "Domain Admins" `
  -Members bhagawan.tapase `
  -MemberTimeToLive (New-TimeSpan -Days 10)

#Example: 8 Hours
Add-ADGroupMember `
  -Identity "Domain Admins" `
  -Members bhagawan.tapase `
  -MemberTimeToLive (New-TimeSpan -Hours 8)

#Example: 1 Hour
Add-ADGroupMember `
  -Identity "Domain Admins" `
  -Members bhagawan.tapase `
  -MemberTimeToLive (New-TimeSpan -Hours 1)

#Step 4: Verify Remaining TTL in Second
Get-ADGroup `
    -Identity "Domain Admins" `
    -Properties member `
    -ShowMemberTimeToLive |
Select-Object -ExpandProperty member |
Where-Object { $_ -match '<TTL=' }

#Step 4: Verify Remaining TTL info with End Date.

$SamAccountName = "Admin Account"

try {
    $DN = (Get-ADUser $SamAccountName -ErrorAction Stop).DistinguishedName

    $entry = (Get-ADGroup "Domain Admins" -Properties member -ShowMemberTimeToLive).member |
        Where-Object { $_ -like "*$DN*" }

    if (-not $entry) {
        Write-Host "$SamAccountName is not a member of Domain Admins." -ForegroundColor Yellow
    }
    elseif ($entry -match '<TTL=(\d+)>') {
        $ttl = [int64]$Matches[1]

        [PSCustomObject]@{
            SamAccountName = $SamAccountName
            TTLSeconds     = $ttl
            ExpiryTime     = (Get-Date).AddSeconds($ttl)
        } | Format-List
    }
    else {
        Write-Host "$SamAccountName is a permanent member of Domain Admins (no TTL)." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "User $SamAccountName not found." -ForegroundColor Red
}
