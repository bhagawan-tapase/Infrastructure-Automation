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

#Step 4: Verify Remaining TTL
Get-ADGroup `
    -Identity "Domain Admins" `
    -Properties member `
    -ShowMemberTimeToLive |
Select-Object -ExpandProperty member |
Where-Object { $_ -match '<TTL=' }
