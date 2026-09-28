<#

Collects local Administrators group members from a target server.

Author: Bhagawan Tapase
#>

param(
    [string]$ServerName = "Hostname",
    [switch]$UseCredential,
    [int]$MaxDepth = 5
)

$cred = $null

if ($UseCredential) {
    $cred = Get-Credential -Message "Enter credentials with local admin rights on target server"
}

Write-Host "`nConnecting to $ServerName ..." -ForegroundColor Cyan

try {
    if ($UseCredential) {
        Test-WSMan -ComputerName $ServerName -Credential $cred -ErrorAction Stop | Out-Null
    }
    else {
        Test-WSMan -ComputerName $ServerName -ErrorAction Stop | Out-Null
    }

    Write-Host "Connection Successful." -ForegroundColor Green
}
catch {
    Write-Error "Cannot connect to $ServerName. Error: $($_.Exception.Message)"
    return
}

$scriptBlock = {

    param(
        [string]$RemoteServerName,
        [int]$MaxDepth
    )

    function Get-WinNTNameParts {
        param(
            [string]$AdsPath
        )

        $m = [regex]::Match($AdsPath, '^WinNT://([^/]+)/(.+)$')

        if ($m.Success) {
            $authority = $m.Groups[1].Value
            $rest = $m.Groups[2].Value
            $name = ($rest -split '/')[0]

            return @{
                Authority = $authority
                Name      = $name
            }
        }

        return @{
            Authority = $null
            Name      = $null
        }
    }

    function Get-AdsObject {
        param(
            [string]$AdsPath,
            [string]$ExpectedClass = "group"
        )

        try {
            if ($ExpectedClass -and $AdsPath -notmatch ',') {
                return [ADSI]"$AdsPath,$ExpectedClass"
            }
            else {
                return [ADSI]$AdsPath
            }
        }
        catch {
            try {
                return [ADSI]$AdsPath
            }
            catch {
                return $null
            }
        }
    }

    function Expand-WinNTGroupMembers {

        param(
            [string]$GroupAdsPath,
            [string]$ParentGroup,
            [string]$DirectMember,
            [string]$DirectType,
            [string]$DirectPath,
            [int]$MaxDepth = 5,
            [int]$Level = 1,
            [System.Collections.Generic.HashSet[string]]$Visited
        )

        $rows = New-Object System.Collections.Generic.List[object]

        if (-not $Visited) {
            $Visited = [System.Collections.Generic.HashSet[string]]::new()
        }

        if ($Level -gt $MaxDepth) {
            return $rows
        }

        if ($Visited.Contains($GroupAdsPath)) {
            return $rows
        }

        $Visited.Add($GroupAdsPath) | Out-Null

        $groupObj = Get-AdsObject -AdsPath $GroupAdsPath -ExpectedClass "group"

        if (-not $groupObj) {
            $parts = Get-WinNTNameParts -AdsPath $GroupAdsPath

            $rows.Add([PSCustomObject]@{
                Hostname        = $RemoteServerName
                DirectMember    = $DirectMember
                DirectType      = $DirectType
                DirectPath      = $DirectPath
                ExpandedMember  = $null
                ExpandedType    = $null
                ExpandedPath    = $null
                SourceGroup     = $ParentGroup
                Level           = $Level
                Authority       = $parts.Authority
                Status          = "Group object unavailable"
                Error           = "Unable to bind ADSI object"
            })

            return $rows
        }

        try {
            $members = @($groupObj.Members())
        }
        catch {
            $parts = Get-WinNTNameParts -AdsPath $GroupAdsPath

            $rows.Add([PSCustomObject]@{
                Hostname        = $RemoteServerName
                DirectMember    = $DirectMember
                DirectType      = $DirectType
                DirectPath      = $DirectPath
                ExpandedMember  = $null
                ExpandedType    = $null
                ExpandedPath    = $null
                SourceGroup     = $ParentGroup
                Level           = $Level
                Authority       = $parts.Authority
                Status          = "Group listed; members unavailable"
                Error           = $_.Exception.Message
            })

            return $rows
        }

        foreach ($member in $members) {

            try {
                $name  = $member.GetType().InvokeMember("Name", "GetProperty", $null, $member, $null)
                $class = $member.GetType().InvokeMember("Class", "GetProperty", $null, $member, $null)
                $path  = $member.GetType().InvokeMember("ADsPath", "GetProperty", $null, $member, $null)

                $parts = Get-WinNTNameParts -AdsPath $path

                $rows.Add([PSCustomObject]@{
                    Hostname        = $RemoteServerName
                    DirectMember    = $DirectMember
                    DirectType      = $DirectType
                    DirectPath      = $DirectPath
                    ExpandedMember  = $name
                    ExpandedType    = $class
                    ExpandedPath    = $path
                    SourceGroup     = $ParentGroup
                    Level           = $Level
                    Authority       = $parts.Authority
                    Status          = "OK"
                    Error           = $null
                })

                if ($class -eq "Group" -and $Level -lt $MaxDepth) {

                    $nested = Expand-WinNTGroupMembers `
                        -GroupAdsPath $path `
                        -ParentGroup $name `
                        -DirectMember $DirectMember `
                        -DirectType $DirectType `
                        -DirectPath $DirectPath `
                        -MaxDepth $MaxDepth `
                        -Level ($Level + 1) `
                        -Visited $Visited

                    foreach ($n in $nested) {
                        $rows.Add($n)
                    }
                }
            }
            catch {
                $rows.Add([PSCustomObject]@{
                    Hostname        = $RemoteServerName
                    DirectMember    = $DirectMember
                    DirectType      = $DirectType
                    DirectPath      = $DirectPath
                    ExpandedMember  = $null
                    ExpandedType    = $null
                    ExpandedPath    = $null
                    SourceGroup     = $ParentGroup
                    Level           = $Level
                    Authority       = $null
                    Status          = "Member read failed"
                    Error           = $_.Exception.Message
                })
            }
        }

        return $rows
    }

    $allRows = New-Object System.Collections.Generic.List[object]

    try {
        $adminGroup = [ADSI]"WinNT://./Administrators,group"
        $directMembers = @($adminGroup.Members())
    }
    catch {
        $allRows.Add([PSCustomObject]@{
            Hostname        = $RemoteServerName
            DirectMember    = $null
            DirectType      = $null
            DirectPath      = $null
            ExpandedMember  = $null
            ExpandedType    = $null
            ExpandedPath    = $null
            SourceGroup     = "Administrators"
            Level           = $null
            Authority       = $null
            Status          = "Failed to read Administrators group"
            Error           = $_.Exception.Message
        })

        return $allRows
    }

    foreach ($direct in $directMembers) {

        try {
            $directName  = $direct.GetType().InvokeMember("Name", "GetProperty", $null, $direct, $null)
            $directClass = $direct.GetType().InvokeMember("Class", "GetProperty", $null, $direct, $null)
            $directPath  = $direct.GetType().InvokeMember("ADsPath", "GetProperty", $null, $direct, $null)

            $directParts = Get-WinNTNameParts -AdsPath $directPath

            $allRows.Add([PSCustomObject]@{
                Hostname        = $RemoteServerName
                DirectMember    = $directName
                DirectType      = $directClass
                DirectPath      = $directPath
                ExpandedMember  = $directName
                ExpandedType    = $directClass
                ExpandedPath    = $directPath
                SourceGroup     = "Administrators"
                Level           = 0
                Authority       = $directParts.Authority
                Status          = "OK"
                Error           = $null
            })

            if ($directClass -eq "Group") {

                $expandedMembers = Expand-WinNTGroupMembers `
                    -GroupAdsPath $directPath `
                    -ParentGroup $directName `
                    -DirectMember $directName `
                    -DirectType $directClass `
                    -DirectPath $directPath `
                    -MaxDepth $MaxDepth `
                    -Level 1

                foreach ($item in $expandedMembers) {
                    $allRows.Add($item)
                }
            }
        }
        catch {
            $allRows.Add([PSCustomObject]@{
                Hostname        = $RemoteServerName
                DirectMember    = $null
                DirectType      = $null
                DirectPath      = $null
                ExpandedMember  = $null
                ExpandedType    = $null
                ExpandedPath    = $null
                SourceGroup     = "Administrators"
                Level           = $null
        Authority       = $null
                Status          = "Direct member read failed"
                Error           = $_.Exception.Message
            })
        }
    }

    return $allRows
}

try {
    if ($UseCredential) {
        $results = Invoke-Command `
            -ComputerName $ServerName `
            -Credential $cred `
            -ScriptBlock $scriptBlock `
            -ArgumentList $ServerName, $MaxDepth `
            -ErrorAction Stop
    }
    else {
        $results = Invoke-Command `
            -ComputerName $ServerName `
            -ScriptBlock $scriptBlock `
            -ArgumentList $ServerName, $MaxDepth `
            -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to collect Administrators group from $ServerName. Error: $($_.Exception.Message)"
    return
}

$ExcludedAuthorities = @(
    "NT SERVICE",
    "NT AUTHORITY"
)

$ExcludedTreeGroups = @(
    "DOMAIN ADMINS",
    "CC_AWS_SERVER_ADMINS",
    "CC_SERVER_ADMINS",
    "CC_LOCAL ADMIN-SERVERS"
)

function Test-IsExcludedEntry {
    param(
        [string]$Member,
        [string]$Authority
    )

    if (-not $Member -or $Member.Trim() -eq "") {
        return $true
    }

    if ($Member -match '^S-\d-\d+') {
        return $true
    }

    if ($Authority -and $Authority.ToUpper() -in $ExcludedAuthorities) {
        return $true
    }

    return $false
}

function Test-IsExcludedTreeGroup {
    param(
        [string]$GroupName
    )

    if (-not $GroupName) {
        return $false
    }

    return ($GroupName.ToUpper() -in $ExcludedTreeGroups)
}

function Get-MemberLabel {
    param(
        [string]$MemberType,
        [string]$Authority,
        [string]$ServerName
    )

    $auth = ""
    if ($Authority) {
        $auth = $Authority.ToUpper()
    }

    $serverUpper = $ServerName.ToUpper()
    $localComputer = $env:COMPUTERNAME.ToUpper()

    if ($auth -eq "BUILTIN") {
        if ($MemberType -eq "Group") {
            return "BUILTIN GROUP"
        }
        elseif ($MemberType -eq "User") {
            return "BUILTIN USER"
        }
        else {
            return "BUILTIN $($MemberType.ToUpper())"
        }
    }

    if ($auth -eq $serverUpper -or $auth -eq $localComputer) {
        if ($MemberType -eq "Group") {
            return "LOCAL GROUP"
        }
        elseif ($MemberType -eq "User") {
            return "LOCAL USER"
        }
        elseif ($MemberType -eq "Computer") {
            return "LOCAL COMPUTER"
        }
        else {
            return "LOCAL $($MemberType.ToUpper())"
        }
    }

    if ($MemberType -eq "Group") {
        return "DOMAIN GROUP"
    }
    elseif ($MemberType -eq "User") {
        return "DOMAIN USER"
    }
    elseif ($MemberType -eq "Computer") {
        return "DOMAIN COMPUTER"
    }
    else {
        return "DOMAIN $($MemberType.ToUpper())"
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ADModuleAvailable = $true
}
catch {
    $ADModuleAvailable = $false
}

function Resolve-ADGroupSafe {
    param(
        [string]$GroupName
    )

    try {
        return Get-ADGroup -Identity $GroupName -ErrorAction Stop
    }
    catch {
        try {
            return Get-ADGroup -LDAPFilter "(|(samAccountName=$GroupName)(name=$GroupName))" -ErrorAction Stop |
                Select-Object -First 1
        }
        catch {
            return $null
        }
    }
}

function Show-ADGroupTree {
    param(
        [string]$GroupName,
        [string]$Prefix = "",
        [int]$Level = 0,
        [int]$MaxDepth = 5,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    if (-not $Visited) {
        $Visited = [System.Collections.Generic.HashSet[string]]::new()
    }

    if ($Level -gt $MaxDepth) {
        Write-Host "$Prefix└── Max depth reached for $GroupName" -ForegroundColor DarkYellow
        return
    }

    if (Test-IsExcludedTreeGroup -GroupName $GroupName) {
        Write-Host "$Prefix└── Group expansion skipped as per exclusion list: $GroupName" -ForegroundColor DarkYellow
        return
    }

    $adGroup = Resolve-ADGroupSafe -GroupName $GroupName

    if (-not $adGroup) {
        Write-Host "$Prefix[GROUP] $GroupName" -ForegroundColor Red
        Write-Host "$Prefix└── Unable to resolve this group in Active Directory" -ForegroundColor Red
        return
    }

    if (Test-IsExcludedTreeGroup -GroupName $adGroup.Name) {
        Write-Host "$Prefix└── Group expansion skipped as per exclusion list: $($adGroup.Name)" -ForegroundColor DarkYellow
        return
    }

    if ($Visited.Contains($adGroup.DistinguishedName)) {
        Write-Host "$Prefix[GROUP] $($adGroup.Name)" -ForegroundColor DarkYellow
        Write-Host "$Prefix└── Circular nesting detected. Already processed." -ForegroundColor DarkYellow
        return
    }

    $Visited.Add($adGroup.DistinguishedName) | Out-Null

    try {
        $Members = @(Get-ADGroupMember -Identity $adGroup.DistinguishedName -ErrorAction Stop)

        $UserCount     = ($Members | Where-Object {$_.ObjectClass -eq 'user'}).Count
        $GroupCount    = ($Members | Where-Object {$_.ObjectClass -eq 'group'}).Count
        $ComputerCount = ($Members | Where-Object {$_.ObjectClass -eq 'computer'}).Count
        $OtherCount    = ($Members | Where-Object {$_.ObjectClass -notin @('user','group','computer')}).Count

        Write-Host "$Prefix[GROUP] $($adGroup.Name)" -ForegroundColor Cyan
        Write-Host "$Prefix├── Users: $UserCount" -ForegroundColor Yellow
        Write-Host "$Prefix├── Groups: $GroupCount" -ForegroundColor Yellow
        Write-Host "$Prefix├── Computers: $ComputerCount" -ForegroundColor Yellow
        Write-Host "$Prefix└── Others: $OtherCount" -ForegroundColor Yellow

        foreach ($Member in ($Members | Sort-Object ObjectClass, Name)) {

            switch ($Member.ObjectClass) {

                "user" {
                    try {
                        $u = Get-ADUser -Identity $Member.DistinguishedName -Properties Enabled, SamAccountName -ErrorAction Stop
                        Write-Host "$Prefix    ├── [USER] $($u.Name) ($($u.SamAccountName))"
                    }
                    catch {
                        Write-Host "$Prefix    ├── [USER] $($Member.Name)"
                    }
                }

                "computer" {
                    Write-Host "$Prefix    ├── [COMPUTER] $($Member.Name)"
                }

                "group" {
                    Write-Host "$Prefix    ├── [GROUP] $($Member.Name)" -ForegroundColor Green

                    if (Test-IsExcludedTreeGroup -GroupName $Member.Name) {
                      #  Write-Host "$Prefix    │   └── Nested group expansion skipped as per exclusion list" -ForegroundColor DarkYellow
                      continue
                    }
                    else {
                        Show-ADGroupTree `
                            -GroupName $Member.SamAccountName `
                            -Prefix "$Prefix    │   " `
                            -Level ($Level + 1) `
                            -MaxDepth $MaxDepth `
                            -Visited $Visited
                    }
                }

                default {
                    Write-Host "$Prefix    ├── [$($Member.ObjectClass.ToUpper())] $($Member.Name)"
                }
            }
        }
    }
    catch {
        Write-Host "$Prefix[GROUP] $GroupName" -ForegroundColor Red
        Write-Host "$Prefix└── ERROR: Cannot read group members. $($_.Exception.Message)" -ForegroundColor Red
    }
}

$finalClean = $results |
Select-Object @{
    Name='Hostname'
    Expression={$_.Hostname}
}, @{
    Name='Member'
    Expression={
        if ($_.ExpandedMember) {
            $_.ExpandedMember
        }
        else {
            $_.DirectMember
        }
    }
}, @{
    Name='Type'
    Expression={
        if ($_.ExpandedType) {
            $_.ExpandedType
        }
        else {
            $_.DirectType
        }
    }
}, @{
    Name='Authority'
    Expression={$_.Authority}
} |
Where-Object {
    -not (Test-IsExcludedEntry -Member $_.Member -Authority $_.Authority)
} |
Sort-Object Hostname, Type, Member, Authority -Unique

$DirectAdminMembers = $results |
Where-Object {
    $_.Level -eq 0 -and
    -not (Test-IsExcludedEntry -Member $_.DirectMember -Authority $_.Authority)
} |
Select-Object DirectMember, DirectType, DirectPath, Authority -Unique |
Sort-Object DirectType, DirectMember

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "ADMINISTRATORS REPORT : $ServerName " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Server    : $ServerName"
Write-Host "Generated : $(Get-Date)"
#Write-Host "Excluded  : NT SERVICE, NT AUTHORITY, SID-only entries"
#Write-Host "Included  : Domain Users/Groups, Local Users/Groups, BUILTIN Groups"
#Write-Host "Tree Skip : Domain Admins, CC_AWS_Server_Admins, CC_Server_Admins, CC_Local Admin-Servers"
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "============================================================" -ForegroundColor Green
Write-Host "MEMBERS SUMMARY" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

if (-not $finalClean -or $finalClean.Count -eq 0) {
    Write-Host "No valid members found." -ForegroundColor Red
}
else {
    foreach ($row in $finalClean) {

        $summaryLabel = Get-MemberLabel `
            -MemberType $row.Type `
            -Authority $row.Authority `
            -ServerName $ServerName

        Write-Host "$($row.Hostname) | [$summaryLabel] | $($row.Member) | $($row.Authority)"
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "LOCAL ADMINISTRATORS TREE VIEW" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "LOCAL ADMINISTRATORS" -ForegroundColor Cyan

if (-not $DirectAdminMembers -or $DirectAdminMembers.Count -eq 0) {
    Write-Host "└── No valid members found or unable to read local Administrators group" -ForegroundColor Red
}
else {
    foreach ($item in $DirectAdminMembers) {

        $memberName = $item.DirectMember
        $memberType = $item.DirectType
        $authority  = $item.Authority

        $label = Get-MemberLabel `
            -MemberType $memberType `
            -Authority $authority `
            -ServerName $ServerName

        if ($memberType -eq "Group") {

            Write-Host "├── [$label] $memberName [$authority]" -ForegroundColor Green

            if ($label -eq "DOMAIN GROUP") {

                if (Test-IsExcludedTreeGroup -GroupName $memberName) {
                   # Write-Host "│   └── Group expansion skipped as per exclusion list" -ForegroundColor DarkYellow
                   continue
                }
                elseif ($ADModuleAvailable) {
                    Write-Host "│"
                    Show-ADGroupTree `
                        -GroupName $memberName `
                        -Prefix "│   " `
                        -MaxDepth $MaxDepth
                    Write-Host "│"
                }
                else {
                    Write-Host "│   └── ActiveDirectory module not available. AD expansion skipped." -ForegroundColor DarkYellow
                }
            }
            else {
                Write-Host "│   └── $label displayed. AD expansion skipped." -ForegroundColor DarkYellow
            }
        }
        else {
            Write-Host "├── [$label] $memberName [$authority]"
        }
    }
}

Write-Host ""
Write-Host "Congratulations! Your report is ready." -ForegroundColor Green
