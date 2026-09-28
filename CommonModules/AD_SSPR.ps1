<#
Script Name : Self_Service_Password_Reset.ps1

Description :
This PowerShell-based Self-Service Password Reset (SSPR) solution provides a secure and user-friendly interface for Active Directory password management. The tool enables users to generate strong passwords, securely change existing passwords, and validate password requirements against Domain and Fine-Grained Password Policies (FGPP).

Key Features:
✅ Self-Service Password Reset (SSPR)
✅ Secure password generation using cryptographic randomization
✅ Active Directory password policy validation
✅ Fine-Grained Password Policy (FGPP) support
✅ Password complexity, history, and minimum age enforcement
✅ Account lockout detection and validation
✅ Username and name-based password restriction checks
✅ NetAPI password change with LDAP fallback support
✅ SecureString-based password handling
✅ Automatic password reveal timeout protection
✅ Modern WPF graphical user interface

This solution helps organizations improve password security, reduce helpdesk workload, and provide a streamlined password management experience for Active Directory users.
#>


#region Bootstrap: Windows + STA
if (-not $IsWindows) {
    $plat = [Environment]::OSVersion.Platform
    $isWin = ($plat -eq 'Win32NT' -or $plat -eq 2 -or $plat -eq 1)
    if (-not $isWin) { Write-Error "Windows-only (WPF + Netapi32 + System.DirectoryServices.Protocols)."; return }
}
try { $apt = [System.Threading.Thread]::CurrentThread.ApartmentState } catch { $apt = 'Unknown' }
function Restart-AsSTA {
    $psExe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh' } else { 'powershell' }
    Start-Process -FilePath $psExe -ArgumentList @('-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") | Out-Null
    exit
}
if ($host.Name -notlike '*ISE*' -and $apt -ne 'STA') { Restart-AsSTA }
#endregion

# Assemblies
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase, System.Xaml | Out-Null
Add-Type -AssemblyName System.DirectoryServices.Protocols | Out-Null

# ---------------------------
# Theme / Config
# ---------------------------
$Theme = @{
  Bg        = '#1E2227'
  Card      = '#24292F'
  Field     = '#2C323A'
  Text      = '#F0F0F0'
  Muted     = '#B8C0CC'
  Accent    = '#0E7AC7'
  AccentHi  = '#2EA7FF'
  Success   = '#49B06E'
  Warn      = '#D18A3B'
  Error     = '#E05A5A'
  Border    = '#3A424B'
}

# Defaults (effective policy can override)
$MinLengthDefault   = 14
$AvoidLookAlikes    = $true
$EnableLdapFallback = $true    # try LDAP only if primary (NetAPI) fails
$PreferStartTLS     = $true    # fallback: try StartTLS 389 before LDAPS 636

# ---------------------------
# Comment rendering helpers (colorized)
# ---------------------------
function Show-Message {
    param(
        [Parameter(Mandatory)]$Box,
        [ValidateSet('success','warn','error','info')] [string]$Kind = 'info',
        [string]$Summary,
        [string]$Reason,
        [string]$System,
        [string]$Server,
        [string]$Policy,
        [switch]$Append
    )
    $lines = New-Object System.Collections.Generic.List[string]

    $prefix = switch ($Kind) {
        'success' { 'Success' }
        'warn'    { 'Note' }
        'error'   { 'Error' }
        default   { 'Info' }
    }

    if ($Summary) { $lines.Add(("{0}: {1}" -f $prefix, $Summary)) }
    if ($Reason)  { $lines.Add("Reason: " + $Reason) }
    if ($System)  { $lines.Add("System: " + $System) }
    if ($Server)  { $lines.Add("Server: " + $Server) }
    if ($Policy)  { $lines.Add($Policy) }

    $text = ($lines -join "`r`n")

    if ($Append -and -not [string]::IsNullOrWhiteSpace($Box.Text)) {
        $Box.Text = $Box.Text + "`r`n---`r`n" + $text
    } else {
        $Box.Text = $text
    }

    $hex = switch ($Kind) {
        'success' { $Theme.Success }
        'warn'    { $Theme.Warn }
        'error'   { $Theme.Error }
        default   { $Theme.Text }
    }
    $Box.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($hex))
}
# Back-compat alias
function Set-Comment {
    param(
        [Parameter(Mandatory)]$Box,
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('info','success','warn','error')] [string]$Kind = 'info'
    )
    Show-Message -Box $Box -Kind $Kind -Summary $Text
}

# ---------------------------
# Crypto RNG & Password Utils
# ---------------------------
function Get-RandomBytes { param([int]$Count=32)
    $bytes = New-Object byte[] ($Count)
    try { $rng=[System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($bytes); $rng.Dispose() }
    catch { $rng=New-Object System.Security.Cryptography.RNGCryptoServiceProvider; $rng.GetBytes($bytes); $rng.Dispose() }
    return $bytes
}

function New-StrongPassword {
    param([int]$Length=$MinLengthDefault,[bool]$NoLookAlikes=$AvoidLookAlikes)
    if ($Length -lt 8) { $Length = 8 }
    $Upper = if ($NoLookAlikes) { 'ABCDEFGHJKLMNPQRSTUVWXYZ' } else { 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }
    $Lower = if ($NoLookAlikes) { 'abcdefghijkmnpqrstuvwxyz' } else { 'abcdefghijklmnopqrstuvwxyz' }
    $Digit = if ($NoLookAlikes) { '23456789' } else { '0123456789' }
    $Sym   = '!@#$%^&*()-_=+[]{}:;,.?'
    function Get-CryptoIndex([int]$max){ if($max -le 0){0}else{ ((Get-RandomBytes -Count 1)[0] % $max) } }

    $chars = New-Object 'char[]' ($Length)
    $spots = New-Object System.Collections.ArrayList
    while($spots.Count -lt 4){ $i=Get-CryptoIndex $Length; if(-not $spots.Contains($i)){[void]$spots.Add($i)} }
    $spots=[int[]]$spots
    $chars[$spots[0]]=$Upper[(Get-CryptoIndex $Upper.Length)]
    $chars[$spots[1]]=$Lower[(Get-CryptoIndex $Lower.Length)]
    $chars[$spots[2]]=$Digit[(Get-CryptoIndex $Digit.Length)]
    $chars[$spots[3]]=$Sym[(Get-CryptoIndex $Sym.Length)]
    $all = ($Upper+$Lower+$Digit+$Sym)
    for($i=0;$i -lt $Length;$i++){ if($chars[$i] -ne 0){continue}; $chars[$i]=$all[(Get-CryptoIndex $all.Length)] }
    for($i=$Length-1;$i -ge 1;$i--){ $j=Get-CryptoIndex ($i+1); if($j -ne $i){ $t=$chars[$i]; $chars[$i]=$chars[$j]; $chars[$j]=$t } }
    -join $chars
}

function Test-PasswordComplexity { param([string]$Password,[int]$Min)
    if([string]::IsNullOrWhiteSpace($Password)){return $false}
    if($Password.Length -lt $Min){return $false}
    if($Password -notmatch '[A-Z]'){return $false}
    if($Password -notmatch '[a-z]'){return $false}
    if($Password -notmatch '\d'){return $false}
    if($Password -notmatch '[^A-Za-z0-9]'){return $false}
    return $true
}

function Test-AccountLockout {
    param($UserInfo)
    if (-not $UserInfo -or -not $UserInfo.Entry) { return $false }
    $uac = $UserInfo.Entry.Properties["msDS-User-Account-Control-Computed"].Value
    if ($uac -eq $null) { return $false }
    return (($uac -band 0x10) -ne 0) # UF_LOCKOUT
}

function Parse-UserDomain { param([string]$InputUsername)
    $domain=$null;$user=$InputUsername
    if($InputUsername -match '\\'){ $parts=$InputUsername -split '\\',2; $domain=$parts[0]; $user=$parts[1] }
    elseif($InputUsername -match '@'){ $parts=$InputUsername -split '@',2; $user=$parts[0]; $domain=$parts[1] }
    else{ $domain=$env:USERDNSDOMAIN; if([string]::IsNullOrWhiteSpace($domain)){$domain=$env:USERDOMAIN}; if([string]::IsNullOrWhiteSpace($domain)){$domain='.'} }
    @{Domain=$domain;User=$user}
}

# ---------------------------
# ADSI helpers: policy + user
# ---------------------------
function Convert-LargeIntegerToInt64 { param($large)
    if(-not $large){return 0L}
    $high=[int]$large.HighPart; $low=[uint32]$large.LowPart
    ([int64]$high -shl 32) -bor [int64]$low
}
function Was-RecentlyChanged {
    param($EffectiveInfo,[int]$Minutes = 5)
    if (-not $EffectiveInfo.LastSet) { return $false }
    return (((Get-Date) - $EffectiveInfo.LastSet).TotalMinutes -lt $Minutes)
}

function Get-DomainDefaultPolicy {
    try {
        $root = [ADSI]"LDAP://RootDSE"
        $defaultNC = [string]$root.defaultNamingContext
        if ([string]::IsNullOrWhiteSpace($defaultNC)) { return $null }

        $dom = [ADSI]"LDAP://$defaultNC"

        if (-not $dom.minPwdAge.Value) {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = $dom
            $searcher.Filter = "(objectClass=domainDNS)"
            $null = $searcher.PropertiesToLoad.Add("minPwdAge")
            $null = $searcher.PropertiesToLoad.Add("pwdHistoryLength")
            $null = $searcher.PropertiesToLoad.Add("pwdProperties")
            $null = $searcher.PropertiesToLoad.Add("minPwdLength")

            $res = $searcher.FindOne()
            if ($res) { $dom = $res.GetDirectoryEntry() }
        }

        $minPwdAge = [TimeSpan]::FromTicks(
            [math]::Abs((Convert-LargeIntegerToInt64 $dom.minPwdAge.Value))
        )

        $hist     = [int]$dom.pwdHistoryLength.Value
        $props    = [int]$dom.pwdProperties.Value
        $complex  = (($props -band 1) -ne 0)
        $minLen   = [int]$dom.minPwdLength.Value

        return @{
            Scope      = 'DomainDefault'
            DefaultNC  = $defaultNC
            MinPwdAge  = $minPwdAge
            History    = $hist
            Complexity = $complex
            MinLength  = if ($minLen -gt 0) { $minLen } else { $MinLengthDefault }
        }
    }
    catch {
        return $null
    }
}

function Find-AdUser { param([string]$InputUsername)
    try{
        $root=[ADSI]"LDAP://RootDSE"; $base="LDAP://{0}" -f $root.defaultNamingContext
        $sr=New-Object System.DirectoryServices.DirectorySearcher([ADSI]$base)
        $sam=$InputUsername;$upn=$InputUsername; if($InputUsername -match '\\'){ $sam=$InputUsername.Split('\')[-1] }
        $sr.Filter="(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$sam)(userPrincipalName=$upn)))"
        foreach($p in 'pwdLastSet','lockoutTime','msDS-User-Account-Control-Computed',
                 'sAMAccountName','displayName','givenName','sn','msDS-ResultantPSO'){
            [void]$sr.PropertiesToLoad.Add($p)
        }
        $res=$sr.FindOne(); if(-not $res){return $null}
        $entry=$res.GetDirectoryEntry()
        @{
            Entry=$entry
            sAM=[string]$entry.Properties['sAMAccountName'].Value
            displayName=[string]$entry.Properties['displayName'].Value
            givenName=[string]$entry.Properties['givenName'].Value
            sn=[string]$entry.Properties['sn'].Value
            pwdLastSetRaw=$entry.Properties['pwdLastSet'].Value
            ResultantPSO=[string]$entry.Properties['msDS-ResultantPSO'].Value
        }
    }catch{ $null }
}

function Get-PSOByDn {
    param([string]$dn)
    if ([string]::IsNullOrWhiteSpace($dn)) { return $null }
    try {
        $pso = [ADSI]"LDAP://$dn"

        $minLenProp = $pso.Properties['msDS-MinimumPasswordLength'].Value
        $minAgeProp = $pso.Properties['msDS-MinimumPasswordAge'].Value
        $histProp   = $pso.Properties['msDS-PasswordHistoryLength'].Value
        $cmpProp    = $pso.Properties['msDS-PasswordComplexityEnabled'].Value

        $minLen = [int]$minLenProp
        $minAge = [TimeSpan]::FromTicks([math]::Abs((Convert-LargeIntegerToInt64 $minAgeProp)))
        $hist   = [int]$histProp
        $cmp    = [bool]$cmpProp

        return @{
            Scope      = 'FGPP'
            MinLength  = $minLen
            MinPwdAge  = $minAge
            History    = $hist
            Complexity = $cmp
        }
    } catch {
        return $null
    }
}

function Get-EffectivePasswordPolicy {
    param([Parameter(Mandatory)][string]$InputUsername)

    $u         = Find-AdUser -InputUsername $InputUsername
    $domainPol = Get-DomainDefaultPolicy

    if (-not $u) {
        return @{ Policy=$domainPol; User=$null; LastSet=$null; NextAllowed=$null }
    }

    $psoPol = $null
    if ($u.ResultantPSO -and $u.ResultantPSO.Trim()) {
        $psoPol = Get-PSOByDn -dn $u.ResultantPSO
    }

    $eff    = if ($psoPol) { $psoPol } else { $domainPol }
    $minLen = if ($eff.MinLength -gt 0) { [int]$eff.MinLength } else { $MinLengthDefault }

    $ticks = Convert-LargeIntegerToInt64 $u.pwdLastSetRaw
    $lastSet = if ($ticks -gt 0) { [DateTime]::FromFileTimeUtc($ticks).ToLocalTime() } else { $null }
    $nextAllowed = if ($lastSet -and $eff.MinPwdAge) { $lastSet + $eff.MinPwdAge } else { $null }

    return @{
        Policy = @{
            Scope      = $eff.Scope
            MinLength  = $minLen
            MinPwdAge  = $eff.MinPwdAge
            History    = $eff.History
            Complexity = $eff.Complexity
        }
        User        = $u
        LastSet     = $lastSet
        NextAllowed = $nextAllowed
    }
}

function Test-PasswordAgainstName { param([string]$Password,[string]$Sam,[string]$DisplayName,[string]$GivenName,[string]$Sn)
    $pwd=$Password.ToLowerInvariant(); $tokens=@()
    foreach($t in @($Sam,$DisplayName,$GivenName,$Sn)){
        if([string]::IsNullOrWhiteSpace($t)){continue}
        $parts=($t -replace '[^A-Za-z0-9]',' ') -split '\s+'
        foreach($p in $parts){ if($p.Length -ge 3){ $tokens+=$p.ToLowerInvariant() } }
    }
    foreach($tok in ($tokens | Select-Object -Unique)){ if($pwd.Contains($tok)){ return $false } }
    return $true
}

# ---------------------------
# NetUserChangePassword (Primary)
# ---------------------------
$pinvoke = @"
using System;
using System.Runtime.InteropServices;

public static class LocalNetApi {
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint NetUserChangePassword(
        string domain,
        string username,
        string oldPassword,
        string newPassword
    );
}
"@
Add-Type -TypeDefinition $pinvoke -ErrorAction Stop

function Invoke-PasswordChange {
    param([string]$InputUsername,[string]$OldPassword,[string]$NewPassword)
    $parsed=Parse-UserDomain -InputUsername $InputUsername
    $rc=[LocalNetApi]::NetUserChangePassword($parsed.Domain,$parsed.User,$OldPassword,$NewPassword)
    $msg=switch($rc){
        0     {"Password changed successfully."}
        5     {"Access denied. Check domain or 'DOMAIN\user' format."}
        86    {"Current (old) password is incorrect."}
        87    {"Invalid parameter. Check username format."}
        1323  {"Policy restriction (complexity/min-age/history/name rules)."}
        1325  {"User not found."}
        1351  {"Domain not found or unreachable."}
        2221  {"User name could not be found."}
        2245  {"Password too short or violates policy."}
        default {"Change failed. Win32 code: $rc"}
    }
    $sys = (New-Object System.ComponentModel.Win32Exception([int]$rc)).Message
    @{ Ok=($rc -eq 0); Message=$msg; Code=$rc; System=$sys }
}

# ---------------------------
# LDAP helpers (shared)
# ---------------------------
function Get-QuotedUnicodeBytes([string]$pwd){ [Text.Encoding]::Unicode.GetBytes(('"{0}"' -f $pwd)) } # (legacy, kept)

function Resolve-LdapServerFromUsername([string]$InputUsername){
    if($env:LOGONSERVER){ return ($env:LOGONSERVER -replace '^\\\','') }
    if($InputUsername -match '@'){ return ($InputUsername -split '@',2)[1] }
    if($env:USERDNSDOMAIN){ return $env:USERDNSDOMAIN }
    return $null
}

# ============================
# Secure helpers (+ robust auto-hide timer)
# ============================

# Ensure no stale version from earlier loads
Remove-Item Function:\Start-AutoHideTimer -ErrorAction SilentlyContinue

# Global table to keep timers alive (GC-proof) and addressable
if (-not $script:RevealTimers) { $script:RevealTimers = @{} }

function Start-RevealAutoHideTimer {
    param(
        [Parameter(Mandatory)]$Pwd,         # PasswordBox (hidden)
        [Parameter(Mandatory)]$PwdReveal,   # TextBox (revealed)
        [Parameter(Mandatory)]$Btn,         # Button (👁 / 🙈)
        [int]$Seconds = 5
    )

    # Stable key per button instance
    $key = if ($Btn) { [int]$Btn.GetHashCode() } else { [guid]::NewGuid().ToString() }

    # Stop any previous timer for this key (if user clicked multiple times)
    if ($script:RevealTimers.ContainsKey($key)) {
        try { $script:RevealTimers[$key].Stop() } catch {}
        $null = $script:RevealTimers.Remove($key)
    }

    if ($PwdReveal.Visibility -ne 'Visible') { return }

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds($Seconds)

    # IMPORTANT: PowerShell often doesn't pass sender/args → use the hashtable to stop.
    $timer.Add_Tick({
        try {
            # Hide if still visible
            if ($PwdReveal.Visibility -eq 'Visible') {
                Toggle-Reveal-Safe -pwd $Pwd -pwdReveal $PwdReveal
                if ($Btn) { try { $Btn.Content = '👁' } catch {} }
            }
        } catch { }

        # Stop and remove this timer by key from the global table
        try {
            if ($script:RevealTimers.ContainsKey($key)) {
                try { $script:RevealTimers[$key].Stop() } catch {}
                $null = $script:RevealTimers.Remove($key)
            }
        } catch { }
    })

    $script:RevealTimers[$key] = $timer
    $timer.Start()
}


# Compare two SecureStrings without creating managed strings
function Compare-SecureString {
    param([Parameter(Mandatory)][SecureString]$A,[Parameter(Mandatory)][SecureString]$B)
    if ($A.Length -ne $B.Length) { return $false }
    $pa = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($A)
    $pb = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($B)
    try {
        for ($i=0; $i -lt $A.Length; $i++) {
            $ca = [Runtime.InteropServices.Marshal]::ReadInt16($pa, $i*2)
            $cb = [Runtime.InteropServices.Marshal]::ReadInt16($pb, $i*2)
            if ($ca -ne $cb) { return $false }
        }
        return $true
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pa)
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pb)
    }
}

# Build quoted UTF-16LE bytes from SecureString for unicodePwd, without managed strings
function Get-QuotedUnicodeBytesFromSecureString {
    param([Parameter(Mandatory)][SecureString]$Sec)
    $len = $Sec.Length
    $pSrc = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Sec)
    try {
        $bytes = New-Object byte[] ((($len + 2) * 2)) # leading + trailing quote, UTF-16LE
        $bytes[0] = 0x22; $bytes[1] = 0x00           # leading quote
        [Runtime.InteropServices.Marshal]::Copy($pSrc, $bytes, 2, $len * 2)
        $bytes[2 + ($len * 2)]     = 0x22            # trailing quote
        $bytes[2 + ($len * 2) + 1] = 0x00
        return $bytes
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pSrc)
    }
}

# Complexity check against SecureString
function Test-PasswordComplexitySecure {
    param([SecureString]$Sec,[int]$Min)
    if (-not $Sec -or $Sec.Length -lt [Math]::Max($Min,8)) { return $false }
    $hasU=$false;$hasL=$false;$hasD=$false;$hasS=$false
    $p = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Sec)
    try {
        for($i=0;$i -lt $Sec.Length;$i++){
            $ch = [char][uint16][Runtime.InteropServices.Marshal]::ReadInt16($p,$i*2)
            if ([char]::IsUpper($ch)) { $hasU=$true; continue }
            if ([char]::IsLower($ch)) { $hasL=$true; continue }
            if ([char]::IsDigit($ch)) { $hasD=$true; continue }
            if ($ch -notin [char[]]'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') { $hasS=$true }
        }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($p)
    }
    return ($hasU -and $hasL -and $hasD -and $hasS)
}

# Name-token check using SecureString (minimize string lifetime)
function Test-PasswordAgainstNameSecure {
    param([SecureString]$Sec,[string]$Sam,[string]$DisplayName,[string]$GivenName,[string]$Sn)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Sec)
    $pwd = [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    try {
        if ([string]::IsNullOrWhiteSpace($pwd)) { return $false }
        $pwd = $pwd.ToLowerInvariant()
        $tokens=@()
        foreach($t in @($Sam,$DisplayName,$GivenName,$Sn)){
            if([string]::IsNullOrWhiteSpace($t)){continue}
            $parts=($t -replace '[^A-Za-z0-9]',' ') -split '\s+'
            foreach($p in $parts){ if($p.Length -ge 3){ $tokens+=$p.ToLowerInvariant() } }
        }
        foreach($tok in ($tokens | Select-Object -Unique)){ if($pwd.Contains($tok)){ return $false } }
        return $true
    } finally {
        $pwd = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

# ---------------------------
# LDAP connection using SecureString creds
# ---------------------------
function New-LdapConnection {
    param(
        [string]$server,[int]$port,[bool]$useStartTls,
        [string]$bindUser,
        [Parameter(Mandatory)][SecureString]$bindPwdSec
    )
    $id=New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($server,$port,$false,$false)
    $domainPart=$null; $userPart=$bindUser
    if($bindUser -match '^[^\\]+\\[^\\]+$'){ $parts=$bindUser.Split('\',2); $domainPart=$parts[0]; $userPart=$parts[1] }
    if($domainPart){ $cred=New-Object System.Net.NetworkCredential($userPart,$bindPwdSec,$domainPart) }
    else{ $cred=New-Object System.Net.NetworkCredential($bindUser,$bindPwdSec) }
    $conn=New-Object System.DirectoryServices.Protocols.LdapConnection($id,$cred,[System.DirectoryServices.Protocols.AuthType]::Negotiate)
    $conn.SessionOptions.ProtocolVersion=3
    if($useStartTls){ $conn.SessionOptions.StartTransportLayerSecurity($null) } else { $conn.SessionOptions.SecureSocketLayer=$true }
    $conn.Bind(); $conn
}

# ---------------------------
# LDAP fallback (SecureString version)
# ---------------------------
function Ldap-GetDefaultNamingContext([System.DirectoryServices.Protocols.LdapConnection]$conn){
    $req=New-Object System.DirectoryServices.Protocols.SearchRequest("","(objectClass=*)",[System.DirectoryServices.Protocols.SearchScope]::Base,@("defaultNamingContext"))
    $res=$conn.SendRequest($req)
    if($res.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success){ throw ("RootDSE read failed: {0} {1}" -f $res.ResultCode,$res.ErrorMessage) }
    $res.Entries[0].Attributes["defaultNamingContext"][0]
}

function Ldap-FindUserDN([System.DirectoryServices.Protocols.LdapConnection]$conn,[string]$baseDn,[string]$InputUsername){
    $filter= if($InputUsername -match '@'){ "(userPrincipalName=$InputUsername)" } else { "(sAMAccountName=$InputUsername)" }
    $req=New-Object System.DirectoryServices.Protocols.SearchRequest($baseDn,$filter,[System.DirectoryServices.Protocols.SearchScope]::Subtree,@("distinguishedName"))
    $res=$conn.SendRequest($req)
    if($res.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success){ throw ("Search failed: {0} {1}" -f $res.ResultCode,$res.ErrorMessage) }
    if($res.Entries.Count -lt 1){ throw "Could not locate your account in AD. Check the UPN/sAMAccountName." }
    $res.Entries[0].DistinguishedName
}

function Invoke-PasswordChangeFallbackLDAP {
    param(
        [Parameter(Mandatory)][string]$InputUsername,
        [Parameter(Mandatory)][SecureString]$OldPasswordSec,
        [Parameter(Mandatory)][SecureString]$NewPasswordSec
    )
    $server = Resolve-LdapServerFromUsername -InputUsername $InputUsername
    if (-not $server) {
        return @{ Ok=$false; Summary="Directory lookup failed."; Reason="Could not resolve a Domain Controller."; Server=$null; Code="ResolveDC" }
    }

    $conn = $null
    try {
        if ($PreferStartTLS) {
            try { $conn = New-LdapConnection -server $server -port 389 -useStartTls $true -bindUser $InputUsername -bindPwdSec $OldPasswordSec } catch { $conn = $null }
        }
        if (-not $conn) {
            $conn = New-LdapConnection -server $server -port 636 -useStartTls $false -bindUser $InputUsername -bindPwdSec $OldPasswordSec
        }

        $base   = Ldap-GetDefaultNamingContext -conn $conn
        try {
            $userDn = Ldap-FindUserDN -conn $conn -baseDn $base -InputUsername $InputUsername
        } catch {
            $msg = $_.Exception.Message
            if ($msg -like "*Could not locate your account in AD*") {
                return @{ Ok=$false; Summary="Could not locate your account in AD."; Reason="Check the UPN or sAMAccountName."; Server=$msg; Code="UserNotFound" }
            }
            return @{ Ok=$false; Summary="Directory search failed."; Reason="Unexpected LDAP search error."; Server=$msg; Code="SearchFailed" }
        }

        [byte[]]$oldBytes = Get-QuotedUnicodeBytesFromSecureString $OldPasswordSec
        [byte[]]$newBytes = Get-QuotedUnicodeBytesFromSecureString $NewPasswordSec

        $del = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
        $del.Name = "unicodePwd"; $del.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
        [void]$del.Add([object]$oldBytes)

        $add = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
        $add.Name = "unicodePwd"; $add.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
        [void]$add.Add([object]$newBytes)

        $modReq = New-Object System.DirectoryServices.Protocols.ModifyRequest
        $modReq.DistinguishedName = $userDn
        [void]$modReq.Modifications.Add($del)
        [void]$modReq.Modifications.Add($add)

        $res = $conn.SendRequest($modReq)
        if ($res.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
            $rc = $res.ResultCode.ToString()
            $serverMsg = $res.ErrorMessage

            $friendly = switch ($rc) {
                'InvalidCredentials'   { "Current (old) password is incorrect." }
                'UnwillingToPerform'   { "Rejected by password policy (history or additional password filter)." }
                'ConstraintViolation'  { "Rejected by password policy (history or additional password filter)." }
                default                 { "LDAP change failed ($rc)." }
            }

            $summary = if ($rc -in @('UnwillingToPerform','ConstraintViolation')) {
                "Password too short or violates policy."
            } elseif ($rc -eq 'InvalidCredentials') {
                "Current (old) password is incorrect."
            } else {
                "Password change failed."
            }

            return @{ Ok=$false; Summary=$summary; Reason=$friendly; Server=$serverMsg; Code=$rc }
        }

        return @{ Ok=$true; Summary="Password changed successfully (via LDAP)."; Reason=$null; Server=$null; Code="Success" }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -like "*The supplied credential is invalid*") {
            return @{ Ok=$false; Summary="Current (old) password is incorrect."; Reason="Bind failed with invalid credentials."; Server=$msg; Code="InvalidCredentials" }
        }
        if ($msg -like "*StartTLS*") {
            return @{ Ok=$false; Summary="TLS negotiation failed."; Reason="StartTLS not available or DC certificate not trusted."; Server=$msg; Code="StartTLS" }
        }
        if ($msg -like "*Bind failed*") {
            return @{ Ok=$false; Summary="Directory bind failed."; Reason="Credentials/trust/connectivity."; Server=$msg; Code="BindFailed" }
        }
        return @{ Ok=$false; Summary="Fallback error"; Reason="Unexpected LDAP error."; Server=$msg; Code="Exception" }
    }
    finally {
        if ($conn) { $conn.Dispose() }
    }
}

# ---------------------------
# Reveal helper (PasswordBox <-> TextBox)
# ---------------------------
function Toggle-Reveal-Safe {
    param(
        [Parameter(Mandatory)]$pwd,        # PasswordBox (hidden mode)
        [Parameter(Mandatory)]$pwdReveal   # TextBox (reveal mode)
    )

    if ($pwd.Visibility -eq 'Visible') {
        # Switch to reveal mode
        $pwdReveal.Text = $pwd.Password
        $pwd.Visibility = 'Collapsed'
        $pwdReveal.Visibility = 'Visible'
        $pwdReveal.Focus()
        $pwdReveal.SelectAll()
    }
    else {
        # Switch back to hidden mode
        $pwd.Password = $pwdReveal.Text
        $pwdReveal.Visibility = 'Collapsed'
        $pwd.Visibility = 'Visible'
        $pwd.Focus()
    }
}

# ---------------------------
# Secure NetAPI wrapper (minimize string lifetime)
# ---------------------------
function Invoke-PasswordChangeSecure {
    param(
        [string]$InputUsername,
        [SecureString]$OldPasswordSec,
        [SecureString]$NewPasswordSec
    )

    $oldPtr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($OldPasswordSec)
    $newPtr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($NewPasswordSec)
    try {
        $old = [Runtime.InteropServices.Marshal]::PtrToStringUni($oldPtr)
        $new = [Runtime.InteropServices.Marshal]::PtrToStringUni($newPtr)
        try {
            return Invoke-PasswordChange -InputUsername $InputUsername -OldPassword $old -NewPassword $new
        } finally {
            $old = $null; $new = $null
        }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($oldPtr)
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($newPtr)
    }
}

# ---------------------------
# Common Submit pre-checks (SecureString path) + primary + conditional fallback
# ---------------------------
function Invoke-SubmitWithPrechecksSecure {
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][SecureString]$OldPasswordSec,
        [Parameter(Mandatory)][SecureString]$NewPasswordSec,
        [Parameter(Mandatory)]$CommentBox
    )

    $eff       = Get-EffectivePasswordPolicy -InputUsername $Username
    $minLenEff = if ($eff.Policy.MinLength) { [int]$eff.Policy.MinLength } else { 14 }
    $complex   = [bool]$eff.Policy.Complexity
    $hist      = $eff.Policy.History
    $minAge    = $eff.Policy.MinPwdAge
    $minAgeStr = if ($minAge) { "{0} hours" -f [math]::Round($minAge.TotalHours) } else { "N/A" }

    # Account lockout
    if ($eff.User -and (Test-AccountLockout -UserInfo $eff.User)) {
        Show-Message -Box $CommentBox -Kind warn `
            -Summary "Account is locked." `
            -Reason  "Too many failed sign-in attempts. Please wait or contact IT to unlock your account."
        return
    }

    if (-not (Test-PasswordComplexitySecure -Sec $NewPasswordSec -Min $minLenEff)) {
        Show-Message -Box $CommentBox -Kind warn -Summary "Password does not meet complexity requirements."
        return
    }

    if ($complex -and $eff.User) {
        if (-not (Test-PasswordAgainstNameSecure `
            -Sec $NewPasswordSec `
            -Sam $eff.User.sAM `
            -DisplayName $eff.User.displayName `
            -GivenName $eff.User.givenName `
            -Sn $eff.User.sn)) {
            Show-Message -Box $CommentBox -Kind warn -Summary "Password contains part of your name or username."
            return
        }
    }

    if ($eff.NextAllowed -and (Get-Date) -lt $eff.NextAllowed) {
        $wait = $eff.NextAllowed - (Get-Date)
        Show-Message -Box $CommentBox -Kind warn `
            -Summary "Password cannot be changed yet." `
            -Reason  ("Minimum password age policy applies. Wait {0}h {1}m." -f $wait.Hours,$wait.Minutes)
        return
    }

    $policySummary = "Password Policy — Length: $minLenEff | Complexity: $complex | History: $hist | MinAge: 24 Hours"

    # ---------- PRIMARY (NetAPI) ----------
    $res = Invoke-PasswordChangeSecure -InputUsername $Username -OldPasswordSec $OldPasswordSec -NewPasswordSec $NewPasswordSec

    if ($res.Ok) {
        Show-Message -Box $CommentBox -Kind success -Summary $res.Message
        return 'OK'
    }

    $netApiConfirmedUser = ($res.Code -notin @(1325,2221))

    # Do NOT fallback for policy failures
    if ($res.Code -in 1323,2245) {
        Show-Message -Box $CommentBox -Kind warn `
            -Summary "Password rejected by policy." `
            -Reason  "History, complexity, or minimum age rule." `
            -Policy  $policySummary
        return
    }

    # Recently changed password → stop here
    if (Was-RecentlyChanged -EffectiveInfo $eff -Minutes 5) {
        Show-Message -Box $CommentBox -Kind warn `
            -Summary "Password was changed recently." `
            -Reason  "Active Directory replication is still in progress. Please wait a few minutes." `
            -Policy  $policySummary
        return
    }

    if (-not $EnableLdapFallback) {
        Show-Message -Box $CommentBox -Kind error `
            -Summary "Password change failed." `
            -Reason  $res.Message `
            -System  $res.System
        return
    }

    # ---------- FALLBACK (LDAP) ----------
    $fb = Invoke-PasswordChangeFallbackLDAP -InputUsername $Username -OldPasswordSec $OldPasswordSec -NewPasswordSec $NewPasswordSec

    if ($fb.Ok) {
        Show-Message -Box $CommentBox -Kind success -Summary $fb.Summary
        return 'OK'
    }

    switch ($fb.Code) {
        'UserNotFound' {
            if ($netApiConfirmedUser) {
                Show-Message -Box $CommentBox -Kind warn `
                    -Summary "Password was changed recently." `
                    -Reason  "Directory replication delay detected." `
                    -Policy  $policySummary
            }
            else {
                Show-Message -Box $CommentBox -Kind error `
                    -Summary "Could not locate your account in AD." `
                    -Reason  "Check the UPN or sAMAccountName."
            }
        }
        'InvalidCredentials' {
            Show-Message -Box $CommentBox -Kind error -Summary "Current password is incorrect."
        }
        default {
            Show-Message -Box $CommentBox -Kind error `
                -Summary "Password change failed." `
                -Reason  $fb.Reason `
                -Server  $fb.Server `
                -System  $res.System
        }
    }
}

# ---------------------------------------
# Child dialog: Generate (2 buttons: Generate | Submit)
# ---------------------------------------
function Show-GenerateDialog {
    param($OwnerWindow,[string]$Username,$CommentBox)

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Generate Password"
        Width="270" Height="320" MinWidth="270" MinHeight="320"
        WindowStartupLocation="CenterOwner"
        Background="$($Theme.Bg)" ResizeMode="NoResize"
        SnapsToDevicePixels="True" UseLayoutRounding="True"
        ShowInTaskbar="False">
  <Window.Resources>
    <SolidColorBrush x:Key="Card"  Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text"  Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <Style TargetType="TextBlock" x:Key="Lbl"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="FontSize" Value="12"/><Setter Property="Margin" Value="0,6,0,2"/></Style>
    <Style TargetType="TextBox" x:Key="Txt"><Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="#3A424B"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,2"/><Setter Property="FontSize" Value="12"/><Setter Property="Height" Value="24"/></Style>
    <Style TargetType="PasswordBox" x:Key="Pwd"><Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="#3A424B"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,2"/><Setter Property="FontSize" Value="12"/><Setter Property="Height" Value="24"/></Style>
    <Style TargetType="Button" x:Key="Primary"><Setter Property="Background" Value="$($Theme.Accent)"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="8,4"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Height" Value="26"/></Style>
    <Style TargetType="Button" x:Key="Secondary"><Setter Property="Background" Value="{StaticResource Card}"/><Setter Property="Foreground" Value="{StaticResource Accent}"/><Setter Property="BorderBrush" Value="{StaticResource Accent}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="8,4"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Height" Value="26"/></Style>
  </Window.Resources>

  <Grid Margin="8">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>

    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="6" Padding="6" Margin="0,0,0,6">
      <StackPanel>
        <TextBlock Text="Generate Password" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13"/>
        <TextBlock Text="$Username" Foreground="{StaticResource Muted}" FontSize="11"/>
      </StackPanel>
    </Border>

    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="6" Padding="8">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Current password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="1">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="26"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="pwdOld" Visibility="Visible" Style="{StaticResource Pwd}" />
            <TextBox     x:Name="pwdOldReveal" Visibility="Collapsed" Style="{StaticResource Txt}" FontFamily="Consolas" />
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealOld" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1"/>
        </Grid>

        <TextBlock Grid.Row="2" Text="New password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="26"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="pwdNew" Visibility="Visible" Style="{StaticResource Pwd}" />
            <TextBox     x:Name="pwdNewReveal" Visibility="Collapsed" Style="{StaticResource Txt}" FontFamily="Consolas" />
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealNew" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1"/>
        </Grid>

        <TextBlock Grid.Row="4" Text="Confirm password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="5">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="26"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="pwdConfirm" Visibility="Visible" Style="{StaticResource Pwd}" />
            <TextBox     x:Name="pwdConfirmReveal" Visibility="Collapsed" Style="{StaticResource Txt}" FontFamily="Consolas" />
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealConfirm" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1"/>
        </Grid>
      </Grid>
    </Border>

    <Grid Grid.Row="2" Margin="0,6,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Button x:Name="btnGenerate" Grid.Column="0" Style="{StaticResource Secondary}" Content="Generate"/>
      <Button x:Name="btnSubmit"   Grid.Column="1" Style="{StaticResource Primary}"   Content="Submit" Margin="6,0,0,0"/>
    </Grid>
  </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $win = [Windows.Markup.XamlReader]::Load($reader)
    function F([string]$n){ $win.FindName($n) }

    $pwdOld=F 'pwdOld'; $pwdOldReveal=F 'pwdOldReveal'; $btnRevealOld=F 'btnRevealOld'
    $pwdNew=F 'pwdNew'; $pwdNewReveal=F 'pwdNewReveal'; $btnRevealNew=F 'btnRevealNew'
    $pwdConfirm=F 'pwdConfirm'; $pwdConfirmReveal=F 'pwdConfirmReveal'; $btnRevealConfirm=F 'btnRevealConfirm'
    $btnGenerate=F 'btnGenerate'; $btnSubmit=F 'btnSubmit'
    $win.Owner=$OwnerWindow

    # Stop/clear any running timers when dialog closes
    $win.Add_Closed({
        try {
            foreach ($kv in $script:RevealTimers.GetEnumerator()) { try { $kv.Value.Stop() } catch {} }
            $script:RevealTimers.Clear()
        } catch {}
    })

    # Make reveal fields display-only (reduce exfil risk)
    $pwdOldReveal.IsReadOnly = $true;      $pwdOldReveal.IsHitTestVisible = $false
    $pwdNewReveal.IsReadOnly = $true;      $pwdNewReveal.IsHitTestVisible = $false
    $pwdConfirmReveal.IsReadOnly = $true;  $pwdConfirmReveal.IsHitTestVisible = $false

    $btnRevealOld.Add_Click({
        Toggle-Reveal-Safe -pwd $pwdOld -pwdReveal $pwdOldReveal
        $btnRevealOld.Content = if ($pwdOld.Visibility -eq 'Visible') { '👁' } else { '🙈' }
        if ($pwdOldReveal.Visibility -eq 'Visible') {
            Start-RevealAutoHideTimer -Pwd $pwdOld -PwdReveal $pwdOldReveal -Btn $btnRevealOld -Seconds 5
        }
    })
    $btnRevealNew.Add_Click({
        Toggle-Reveal-Safe -pwd $pwdNew -pwdReveal $pwdNewReveal
        $btnRevealNew.Content = if ($pwdNew.Visibility -eq 'Visible') { '👁' } else { '🙈' }
        if ($pwdNewReveal.Visibility -eq 'Visible') {
            Start-RevealAutoHideTimer -Pwd $pwdNew -PwdReveal $pwdNewReveal -Btn $btnRevealNew -Seconds 5
        }
    })
    $btnRevealConfirm.Add_Click({
        Toggle-Reveal-Safe -pwd $pwdConfirm -pwdReveal $pwdConfirmReveal
        $btnRevealConfirm.Content = if ($pwdConfirm.Visibility -eq 'Visible') { '👁' } else { '🙈' }
        if ($pwdConfirmReveal.Visibility -eq 'Visible') {
            Start-RevealAutoHideTimer -Pwd $pwdConfirm -PwdReveal $pwdConfirmReveal -Btn $btnRevealConfirm -Seconds 5
        }
    })

    # Optional: auto-hide if dialog loses focus (extra safety)
    $win.Add_Deactivated({
        foreach ($triple in @(
            @($pwdOld,$pwdOldReveal,$btnRevealOld),
            @($pwdNew,$pwdNewReveal,$btnRevealNew),
            @($pwdConfirm,$pwdConfirmReveal,$btnRevealConfirm)
        )) {
            $p = $triple[0]; $r = $triple[1]; $b = $triple[2]
            if ($r -and $r.Visibility -eq 'Visible') {
                try { Toggle-Reveal-Safe -pwd $p -pwdReveal $r } catch {}
                try { if ($b) { $b.Content = '👁' } } catch {}
            }
        }
    })

    $btnGenerate.Add_Click({
        $eff=Get-EffectivePasswordPolicy -InputUsername $Username
        $minLenEff= if($eff.Policy -and $eff.Policy.MinLength){[int]$eff.Policy.MinLength}else{$MinLengthDefault}
        $gen=New-StrongPassword -Length $minLenEff -NoLookAlikes:$AvoidLookAlikes

        if ($pwdNew.Visibility -eq 'Visible') { $pwdNew.Password = $gen } else { $pwdNewReveal.Text = $gen }
        if ($pwdConfirm.Visibility -eq 'Visible') { $pwdConfirm.Password = $gen } else { $pwdConfirmReveal.Text = $gen }

        Set-Comment -Box $CommentBox -Kind info -Text ("Generated strong password for [{0}]" -f $Username)
    })

    $btnSubmit.Add_Click({
        # Read SecureStrings from PasswordBoxes (reveal boxes are display-only)
        $oldSec = $pwdOld.SecurePassword
        $newSec = $pwdNew.SecurePassword
        $cfmSec = $pwdConfirm.SecurePassword

        if ($oldSec.Length -eq 0) { Set-Comment -Box $CommentBox -Kind warn -Text "Enter current password."; return }
        if ($newSec.Length -eq 0) { Set-Comment -Box $CommentBox -Kind warn -Text "Enter new password."; return }
        if (-not (Compare-SecureString -A $newSec -B $cfmSec)) { Set-Comment -Box $CommentBox -Kind warn -Text "New password and confirmation do not match."; return }
        if (Compare-SecureString -A $newSec -B $oldSec) { Set-Comment -Box $CommentBox -Kind warn -Text "New password must differ from current password."; return }

        $ok=Invoke-SubmitWithPrechecksSecure -Username $Username -OldPasswordSec $oldSec -NewPasswordSec $newSec -CommentBox $CommentBox
        if($ok -eq 'OK'){ $win.Close() }

        # Clear only the controls
        $pwdOld.Clear(); $pwdNew.Clear(); $pwdConfirm.Clear()
        $oldSec=$null; $newSec=$null; $cfmSec=$null
    })

    $win.Add_KeyDown({
        param($s,$e)
        if($e.KeyboardDevice.Modifiers -band [Windows.Input.ModifierKeys]::Control -and $e.Key -eq 'G'){
            $btnGenerate.RaiseEvent( (New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)) )
        }
        if($e.Key -eq 'Return'){ $btnSubmit.RaiseEvent( (New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)) ) }
        if($e.Key -eq 'Escape'){ $win.Close() }
    })

    [void]$win.ShowDialog()
}

# ---------------------------------------
# Child dialog: Change (Submit + Cancel)
# ---------------------------------------
function Show-ChangeDialog {
    param($OwnerWindow,[string]$Username,$CommentBox)

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Change Password"
        Width="270" Height="320" MinWidth="270" MinHeight="320"
        WindowStartupLocation="CenterOwner"
        Background="$($Theme.Bg)" ResizeMode="NoResize"
        SnapsToDevicePixels="True" UseLayoutRounding="True"
        ShowInTaskbar="False">
  <Window.Resources>
    <SolidColorBrush x:Key="Card"  Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text"  Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <Style TargetType="TextBlock" x:Key="Lbl"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="FontSize" Value="12"/><Setter Property="Margin" Value="0,6,0,2"/></Style>
    <Style TargetType="TextBox" x:Key="Txt"><Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="#3A424B"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,2"/><Setter Property="FontSize" Value="12"/><Setter Property="Height" Value="24"/></Style>
    <Style TargetType="PasswordBox" x:Key="Pwd"><Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="#3A424B"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,2"/><Setter Property="FontSize" Value="12"/><Setter Property="Height" Value="24"/></Style>
    <Style TargetType="Button" x:Key="Primary"><Setter Property="Background" Value="$($Theme.Accent)"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="8,4"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Height" Value="26"/></Style>
    <Style TargetType="Button" x:Key="Secondary"><Setter Property="Background" Value="{StaticResource Card}"/><Setter Property="Foreground" Value="{StaticResource Accent}"/><Setter Property="BorderBrush" Value="{StaticResource Accent}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="8,4"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Height" Value="26"/></Style>
  </Window.Resources>

  <Grid Margin="8">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>

    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="6" Padding="6" Margin="0,0,0,6">
      <StackPanel>
        <TextBlock Text="Change Password" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13"/>
        <TextBlock Text="$Username" Foreground="{StaticResource Muted}" FontSize="11"/>
      </StackPanel>
    </Border>

    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="6" Padding="8">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/><RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Current password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="1">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="26"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="pwdOld" Visibility="Visible" Style="{StaticResource Pwd}" />
            <TextBox     x:Name="pwdOldReveal" Visibility="Collapsed" Style="{StaticResource Txt}" FontFamily="Consolas" />
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealOld" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1"/>
        </Grid>

        <TextBlock Grid.Row="2" Text="New password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="26"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="pwdNew" Visibility="Visible" Style="{StaticResource Pwd}" />
            <TextBox     x:Name="pwdNewReveal" Visibility="Collapsed" Style="{StaticResource Txt}" FontFamily="Consolas" />
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealNew" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1"/>
        </Grid>

        <TextBlock Grid.Row="4" Text="Confirm password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="5">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="26"/></Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <PasswordBox x:Name="pwdConfirm" Visibility="Visible" Style="{StaticResource Pwd}" />
            <TextBox     x:Name="pwdConfirmReveal" Visibility="Collapsed" Style="{StaticResource Txt}" FontFamily="Consolas" />
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealConfirm" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1"/>
        </Grid>
      </Grid>
    </Border>

    <Grid Grid.Row="2" Margin="0,6,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Button x:Name="btnCancel" Grid.Column="0" Style="{StaticResource Secondary}" Content="Cancel"/>
      <Button x:Name="btnSubmit" Grid.Column="1" Style="{StaticResource Primary}"   Content="Submit" Margin="6,0,0,0"/>
    </Grid>
  </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $win = [Windows.Markup.XamlReader]::Load($reader)
    function F([string]$n){ $win.FindName($n) }

    $pwdOld=F 'pwdOld'; $pwdOldReveal=F 'pwdOldReveal'; $btnRevealOld=F 'btnRevealOld'
    $pwdNew=F 'pwdNew'; $pwdNewReveal=F 'pwdNewReveal'; $btnRevealNew=F 'btnRevealNew'
    $pwdConfirm=F 'pwdConfirm'; $pwdConfirmReveal=F 'pwdConfirmReveal'; $btnRevealConfirm=F 'btnRevealConfirm'
    $btnSubmit = F 'btnSubmit'
    $btnCancel = F 'btnCancel'
    $win.Owner = $OwnerWindow

    # Stop/clear any running timers when dialog closes
    $win.Add_Closed({
        try {
            foreach ($kv in $script:RevealTimers.GetEnumerator()) { try { $kv.Value.Stop() } catch {} }
            $script:RevealTimers.Clear()
        } catch {}
    })

    # Reveal textboxes as display-only
    $pwdOldReveal.IsReadOnly = $true;      $pwdOldReveal.IsHitTestVisible = $false
    $pwdNewReveal.IsReadOnly = $true;      $pwdNewReveal.IsHitTestVisible = $false
    $pwdConfirmReveal.IsReadOnly = $true;  $pwdConfirmReveal.IsHitTestVisible = $false

    $btnRevealOld.Add_Click({
        Toggle-Reveal-Safe -pwd $pwdOld -pwdReveal $pwdOldReveal
        $btnRevealOld.Content = if ($pwdOld.Visibility -eq 'Visible') { '👁' } else { '🙈' }
        if ($pwdOldReveal.Visibility -eq 'Visible') {
            Start-RevealAutoHideTimer -Pwd $pwdOld -PwdReveal $pwdOldReveal -Btn $btnRevealOld -Seconds 5
        }
    })
    $btnRevealNew.Add_Click({
        Toggle-Reveal-Safe -pwd $pwdNew -pwdReveal $pwdNewReveal
        $btnRevealNew.Content = if ($pwdNew.Visibility -eq 'Visible') { '👁' } else { '🙈' }
        if ($pwdNewReveal.Visibility -eq 'Visible') {
            Start-RevealAutoHideTimer -Pwd $pwdNew -PwdReveal $pwdNewReveal -Btn $btnRevealNew -Seconds 5
        }
    })
    $btnRevealConfirm.Add_Click({
        Toggle-Reveal-Safe -pwd $pwdConfirm -pwdReveal $pwdConfirmReveal
        $btnRevealConfirm.Content = if ($pwdConfirm.Visibility -eq 'Visible') { '👁' } else { '🙈' }
        if ($pwdConfirmReveal.Visibility -eq 'Visible') {
            Start-RevealAutoHideTimer -Pwd $pwdConfirm -PwdReveal $pwdConfirmReveal -Btn $btnRevealConfirm -Seconds 5
        }
    })

    # Optional: auto-hide on deactivation
    $win.Add_Deactivated({
        foreach ($triple in @(
            @($pwdOld,$pwdOldReveal,$btnRevealOld),
            @($pwdNew,$pwdNewReveal,$btnRevealNew),
            @($pwdConfirm,$pwdConfirmReveal,$btnRevealConfirm)
        )) {
            $p = $triple[0]; $r = $triple[1]; $b = $triple[2]
            if ($r -and $r.Visibility -eq 'Visible') {
                try { Toggle-Reveal-Safe -pwd $p -pwdReveal $r } catch {}
                try { if ($b) { $b.Content = '👁' } } catch {}
            }
        }
    })

    $btnSubmit.Add_Click({
        $oldSec = $pwdOld.SecurePassword
        $newSec = $pwdNew.SecurePassword
        $cfmSec = $pwdConfirm.SecurePassword

        if ($oldSec.Length -eq 0) { Set-Comment -Box $CommentBox -Kind warn -Text "Enter current password."; return }
        if ($newSec.Length -eq 0) { Set-Comment -Box $CommentBox -Kind warn -Text "Enter new password."; return }
        if (-not (Compare-SecureString -A $newSec -B $cfmSec)) { Set-Comment -Box $CommentBox -Kind warn -Text "New password and confirmation do not match."; return }
        if (Compare-SecureString -A $newSec -B $oldSec) { Set-Comment -Box $CommentBox -Kind warn -Text "New password must differ from current password."; return }

        $ok = Invoke-SubmitWithPrechecksSecure -Username $Username -OldPasswordSec $oldSec -NewPasswordSec $newSec -CommentBox $CommentBox
        if ($ok -eq 'OK') { $win.Close() }

        $pwdOld.Clear(); $pwdNew.Clear(); $pwdConfirm.Clear()
        $oldSec=$null; $newSec=$null; $cfmSec=$null
    })

    $btnCancel.Add_Click({ $win.Close() })

    $win.Add_KeyDown({
        param($s,$e)
        if($e.Key -eq 'Escape'){ $win.Close() }
        if($e.Key -eq 'Return'){
            $btnSubmit.RaiseEvent(
                (New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))
            )
        }
    })

    [void]$win.ShowDialog()
}

# ------------------------
# Main window (3x4)
# ------------------------
[xml]$mainXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Self Password Reset"
        Width="288" Height="384" MinWidth="288" MinHeight="384"
        WindowStartupLocation="CenterScreen"
        Background="$($Theme.Bg)"
        ResizeMode="NoResize"
        SnapsToDevicePixels="True" UseLayoutRounding="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Card"  Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text"  Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <Style TargetType="TextBlock" x:Key="Lbl"><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="FontSize" Value="12"/><Setter Property="Margin" Value="0,6,0,2"/><Setter Property="TextWrapping" Value="Wrap"/></Style>
    <Style TargetType="TextBox" x:Key="Txt"><Setter Property="Background" Value="{StaticResource Field}"/><Setter Property="Foreground" Value="{StaticResource Text}"/><Setter Property="BorderBrush" Value="#3A424B"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="6,2"/><Setter Property="FontSize" Value="12"/><Setter Property="Height" Value="24"/><Setter Property="HorizontalAlignment" Value="Stretch"/></Style>
    <Style TargetType="Button" x:Key="Primary"><Setter Property="Background" Value="$($Theme.Accent)"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="8,4"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Height" Value="26"/></Style>
    <Style TargetType="Button" x:Key="Secondary"><Setter Property="Background" Value="{StaticResource Card}"/><Setter Property="Foreground" Value="{StaticResource Accent}"/><Setter Property="BorderBrush" Value="{StaticResource Accent}"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="8,4"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Height" Value="26"/></Style>
  </Window.Resources>

  <Grid Margin="6">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>

    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="6" Padding="8" Margin="0,0,0,6">
      <TextBlock Text="Self Password Reset" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13"/>
    </Border>

    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="6" Padding="8">
      <Grid>
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="User Name:" Style="{StaticResource Lbl}"/>
        <TextBox   Grid.Row="1" x:Name="txtUser" Style="{StaticResource Txt}"/>

        <Grid Grid.Row="2" Margin="0,10,0,0">
          <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <Button x:Name="btnGenerate" Grid.Column="0" Style="{StaticResource Secondary}" Content="Generate Password"/>
          <Button x:Name="btnChange"   Grid.Column="1" Style="{StaticResource Primary}"   Content="Change Password" Margin="6,0,0,0"/>
        </Grid>

        <Grid Grid.Row="3" Margin="0,10,0,0">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Comment:" Style="{StaticResource Lbl}" Margin="0,0,0,2"/>
          <Border Grid.Row="1" Background="{StaticResource Field}" CornerRadius="4" Padding="4">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <TextBlock x:Name="txtComment" Text="Ready." Foreground="{StaticResource Text}" TextWrapping="Wrap"/>
            </ScrollViewer>
          </Border>
        </Grid>
      </Grid>
    </Border>

    <Border Grid.Row="2" Background="{StaticResource Card}" CornerRadius="6" Padding="6" Margin="0,6,0,0">
      <TextBlock Text="Tips: Enter = Change • Esc = Close" Foreground="{StaticResource Muted}" FontSize="11"/>
    </Border>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $mainXaml
$main = [Windows.Markup.XamlReader]::Load($reader)
function M([string]$n) { $main.FindName($n) }

$txtUser     = M 'txtUser'
$btnGenerate = M 'btnGenerate'
$btnChange   = M 'btnChange'
$txtComment  = M 'txtComment'

# Pre-fill username
if ($env:USERDOMAIN -and $env:USERNAME) {
    $txtUser.Text = "$($env:USERDOMAIN)\$($env:USERNAME)"
} else {
    $txtUser.Text = ""
}

# Window keys
$main.Add_KeyDown({
    param($s, $e)
    if ($e.Key -eq 'Escape') { $main.Close() }
    if ($e.Key -eq 'Return') {
        $btnChange.RaiseEvent(
            (New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
    }
})

# Generate button
$btnGenerate.Add_Click({
    $u = $txtUser.Text.Trim()
    if (-not $u) {
        Set-Comment -Box $txtComment -Kind warn -Text "Please enter a username first."
        return
    }
    Show-GenerateDialog -OwnerWindow $main -Username $u -CommentBox $txtComment
})

# Change button
$btnChange.Add_Click({
    $u = $txtUser.Text.Trim()
    if (-not $u) {
        Set-Comment -Box $txtComment -Kind warn -Text "Please enter a username first."
        return
    }
    Show-ChangeDialog -OwnerWindow $main -Username $u -CommentBox $txtComment
})

[void]$main.ShowDialog()

