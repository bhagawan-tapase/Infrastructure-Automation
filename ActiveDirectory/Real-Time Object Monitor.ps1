
<# 
  Real-time Account monitor:
    1) User Account Status: Created (4720), Enabled (4722), Disabled (4725), Deleted (4726)
    2) Computer Account Status: Created (4741), Deleted (4743); Enabled/Disabled via 4722/4725
    3) Group Membership: Added/Removed (4728,4729,4732,4733,4756,4757)

#>

param(
  [switch]$Force,
  [switch]$ForceExitOld,
  [int]$PollIntervalSec = 5,
  [switch]$Diag,
  [int]$InitialLookbackMinutes = 5,
  [switch]$NoSuppressInitialEnable,
  [int]$WindowOverlapSec = 5,
  [switch]$NoDedup,
  [string[]]$RWDC,
  [int]$HeartbeatMinutes = 0,
  [switch]$HeartbeatEmail,
  [int]$RateLimitMinGapSec = 0,
  [switch]$UseUtcWindows = $false,
  [switch]$SuppressNoEventLog = $true
)

# =========================
# === Email settings ===
# =========================

#region --- ACCOUNT watcher email settings ---
$ASmtpServer      = 'YourRelayServer'
$ASmtpPort        = 25
$AUseSsl          = $false

$AFrom            = 'noreply@yourdomain.com'
$AFromDisplayName = 'Account Status Monitor'
$ATo              = 'admin@yourdomain.com'
$ACc              = 'dl-admin@yourdomain.com'
$ABcc             = ''   # comma-separated BCC addresses for Account alerts
$ASubjectDefault  = 'Real-time Alert: Account Status'

$ASmtpUser = ''
$ASmtpPass = ''
$ACredential = if ($ASmtpUser -and $ASmtpPass) {
  New-Object System.Management.Automation.PSCredential(
    $ASmtpUser,(ConvertTo-SecureString $ASmtpPass -AsPlainText -Force)
  )
} else { $null }
#endregion

#region --- GROUP watcher email settings ---
$GSmtpServer      = 'YourRelayServer'
$GSmtpPort        = 25
$GUseSsl          = $false

$GFrom            = 'noreply@yourdomain.com'
$GFromDisplayName = 'AD Group Monitor'
$GTo              = 'admin@yourdomain.com'
$GCc              = 'dl-admin@yourdomain.com'
$GBcc             = ''   # comma-separated BCC addresses for Group alerts
$GSubjectPrefix   = 'Group Membership Changed - '

$GSmtpUser = ''
$GSmtpPass = ''
$GCredential = if ($GSmtpUser -and $GSmtpPass) {
  New-Object System.Management.Automation.PSCredential(
    $GSmtpUser,(ConvertTo-SecureString $GSmtpPass -AsPlainText -Force)
  )
} else { $null }
#endregion

# =========================
# === Logging (INFO-only) ===
# =========================
$LogDir   = 'C:\Logs'
$GLogFile = Join-Path $LogDir 'GroupMembershipWatcher-Central.log'
$ALogFile = Join-Path $LogDir 'AccountStatusWatcher-Central.log'

try {
  if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
  if (-not (Test-Path $ALogFile)) { New-Item -Path $ALogFile -ItemType File -Force | Out-Null }
  if (-not (Test-Path $GLogFile)) { New-Item -Path $GLogFile -ItemType File -Force | Out-Null }
} catch { } # suppressed

function Rotate-LogIfLarge([string]$path,[int]$maxKB=4096) {
  try {
    if (Test-Path $path) {
      $sizeKB = (Get-Item $path).Length / 1KB
      if ($sizeKB -ge $maxKB) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        Move-Item -Path $path -Destination "$path.$stamp" -Force
        New-Item -Path $path -ItemType File -Force | Out-Null
      }
    }
  } catch { } # suppressed
}
function Write-LogA([string]$msg,[string]$level='INFO') {
  if ($level -ne 'INFO') { return }  # old behavior
  Rotate-LogIfLarge -path $ALogFile
  $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  Add-Content -Path $ALogFile -Value "[$stamp][INFO] $msg"
}
function Write-LogG([string]$msg,[string]$level='INFO') {
  if ($level -ne 'INFO') { return }  # old behavior
  Rotate-LogIfLarge -path $GLogFile
  $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  Add-Content -Path $GLogFile -Value "[$stamp][INFO] $msg"
}

# =========================
# === Force-exit old instances ===
# =========================
if ($ForceExitOld) {
  try {
    $patterns = @(
      'AccountMonitor.ps1','Real-time Account monitor.ps1','AccountStatusWatcher','GroupMembershipWatcher' 
    )
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(pwsh|powershell)(\.exe)?$' }
    $currentPid = $PID
    $targets = @()
    foreach ($p in $procs) {
      $cmd = $p.CommandLine
      if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
      foreach ($pat in $patterns) {
        if ($cmd -match [regex]::Escape($pat)) { if ($p.ProcessId -ne $currentPid) { $targets += $p; break } }
      }
    }
    foreach ($p in $targets) { 
      try { 
        Write-LogA ("ForceExitOld: stopping PID {0} CMD={1}" -f $p.ProcessId, $p.CommandLine)
        Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop 
      } catch { Write-LogA ("ForceExitOld: failed stopping PID {0}: {1}" -f $p.ProcessId, $_.Exception.Message) } 
    }
  } catch { Write-LogA ("ForceExitOld: unexpected failure: {0}" -f $_.Exception.Message) }
}

# =========================
# === Single-instance guard ===
# =========================
if (-not $Force) {
  $globalMutexName = 'Global\UnifiedDirectoryMonitorMutex'
  try {
    $mutex = New-Object System.Threading.Mutex($false, $globalMutexName)
    $got = $false
    try { $got = $mutex.WaitOne(0, $false) }
    catch [System.Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) { Write-LogA "Another instance is running; exiting."; return }
    Register-EngineEvent PowerShell.Exiting -Action {
      try { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } } catch {}
    } | Out-Null
  } catch { Write-LogA ("Mutex init failed; exiting. {0}" -f $_.Exception.Message); return }
}

# =========================
# === AD Module (lazy) ===
# =========================
$AdAvailable = $false
function Ensure-AdModule {
  if (-not $AdAvailable) {
    try { Import-Module ActiveDirectory -ErrorAction Stop; $AdAvailable = $true } catch { Write-LogA ("ActiveDirectory module import failed: {0}" -f $_.Exception.Message) }
  }
}

# =========================
# === Helpers ===
# =========================
function Split-Recipients([string]$csv) {
  if ([string]::IsNullOrWhiteSpace($csv)) { return @() }
  return $csv.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}
function HtmlEncode([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return '' }
  try { return [System.Web.HttpUtility]::HtmlEncode($s) } catch {
    ($s -replace '&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
  }
}
function Escape-LdapFilterValue([string]$value) {
  if ($null -eq $value) { return '' }
  $value = $value -replace '\\', '\5c'
  $value = $value -replace '\*', '\2a'
  $value = $value -replace '\(', '\28'
  $value = $value -replace '\)', '\29'
  $value = $value -replace ([char]0), '\00'
  return $value
}
function New-SmtpClient {
  param([string]$Server,[int]$Port,[bool]$UseSsl,[System.Management.Automation.PSCredential]$Cred,[bool]$UseDefault=$false)
  $client = New-Object System.Net.Mail.SmtpClient($Server, $Port)
  $client.EnableSsl = $UseSsl
  if ($Cred) {
    $client.Credentials = New-Object System.Net.NetworkCredential($Cred.UserName, $Cred.GetNetworkCredential().Password)
    $client.UseDefaultCredentials = $false
  } elseif ($UseDefault) { $client.UseDefaultCredentials = $true } else { $client.UseDefaultCredentials = $false }
  $client.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
  $client.Timeout = 15000
  return $client
}

function Get-StatusPill {
  param(
    [Parameter(Mandatory=$true)][string]$Status,
    [ValidateSet('Account','Group')] [string]$Context = 'Account'
  )
  # Colors chosen for clarity and good contrast in Outlook clients
  switch ($Context) {
    'Account' {
      switch ($Status.ToLower()) {
        'created'  { $bg = '#e0f2fe'; $bd = '#93c5fd'; $fg = '#0c4a6e' }   # blue
        'enabled'  { $bg = '#dcfce7'; $bd = '#86efac'; $fg = '#065f46' }   # green
        'disabled' { $bg = '#fee2e2'; $bd = '#fca5a5'; $fg = '#7f1d1d' }   # red
        'deleted'  { $bg = '#f3f4f6'; $bd = '#e5e7eb'; $fg = '#374151' }   # gray
        default    { $bg = '#f3f4f6'; $bd = '#e5e7eb'; $fg = '#374151' }
      }
    }
    'Group' {
      switch ($Status.ToLower()) {
        'added'    { $bg = '#dcfce7'; $bd = '#86efac'; $fg = '#065f46' }   # green
        'removed'  { $bg = '#fee2e2'; $bd = '#fca5a5'; $fg = '#7f1d1d' }   # red
        'updated'  { $bg = '#fef3c7'; $bd = '#fde68a'; $fg = '#78350f' }   # amber
        default    { $bg = '#f3f4f6'; $bd = '#e5e7eb'; $fg = '#374151' }
      }
    }
  }

  # Use inline styles (Outlook-friendly), pill shape with strong contrast
  $pill = "<span style='display:inline-block;padding:2px 10px;border-radius:9999px;border:1px solid $bd;background:$bg;color:$fg;font-size:12px;font-weight:600;line-height:1;'>$Status</span>"
  return $pill
}

function Invoke-WithRetry([scriptblock]$Action,[int]$Max=3,[int]$DelayMs=750) {
  for ($i=1; $i -le $Max; $i++) { try { & $Action; return } catch { if ($i -eq $Max) { throw }; Start-Sleep -Milliseconds $DelayMs } }
}
function Get-EventFieldValue {
  param([Parameter(Mandatory=$true)] $XmlData,[Parameter(Mandatory=$true)][string[]] $Names)
  foreach ($n in $Names) { $v = ($XmlData | Where-Object { $_.Name -eq $n }).'#text'; if ($null -ne $v -and $v -ne '') { return $v } }
  return $null
}

# =========================
# === Persistent de-dup (both watchers) ===
# =========================
$BookmarkDir = 'C:\Logs\Bookmarks'
try { if (-not (Test-Path $BookmarkDir)) { New-Item -Path $BookmarkDir -ItemType Directory -Force | Out-Null } } catch { }

$script:ASeenCacheFile = Join-Path $BookmarkDir 'AccountSeenEventKeys.json'
$script:ASeenEventKeys = @()
if (Test-Path $script:ASeenCacheFile) { try { $script:ASeenEventKeys = (Get-Content -Path $script:ASeenCacheFile -ErrorAction Stop | ConvertFrom-Json) } catch { $script:ASeenEventKeys = @() } }
function Make-AccountEventKey([string]$Dc,[int]$RecordId,[int]$EventId) { "{0}|{1}|{2}" -f $Dc,$RecordId,$EventId }
function Persist-AccountSeenKeys([string[]]$keys,[int]$maxKeep=10000) { try { ($keys | Select-Object -Last $maxKeep) | ConvertTo-Json | Set-Content -Path $script:ASeenCacheFile -Force } catch { } }

$script:GSeenCacheFile = Join-Path $BookmarkDir 'GroupSeenEventKeys.json'
$script:SeenEventKeysG = @()
if (Test-Path $script:GSeenCacheFile) { try { $script:SeenEventKeysG = (Get-Content -Path $script:GSeenCacheFile -ErrorAction Stop | ConvertFrom-Json) } catch { $script:SeenEventKeysG = @() } }
function Make-GroupEventKey([int]$RecordId,[int]$EventId,[string]$Group,[string]$Dc) { "{0}|{1}|{2}|{3}" -f $RecordId,$EventId,$Group,$Dc }
function Persist-GroupSeenKeys([string[]]$keys,[int]$maxKeep=10000) { try { ($keys | Select-Object -Last $maxKeep) | ConvertTo-Json | Set-Content -Path $script:GSeenCacheFile -Force } catch { } }

function Trim-DedupCaches { $script:ASeenEventKeys = $script:ASeenEventKeys | Select-Object -Last 10000; $script:SeenEventKeysG = $script:SeenEventKeysG | Select-Object -Last 10000 }

# =========================
# === RWDC discovery (fast-start with cache / param) ===
# =========================
$RWDCFile = "C:\Logs\Bookmarks\RWDCList.json"
if (-not $RWDC -or $RWDC.Count -eq 0) { if (Test-Path $RWDCFile) { try { $RWDC = Get-Content $RWDCFile | ConvertFrom-Json } catch { $RWDC = @() } } }
if (-not $RWDC -or $RWDC.Count -eq 0) {
  Ensure-AdModule
  try {
    $RWDC = Get-ADDomainController -Filter * | Where-Object { -not $_.IsReadOnly } | Select-Object -ExpandProperty HostName
    try { $RWDC | ConvertTo-Json | Set-Content $RWDCFile -Force } catch { }
  } catch { Write-LogA ("RWDC discovery failed: {0}" -f $_.Exception.Message); return }
}
$RWDCs = $RWDC

# Console startup banner
try { Write-Host ("[{0}] AccountMonitor is running. Monitoring DCs: {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), ($RWDCs -join ', ')) -ForegroundColor Green } catch { }
$nextHeartbeat = if ($HeartbeatMinutes -gt 0) { (Get-Date).AddMinutes($HeartbeatMinutes) } else { $null }

# =========================
# === Initialize LastSeen (LOCAL vs UTC) ===
# =========================
$LastSeenAcc   = @{}
$LastSeenGroup = @{}
$startWin = if ($UseUtcWindows) { (Get-Date).ToUniversalTime().AddMinutes(-[math]::Max(0, $InitialLookbackMinutes)) }
            else { (Get-Date).AddMinutes(-[math]::Max(0, $InitialLookbackMinutes)) }
foreach ($dc in $RWDCs) { $LastSeenAcc[$dc] = $startWin; $LastSeenGroup[$dc] = $startWin }

# =========================
# === Filters ===
# =========================
$AccountEventIds = @(4720,4722,4725,4726,4741,4743)    # users + computers
$GroupEventIds   = @(4728,4729,4732,4733,4756,4757)

# Optional external watchlist
$GroupsFile = "C:\Logs\GroupsToWatch.json"
$GroupsToWatch = $null
if (Test-Path $GroupsFile) {
  try { $GroupsToWatch = Get-Content $GroupsFile | ConvertFrom-Json } catch { $GroupsToWatch = $null }
}
if (-not $GroupsToWatch -or $GroupsToWatch.Count -eq 0) {
  $GroupsToWatch = @('Domain Admins','Enterprise Admins','DnsAdmins','CC_AD Admins','CC_Helpdesk Admins','CC_LAPS Viewer',
    'CC_Local Admin-Servers','CC_Local Admins-Workstations','CC_MECM Access-FST','CC_NetRDP Access','CC_RDP Access','Administrators','Schema Admins','O365_E3')
}

$CreateEnableSuppressWindowSec = 30            # suppress enable <= 120s after create
$RecentCreates = @{}                            # key: targetSid => DateTime

# =========================
# === Soft cross-DC dedup (accounts + groups) ===
# =========================
$script:SoftDedupWindowSec = 120
$script:SoftSeenAcc = @{}   # key: "<SID>|<EventId>" => DateTime
$script:SoftSeenGrp = @{}   # key: "<SID>|<EventId>|<Group>" => DateTime

function Soft-DedupAcc { param([string]$Sid,[int]$EventId,[datetime]$When)
  if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
  $key = "{0}|{1}" -f $Sid,$EventId
  if ($script:SoftSeenAcc.ContainsKey($key)) { $age = ($When - $script:SoftSeenAcc[$key]).TotalSeconds; if ($age -lt $script:SoftDedupWindowSec) { return $true } }
  $script:SoftSeenAcc[$key] = $When
  return $false
}
function Soft-DedupGrp { param([string]$Sid,[int]$EventId,[string]$Group,[datetime]$When)
  if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
  $key = "{0}|{1}|{2}" -f $Sid,$EventId,$Group
  if ($script:SoftSeenGrp.ContainsKey($key)) { $age = ($When - $script:SoftSeenGrp[$key]).TotalSeconds; if ($age -lt $script:SoftDedupWindowSec) { return $true } }
  $script:SoftSeenGrp[$key] = $When
  return $false
}

# =========================
# === Email functions (HTML-only, explicit text/html + BCC) ===
# =========================
function Send-HtmlMailA([string]$htmlBody,[string]$subjectOverride=$null) {
  $subj = if ($subjectOverride) { $subjectOverride } else { $ASubjectDefault }

  $msg = New-Object System.Net.Mail.MailMessage
  $msg.From = New-Object System.Net.Mail.MailAddress($AFrom, $AFromDisplayName)

  foreach ($addr in (Split-Recipients $ATo))  { if ($addr) { $msg.To.Add($addr) } }
  foreach ($addr in (Split-Recipients $ACc))  { if ($addr) { $msg.CC.Add($addr) } }
  foreach ($addr in (Split-Recipients $ABcc)) { if ($addr) { $msg.Bcc.Add($addr) } }

  $msg.Subject = $subj
  $msg.BodyEncoding    = [System.Text.Encoding]::UTF8
  $msg.SubjectEncoding = [System.Text.Encoding]::UTF8
  $msg.Headers.Add('X-AD-AccountWatcher','true')

  # Ensure HTML only
  $msg.IsBodyHtml = $true
  $msg.Body = $htmlBody
  $htmlView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString(
    $htmlBody, [System.Text.Encoding]::UTF8, 'text/html'
  )
  $msg.AlternateViews.Clear()
  $msg.AlternateViews.Add($htmlView)

  $client = New-SmtpClient -Server $ASmtpServer -Port $ASmtpPort -UseSsl:$AUseSsl -Cred $ACredential
  try { 
    Invoke-WithRetry { $client.Send($msg) }
    Write-LogA ("Email sent: {0}" -f $subj)
  } catch { 
    Write-LogA ("Account email send failed: {0}" -f $_.Exception.Message)
  } finally { $msg.Dispose(); $client.Dispose() }
}

function Send-EmailG { param([string]$Subject,[string]$BodyHtml)
  $msg = New-Object System.Net.Mail.MailMessage
  $msg.From = New-Object System.Net.Mail.MailAddress($GFrom, $GFromDisplayName)

  foreach ($addr in (Split-Recipients $GTo))  { if ($addr) { $msg.To.Add($addr) } }
  foreach ($addr in (Split-Recipients $GCc))  { if ($addr) { $msg.CC.Add($addr) } }
  foreach ($addr in (Split-Recipients $GBcc)) { if ($addr) { $msg.Bcc.Add($addr) } }

  $msg.Subject = $Subject
  $msg.BodyEncoding    = [System.Text.Encoding]::UTF8
  $msg.SubjectEncoding = [System.Text.Encoding]::UTF8
  $msg.Headers.Add('X-AD-GroupWatcher','true')

  # Ensure HTML only
  $msg.IsBodyHtml = $true
  $msg.Body = $BodyHtml
  $htmlView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString(
    $BodyHtml, [System.Text.Encoding]::UTF8, 'text/html'
  )
  $msg.AlternateViews.Clear()
  $msg.AlternateViews.Add($htmlView)

  $client = New-SmtpClient -Server $GSmtpServer -Port $GSmtpPort -UseSsl:$GUseSsl -Cred $GCredential
  try { 
    Invoke-WithRetry { $client.Send($msg) }
    Write-LogG ("Email sent: {0}" -f $Subject)
  } catch { 
    Write-LogG ("Group email send failed: {0}" -f $_.Exception.Message)
  } finally { $msg.Dispose(); $client.Dispose() }
}

# =========================
# === TABLE-BASED Body Builders (old layout, horizontal scroll + NO WRAP) ===
# =========================

function Build-AccountEmailBody {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('Created','Enabled','Disabled','Deleted')] [string]$Status,
    [Parameter(Mandatory=$true)][string]$ModifiedTime,
    [Parameter(Mandatory=$true)][string]$TargetSam,
    [Parameter(Mandatory=$true)][string]$TargetDisplay,
    [Parameter(Mandatory=$true)][string]$CallerSam,
    [Parameter(Mandatory=$true)][string]$CallerDisplay,
    [Parameter(Mandatory=$true)][string]$SourceDcFqdn
  )

  $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $statusPill  = Get-StatusPill -Status $Status -Context 'Account'

  $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Real-time Alert: Account $Status</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#1f1f1f;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#ffffff;">
    <tr>
      <td align="left" style="padding:12px 0;">
        <div style="font-size:18px;font-weight:700;color:#111827;line-height:1.4;">Real‑time Alert: Account $Status</div>
        <div style="font-size:12px;color:#6b6b6b;margin-top:4px;">Generated at: $generatedAt</div>
      </td>
    </tr>
    <tr>
      <td>
        <div style="max-width:100%;overflow-x:auto;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:980px;border-collapse:collapse;">
            <tr>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Modified Time</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Account Status</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Target(SAM)</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Target Display Name</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Caller(SAM)</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Caller Display Name</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Source DC</th>
            </tr>
            <tr>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($ModifiedTime))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$statusPill</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($TargetSam))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($TargetDisplay))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($CallerSam))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($CallerDisplay))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($SourceDcFqdn))</td>
            </tr>
          </table>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding-top:8px;">
        <div style="font-size:12px;color:#555;">
          <em>* This automated alert monitors lifecycle activities for all domain user/Computer accounts.</em>
        </div>
      </td>
    </tr>
  </table>
</body>
</html>
"@
  return $html
}


function Build-GroupEmailBody {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('Added','Removed','Updated')] [string]$Action,
    [Parameter(Mandatory=$true)][string]$ModifiedTime,
    [Parameter(Mandatory=$true)][string]$TargetSam,
    [Parameter(Mandatory=$true)][string]$TargetDisplay,
    [Parameter(Mandatory=$true)][string]$CallerSam,
    [Parameter(Mandatory=$true)][string]$CallerDisplay,
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$true)][string]$SourceDcFqdn
  )

  $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $statusPill  = Get-StatusPill -Status $Action -Context 'Group'

  $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Group Membership Changed - $(HtmlEncode($GroupName))</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#1f1f1f;">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#ffffff;">
    <tr>
      <td align="left" style="padding:12px 0;">
        <div style="font-size:18px;font-weight:700;color:#111827;line-height:1.4;">Group Membership Changed — $(HtmlEncode($GroupName))</div>
        <div style="font-size:12px;color:#6b6b6b;margin-top:4px;">Generated at: $generatedAt</div>
      </td>
    </tr>
    <tr>
      <td>
        <div style="max-width:100%;overflow-x:auto;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:980px;border-collapse:collapse;">
            <tr>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Modified Time</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Group Status</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Target(SAM)</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Target Display Name</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Caller(SAM)</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Caller Display Name</th>
              <th style="border:1px solid #d0d0d0;padding:8px 10px;background:#f2f2f2;text-align:left;font-size:12px;white-space:nowrap;">Source DC</th>
            </tr>
            <tr>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($ModifiedTime))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$statusPill</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($TargetSam))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($TargetDisplay))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($CallerSam))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($CallerDisplay))</td>
              <td style="border:1px solid #d0d0d0;padding:8px 10px;font-size:12px;white-space:nowrap;">$(HtmlEncode($SourceDcFqdn))</td>
            </tr>
          </table>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding-top:8px;">
        <div style="font-size:12px;color:#555;">
          <em>* This automated alert monitors and reports on all High‑critical group modification events.</em>
        </div>
      </td>
    </tr>
  </table>
</body>
</html>
"@
  return $html
}

# =========================
# === AD enrichment (PS 5.1 compatible; users + computers) ===
# =========================
$script:AdCache = @{}
function Resolve-AdUserA { 
  param(
    [string]$Sid,
    [string]$Sam,
    [string]$DomainHint
  )

  Ensure-AdModule

  $cacheKey = if ($Sid) { $Sid } else { "{0}\{1}" -f $DomainHint,$Sam }
  if ($script:AdCache.ContainsKey($cacheKey)) { return $script:AdCache[$cacheKey] }

  $result = [PSCustomObject]@{
    DisplayName    = $null
    SamAccountName = $null
  }

  try {
    $u = $null

    if ($Sid -and ($Sid -match '^S-1-5-')) {
      # Try user by SID
      $u = Get-ADUser -Identity $Sid -Properties DisplayName,sAMAccountName -ErrorAction SilentlyContinue
      if (-not $u) {
        # Fallback: any AD object (computer possibly)
        $u = Get-ADObject -Identity $Sid -Properties displayName,sAMAccountName -ErrorAction SilentlyContinue
      }
    }
    elseif ($Sam) {
      $esc = Escape-LdapFilterValue $Sam

      # Try user first
      $u = Get-ADUser -LDAPFilter "(sAMAccountName=$esc)" -Properties DisplayName,sAMAccountName -ErrorAction SilentlyContinue

      if (-not $u) {
        # Try computer object
        $u = Get-ADObject -LDAPFilter "(&(objectClass=computer)(sAMAccountName=$esc))" -Properties displayName,sAMAccountName -ErrorAction SilentlyContinue
      }
    }

    if ($u) {
      $disp = $null
      if ($u.PSObject.Properties['DisplayName']) { $disp = $u.DisplayName }
      if (-not $disp -and $u.PSObject.Properties['displayName']) { $disp = $u.displayName }

      $samVal = $null
      if ($u.PSObject.Properties['SamAccountName']) { $samVal = $u.SamAccountName }
      if (-not $samVal -and $u.PSObject.Properties['sAMAccountName']) { $samVal = $u.'sAMAccountName' }

      $result.DisplayName    = $disp
      $result.SamAccountName = $samVal
    }
  } catch {
    # fail-safe
  }

  $script:AdCache[$cacheKey] = $result
  return $result
}

function Resolve-GroupMemberDisplay {
  param([string]$MemberSid,[string]$MemberName)
  Ensure-AdModule
  $display = $null; $sam = $null; $cn = $null
  if ($MemberSid -and $MemberSid -match '^S-1-5-') {
    try {
      $obj = Get-ADObject -Identity $MemberSid -Properties DisplayName,Name,sAMAccountName -ErrorAction Stop
      if ($obj.DisplayName) { $display = $obj.DisplayName }
      if ($obj.sAMAccountName) { $sam = $obj.sAMAccountName }
      if ($obj.Name) { $cn = $obj.Name }
    } catch { }
  }
  if (-not $display -and $MemberName) {
    if ($MemberName -match '^CN=') {
      try {
        $obj2 = Get-ADObject -Identity $MemberName -Properties DisplayName,Name,sAMAccountName -ErrorAction Stop
        if ($obj2.DisplayName) { $display = $obj2.DisplayName }
        if (-not $sam -and $obj2.sAMAccountName) { $sam = $obj2.sAMAccountName }
        if (-not $cn -and $obj2.Name) { $cn = $obj2.Name }
      } catch { }
    } elseif ($MemberName -match '\\') {
      $sam = ($MemberName -split '\\')[1]
      try { $u = Get-ADUser -LDAPFilter "(sAMAccountName=$(Escape-LdapFilterValue $sam))" -Properties DisplayName -ErrorAction Stop; if ($u.DisplayName) { $display = $u.DisplayName } } catch { }
    } else {
      $sam = $MemberName
      try { $u2 = Get-ADUser -LDAPFilter "(sAMAccountName=$(Escape-LdapFilterValue $sam))" -Properties DisplayName -ErrorAction Stop; if ($u2.DisplayName) { $display = $u2.DisplayName } } catch { }
    }
  }
  $resolvedSam = if ($sam) { $sam } elseif ($MemberSid) { $MemberSid } else { $MemberName }
  $resolvedDisp = if ($display) { $display } elseif ($cn) { $cn } else { $resolvedSam }
  return @{ Sam = $resolvedSam; Display = $resolvedDisp }
}

# Tombstone display name recovery
$script:DomainDnCache = @{}
function Select-BestDeletedName { param([object[]]$Candidates)
  if (-not $Candidates -or $Candidates.Count -eq 0) { return $null }
  $best = $Candidates | Sort-Object -Property whenChanged -Descending | Select-Object -First 1
  if ($best.displayName) { return $best.displayName } elseif ($best.'msDS-LastKnownRDN') { return $best.'msDS-LastKnownRDN' } elseif ($best.cn) { return $best.cn } elseif ($best.sAMAccountName) { return $best.sAMAccountName }
  return $null
}
function Resolve-DeletedDisplayName { [CmdletBinding()] param([Parameter(Mandatory=$true)][string]$Server,[string]$Sid,[string]$Sam,[string]$DomainDn)
  Ensure-AdModule
  $fallback = $Sam
  try {
    if (-not $DomainDn -or [string]::IsNullOrWhiteSpace($DomainDn)) {
      if ($script:DomainDnCache.ContainsKey($Server)) { $DomainDn = $script:DomainDnCache[$Server] } else { $DomainDn = (Get-ADDomain -Server $Server -ErrorAction Stop).DistinguishedName; $script:DomainDnCache[$Server] = $DomainDn }
    }
  } catch { }
  if ($Sid -and $Sid -match '^S-1-5-') {
    try {
      $obj = Get-ADObject -Server $Server -Identity $Sid -IncludeDeletedObjects -Properties displayName,msDS-LastKnownRDN,cn,sAMAccountName -ErrorAction Stop
      if ($obj) { if ($obj.displayName) { return $obj.displayName } elseif ($obj.'msDS-LastKnownRDN') { return $obj.'msDS-LastKnownRDN' } elseif ($obj.cn) { return $obj.cn } elseif ($obj.sAMAccountName) { return $obj.sAMAccountName } }
    } catch { }
  }
  if ([string]::IsNullOrWhiteSpace($DomainDn)) { return $fallback }
  $searchBase = "CN=Deleted Objects,$DomainDn"
  $props      = 'displayName','msDS-LastKnownRDN','cn','sAMAccountName','whenChanged'
  if ($Sam) {
    $escSam = Escape-LdapFilterValue $Sam
    try { $objs = Get-ADObject -Server $Server -SearchBase $searchBase -IncludeDeletedObjects -LDAPFilter "(&(isDeleted=TRUE)(msDS-LastKnownRDN=$escSam))" -Properties $props -ErrorAction Stop; $name = Select-BestDeletedName -Candidates $objs; if ($name) { return $name } } catch { }
    try { $objs2 = Get-ADObject -Server $Server -SearchBase $searchBase -IncludeDeletedObjects -LDAPFilter "(&(isDeleted=TRUE)(sAMAccountName=$escSam))" -Properties $props -ErrorAction Stop; $name2 = Select-BestDeletedName -Candidates $objs2; if ($name2) { return $name2 } } catch { }
  }
  return $fallback
}

# =========================
# === Optional Rate Limiting ===
# =========================
$script:LastSentAt = @{}  # key: "$TargetSid|$EventId|$GroupName"
function Should-SendNow([string]$key,[datetime]$now) {
  if ($RateLimitMinGapSec -le 0) { return $true }
  if (-not $script:LastSentAt.ContainsKey($key)) { $script:LastSentAt[$key] = $now; return $true }
  $gap = ($now - $script:LastSentAt[$key]).TotalSeconds
  if ($gap -ge $RateLimitMinGapSec) { $script:LastSentAt[$key] = $now; return $true }
  return $false
}

# =========================
# === Main polling loop (LOCAL/UTC windows) ===
# =========================
while ($true) {
  $nowWin = if ($UseUtcWindows) { (Get-Date).ToUniversalTime() } else { Get-Date }
  $endTime = $nowWin

  foreach ($dc in $RWDCs) {
    # ===== Account events (users + computers) =====
    $lastAcc = $LastSeenAcc[$dc]
    $deltaAccSec = ($nowWin - $lastAcc).TotalSeconds
    $applyOverlapAcc = ($deltaAccSec -gt $WindowOverlapSec)
    $startAcc = if ($applyOverlapAcc) { $lastAcc.AddSeconds(-[math]::Max(0,$WindowOverlapSec)) } else { $lastAcc }

    if ($Diag) { Write-LogA ("[Diag] Account poll {0}: Start={1} End={2}" -f $dc, $startAcc.ToString('yyyy-MM-dd HH:mm:ss.fff'), $endTime.ToString('yyyy-MM-dd HH:mm:ss.fff')) }

    $accEvents = $null
    try {
      $accEvents = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName='Security'; Id=$AccountEventIds; StartTime=$startAcc; EndTime=$endTime } -ErrorAction Stop
    } catch {
      $msg = $_.Exception.Message
      $isNoEvents = $msg -and $msg -match 'No events were found that match the specified selection criteria'
      if (-not ($SuppressNoEventLog -and $isNoEvents)) {
        Write-LogA ("Get-WinEvent (accounts) failed on {0}: {1}" -f $dc, $msg)
      }
    }

    if (-not $accEvents -or $accEvents.Count -eq 0) {
      try {
        $fallbackStart = if ($UseUtcWindows) { (Get-Date).ToUniversalTime().AddSeconds(-20) } else { (Get-Date).AddSeconds(-20) }
        $accEvents = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName='Security'; Id=$AccountEventIds; StartTime=$fallbackStart; EndTime=$endTime } -ErrorAction SilentlyContinue
      } catch { }
    }

    if ($accEvents -and $accEvents.Count -gt 0) {
      $sortedAcc = $accEvents | Sort-Object TimeCreated
      foreach ($e in $sortedAcc) {
        if ($Diag) { Write-LogA ("[Diag] {0} Account event: Id={1} RecordId={2} Time={3}" -f $dc, $e.Id, $e.RecordId, $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff')) }
        $accountKey = Make-AccountEventKey -Dc $dc -RecordId $e.RecordId -EventId $e.Id
        if (-not $NoDedup -and ($script:ASeenEventKeys -contains $accountKey)) { continue }

        $x   = [xml]$e.ToXml()
        $sys = $x.Event.System
        $dat = $x.Event.EventData.Data

        $eventId            = [int]$sys.EventID
        $modifiedTimeLocal  = $e.TimeCreated.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $whenBasis          = if ($UseUtcWindows) { $e.TimeCreated.ToUniversalTime() } else { $e.TimeCreated }

        # Fields (users + computers)
        $targetUser    = Get-EventFieldValue -XmlData $dat -Names @('TargetUserName','TargetAccountName','AccountName','SamAccountName','ComputerName')
        $targetDomain  = Get-EventFieldValue -XmlData $dat -Names @('TargetDomainName','TargetAccountDomain','AccountDomain')
        $targetSid     = Get-EventFieldValue -XmlData $dat -Names @('TargetSid','TargetUserSid','SecurityId')
        $callerUser    = Get-EventFieldValue -XmlData $dat -Names @('SubjectUserName','CallerUserName','ActorUser')
        $callerDomain  = Get-EventFieldValue -XmlData $dat -Names @('SubjectDomainName','CallerDomainName','ActorDomain')
        $callerSid     = Get-EventFieldValue -XmlData $dat -Names @('SubjectUserSid','SubjectSid','CallerUserSid')

        if (Soft-DedupAcc -Sid $targetSid -EventId $eventId -When $whenBasis) { continue }

        $target = Resolve-AdUserA -Sid $targetSid -Sam $targetUser -DomainHint $targetDomain
        $caller = Resolve-AdUserA -Sid $callerSid -Sam $callerUser -DomainHint $callerDomain

        $targetSam     = if ($target.SamAccountName) { $target.SamAccountName } else { $targetUser }
        $targetDisplay = if ($target.DisplayName)    { $target.DisplayName    } else { $targetSam }
        $callerSam     = if ($caller.SamAccountName) { $caller.SamAccountName } else { $callerUser }
        $callerDisplay = if ($caller.DisplayName)    { $caller.DisplayName    } else { $callerUser }

        # Creation (users: 4720 | computers: 4741)
        if ($eventId -eq 4720 -or $eventId -eq 4741) {
          if ($targetSid) { $RecentCreates[$targetSid] = $e.TimeCreated }
          $body = Build-AccountEmailBody -Status 'Created' -ModifiedTime $modifiedTimeLocal -TargetSam $targetSam -TargetDisplay $targetDisplay -CallerSam $callerSam -CallerDisplay $callerDisplay -SourceDcFqdn $dc
          $subjectName = if ([string]::IsNullOrWhiteSpace($targetDisplay)) { $targetSam } else { $targetDisplay }
          $sendKey = "{0}|{1}|" -f $targetSid, $eventId
          if (Should-SendNow -key $sendKey -now (Get-Date)) {
            Send-HtmlMailA -htmlBody $body -subjectOverride ("Account Created - {0}" -f $subjectName)
          }
          $script:ASeenEventKeys += $accountKey; Trim-DedupCaches; Persist-AccountSeenKeys -keys $script:ASeenEventKeys
          continue
        }

        # Suppress immediate enable after create (4720→4722 or 4741→4722)
        if ($eventId -eq 4722 -and -not $NoSuppressInitialEnable -and $targetSid -and $RecentCreates.ContainsKey($targetSid)) {
          $age = ($e.TimeCreated - $RecentCreates[$targetSid]).TotalSeconds
          if ($age -le $CreateEnableSuppressWindowSec) {
            $script:ASeenEventKeys += $accountKey; Trim-DedupCaches; Persist-AccountSeenKeys -keys $script:ASeenEventKeys
            $RecentCreates.Remove($targetSid) | Out-Null
            continue
          } else { $RecentCreates.Remove($targetSid) | Out-Null }
        }

        # Deleted (users: 4726 | computers: 4743)
        if ($eventId -eq 4726 -or $eventId -eq 4743) {
          $samForLookup  = if ([string]::IsNullOrWhiteSpace($targetSam)) { $targetUser } else { $targetSam }
          $targetDisplay = Resolve-DeletedDisplayName -Server $dc -Sid $targetSid -Sam $samForLookup
          if ([string]::IsNullOrWhiteSpace($targetDisplay)) { $targetDisplay = $samForLookup }
          $body = Build-AccountEmailBody -Status 'Deleted' -ModifiedTime $modifiedTimeLocal -TargetSam $targetSam -TargetDisplay $targetDisplay -CallerSam $callerSam -CallerDisplay $callerDisplay -SourceDcFqdn $dc
          $subjectName = if ([string]::IsNullOrWhiteSpace($targetDisplay)) { $targetSam } else { $targetDisplay }
          $sendKey = "{0}|{1}|" -f $targetSid, $eventId
          if (Should-SendNow -key $sendKey -now (Get-Date)) {
            Send-HtmlMailA -htmlBody $body -subjectOverride ("Account Deleted - {0}" -f $subjectName)
          }
          $script:ASeenEventKeys += $accountKey; Trim-DedupCaches; Persist-AccountSeenKeys -keys $script:ASeenEventKeys
          continue
        }

        # Enabled/Disabled
        $accountStatus  = if ($eventId -eq 4722) { 'Enabled' } elseif ($eventId -eq 4725) { 'Disabled' } else { $null }
        if ($null -ne $accountStatus) {
          $body = Build-AccountEmailBody -Status $accountStatus -ModifiedTime $modifiedTimeLocal -TargetSam $targetSam -TargetDisplay $targetDisplay -CallerSam $callerSam -CallerDisplay $callerDisplay -SourceDcFqdn $dc
          $subjectName = if ([string]::IsNullOrWhiteSpace($targetDisplay)) { $targetSam } else { $targetDisplay }
          $sendKey = "{0}|{1}|" -f $targetSid, $eventId
          if (Should-SendNow -key $sendKey -now (Get-Date)) {
            Send-HtmlMailA -htmlBody $body -subjectOverride ("Account {0} - {1}" -f $accountStatus, $subjectName)
          }
          $script:ASeenEventKeys += $accountKey; Trim-DedupCaches; Persist-AccountSeenKeys -keys $script:ASeenEventKeys
        }
      }
      $LastSeenAcc[$dc] = if ($UseUtcWindows) { $sortedAcc[-1].TimeCreated.ToUniversalTime().AddSeconds(1) } else { $sortedAcc[-1].TimeCreated.AddSeconds(1) }
    } else { $LastSeenAcc[$dc] = $endTime }

    # ===== Group events =====
    $lastGrp = $LastSeenGroup[$dc]
    $deltaGrpSec = ($nowWin - $lastGrp).TotalSeconds
    $applyOverlapGrp = ($deltaGrpSec -gt $WindowOverlapSec)
    $startGrp = if ($applyOverlapGrp) { $lastGrp.AddSeconds(-[math]::Max(0,$WindowOverlapSec)) } else { $lastGrp }

    if ($Diag) { Write-LogG ("[Diag] Group poll {0}: Start={1} End={2}" -f $dc, $startGrp.ToString('yyyy-MM-dd HH:mm:ss.fff'), $endTime.ToString('yyyy-MM-dd HH:mm:ss.fff')) }

    $grpEvents = $null
    try { 
      $grpEvents = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName='Security'; Id=$GroupEventIds; StartTime=$startGrp; EndTime=$endTime } -ErrorAction Stop 
    } catch { 
      $msg = $_.Exception.Message
      $isNoEvents = $msg -and $msg -match 'No events were found that match the specified selection criteria'
      if (-not ($SuppressNoEventLog -and $isNoEvents)) {
        Write-LogG ("Get-WinEvent (groups) failed on {0}: {1}" -f $dc, $msg)
      }
    }
    if (-not $grpEvents -or $grpEvents.Count -eq 0) { 
      try { 
        $fallbackStartG = if ($UseUtcWindows) { (Get-Date).ToUniversalTime().AddSeconds(-20) } else { (Get-Date).AddSeconds(-20) }
        $grpEvents = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName='Security'; Id=$GroupEventIds; StartTime=$fallbackStartG; EndTime=$endTime } -ErrorAction SilentlyContinue 
      } catch { } 
    }

    if ($grpEvents -and $grpEvents.Count -gt 0) {
      $sortedGrp = $grpEvents | Sort-Object TimeCreated
      foreach ($e in $sortedGrp) {
        if ($Diag) { Write-LogG ("[Diag] {0} Group event: Id={1} RecordId={2} Time={3}" -f $dc, $e.Id, $e.RecordId, $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff')) }

        $x   = [xml]$e.ToXml()
        $sys = $x.Event.System
        $dat = $x.Event.EventData.Data

        $eventId            = [int]$sys.EventID
        $modifiedTimeLocal  = $e.TimeCreated.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $whenBasis          = if ($UseUtcWindows) { $e.TimeCreated.ToUniversalTime() } else { $e.TimeCreated }
        $recordId           = [int]$sys.EventRecordID

        $groupNameRaw  = Get-EventFieldValue -XmlData $dat -Names @('TargetUserName')
        $memberNameRaw = Get-EventFieldValue -XmlData $dat -Names @('MemberName')
        $memberSid     = Get-EventFieldValue -XmlData $dat -Names @('MemberSid')
        $actorUser     = Get-EventFieldValue -XmlData $dat -Names @('SubjectUserName')

        $shortGroup = if ($groupNameRaw -match '^CN=') { ($groupNameRaw -replace '^CN=([^,]+).*','$1') } else { $groupNameRaw }
        if (-not ($GroupsToWatch -contains $shortGroup)) { continue }

        $gKey = Make-GroupEventKey -RecordId $recordId -EventId $eventId -Group $shortGroup -Dc $dc
        if (-not $NoDedup -and ($script:SeenEventKeysG -contains $gKey)) { continue }

        if (Soft-DedupGrp -Sid $memberSid -EventId $eventId -Group $shortGroup -When $whenBasis) { continue }

        $mem = Resolve-GroupMemberDisplay -MemberSid $memberSid -MemberName $memberNameRaw
        $memberSam  = $mem.Sam
        $memberDisp = $mem.Display

        $actorDisplay = $actorUser
        if (-not [string]::IsNullOrWhiteSpace($actorUser)) {
          Ensure-AdModule
          try { $esc = Escape-LdapFilterValue $actorUser; $u = Get-ADUser -LDAPFilter "(sAMAccountName=$esc)" -Properties DisplayName -ErrorAction Stop; if ($u.DisplayName) { $actorDisplay = $u.DisplayName } } catch { }
        }

        $actionLabel = switch ($eventId) { {$_ -in 4728,4732,4756} { 'Added' } {$_ -in 4729,4733,4757} { 'Removed' } default { 'Updated' } }

        $subjectUser = if ([string]::IsNullOrWhiteSpace($memberDisp)) { $memberSam } else { $memberDisp }
        if ([string]::IsNullOrWhiteSpace($subjectUser)) { $subjectUser = 'Unknown User' }
        $subject = ("{0}{1}" -f $GSubjectPrefix, $subjectUser)

        $body = Build-GroupEmailBody -Action $actionLabel -ModifiedTime $modifiedTimeLocal -TargetSam $memberSam -TargetDisplay $memberDisp -CallerSam $actorUser -CallerDisplay $actorDisplay -GroupName $shortGroup -SourceDcFqdn $dc

        $sendKeyG = "{0}|{1}|{2}" -f $memberSid, $eventId, $shortGroup
        if (Should-SendNow -key $sendKeyG -now (Get-Date)) {
          Send-EmailG -Subject $subject -BodyHtml $body
        }
        $script:SeenEventKeysG += $gKey; Trim-DedupCaches; Persist-GroupSeenKeys -keys $script:SeenEventKeysG
      }
      $LastSeenGroup[$dc] = if ($UseUtcWindows) { $sortedGrp[-1].TimeCreated.ToUniversalTime().AddSeconds(1) } else { $sortedGrp[-1].TimeCreated.AddSeconds(1) }
    } else { $LastSeenGroup[$dc] = $endTime }
  } # foreach DC

  # Optional heartbeat (console + optional email)
  if ($HeartbeatMinutes -gt 0 -and $nextHeartbeat -ne $null) {
    $nowHb = Get-Date
    if ($nowHb -ge $nextHeartbeat) {
      try {
        $accSince = ($nowHb - ($LastSeenAcc.Values | Sort-Object -Descending | Select-Object -First 1)).TotalMinutes
        $msg = ("[{0}] AccountMonitor heartbeat: running. Last account event window advanced {1:N1} min ago." -f $nowHb.ToString('yyyy-MM-dd HH:mm:ss'), $accSince)
        Write-Host $msg -ForegroundColor DarkGreen
        if ($HeartbeatEmail) {
          $hbHtml = "<html><body style='font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111827;padding:12px;'>$msg</body></html>"
          Send-HtmlMailA -htmlBody $hbHtml -subjectOverride 'AccountMonitor Heartbeat'
        }
      } catch { Write-LogA ("Heartbeat failed: {0}" -f $_.Exception.Message) }
      $nextHeartbeat = (Get-Date).AddMinutes($HeartbeatMinutes)
    }
  }

  Start-Sleep -Seconds $PollIntervalSec
}
