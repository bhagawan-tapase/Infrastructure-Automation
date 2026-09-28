Import-Module ActiveDirectory

# ==== Customize these ====
$User        = 'a-test'                   # AD user (sAMAccountName or DN/UPN)
$TimeZoneId  = 'Eastern Standard Time'  # Windows TZ ID (e.g., "Eastern Standard Time")
$Date        = '2026-01-30'             # Target calendar date in ET (YYYY-MM-DD)
$Time        = '11:25'                  # Target time in ET (HH:mm, 24h format)
# ==========================

# Parse ET timestamp and set expiration
$tz   = [System.TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
$dtET = Get-Date -Date ("$Date $Time") -Format 'yyyy-MM-dd HH:mm'
$dtET = Get-Date $dtET                       # ensure DateTime
# Note: passing an ET DateTime; AD will store UTC internally
Set-ADAccountExpiration -Identity $User -DateTime $dtET

"Set expiration for $User at $($dtET.ToString('yyyy-MM-dd HH:mm')) ($TimeZoneId)"
