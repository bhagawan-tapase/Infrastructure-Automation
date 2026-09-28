<#
Script Name : AD_Account_Expiration_Notification.ps1

Description :
This script automates Active Directory account expiration notifications by
identifying enabled user accounts scheduled to expire within a configurable
notification window, notifying managers and affected users via email,
calculating remaining days until expiration, and generating detailed logs
for auditing and operational tracking.

Key Features :
- Detects AD accounts expiring within the notification period
- Retrieves manager and user contact information
- Sends consolidated notifications to managers
- Adds affected users in BCC where applicable
- Handles missing user and manager email scenarios
- Generates professional HTML email notifications
- Maintains detailed activity and error logs

Author  : Bhagawan Tapase
Version : 1.0
#>

Import-Module ActiveDirectory

#----------------------------------------------------------
# Email Settings
#----------------------------------------------------------

$SmtpServer      = 'YourRelayServer'
$SmtpPort        = 25
$UseSsl          = $false

$From            = 'noreply@yourdomain.com'
$FromDisplayName = 'IT Support'

$SmtpUser        = ''
$SmtpPass        = ''

$Credential = if ($SmtpUser -and $SmtpPass) {
    New-Object System.Management.Automation.PSCredential(
        $SmtpUser,
        (ConvertTo-SecureString $SmtpPass -AsPlainText -Force)
    )
}
else {
    $null
}

#----------------------------------------------------------
# Configuration
#----------------------------------------------------------

$LogFile = "D:\Account_Expiration\ADAccountExpiryNotification.log"

# Notification window
$StartDate = Get-Date
$EndDate   = $StartDate.AddDays(10)

#----------------------------------------------------------
# Get Expiring Accounts
#----------------------------------------------------------

$Users = Get-ADUser `
    -Filter * `
    -Properties DisplayName,
                SamAccountName,
                Mail,
                Manager,
                AccountExpirationDate,
                Enabled |
    Where-Object {
        $_.Enabled -eq $true -and
        $_.AccountExpirationDate -and
        $_.AccountExpirationDate -ge $StartDate -and
        $_.AccountExpirationDate -le $EndDate
    }

if (!$Users) {
    Add-Content $LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - No expiring accounts found."
    return
}

#----------------------------------------------------------
# Prepare Data
#----------------------------------------------------------
$NotificationData = foreach ($User in $Users)
{
$Manager = $null
$ManagerName = $null
$ManagerEmail = $null

if ($User.Manager)
{
    try
    {
        $Manager = Get-ADUser -Identity $User.Manager -Properties DisplayName,Mail
        $ManagerName = $Manager.DisplayName
        $ManagerEmail = $Manager.Mail
    }
    catch
    {
        $ManagerName = $null
        $ManagerEmail = $null
    }
}

# Skip only if BOTH user and manager email are missing
if (!$User.Mail -and !$ManagerEmail)
{
    Add-Content $LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Skipped $($User.SamAccountName) : Both User and Manager email missing."
    continue
}

# If manager email missing, send to user instead
if (!$ManagerEmail)
{
    $ManagerName  = $User.DisplayName
    $ManagerEmail = $User.Mail
}
 

$DaysRemaining = (New-TimeSpan `
    -Start (Get-Date) `
    -End $User.AccountExpirationDate).Days

    if ($DaysRemaining -lt 0)
    {
        continue
    }

    [PSCustomObject]@{
    UserName      = $User.DisplayName
    UserID        = $User.SamAccountName
    UserEmail     = $User.Mail
    ManagerName   = $ManagerName
    ManagerEmail  = $ManagerEmail
    ExpiryDate    = $User.AccountExpirationDate
    DaysRemaining = $DaysRemaining
}
}

#----------------------------------------------------------
# Send One Email Per Manager
#----------------------------------------------------------

$ManagerGroups = $NotificationData | Group-Object ManagerEmail

foreach ($Group in $ManagerGroups) {

    $ManagerEmail = $Group.Name
    $ManagerName  = ($Group.Group | Select-Object -First 1).ManagerName

    # Build Email Table

    $Rows = ""

    foreach ($Item in $Group.Group) {

$Rows += @"
<tr>
<td style='padding:10px;border:1px solid #d9d9d9;'>$($Item.UserName)</td>
<td style='padding:10px;border:1px solid #d9d9d9;'>$($Item.UserID)</td>
<td style='padding:10px;border:1px solid #d9d9d9;'>$($Item.ExpiryDate.ToString('dd-MMM-yyyy'))</td>
<td style='padding:10px;border:1px solid #d9d9d9;text-align:center;'>$($Item.DaysRemaining)</td>
</tr>
"@
    }

    # User BCC
$BCCUsers = @(
    $Group.Group |
    Where-Object {
        $_.UserEmail -and
        $_.UserEmail -ne $_.ManagerEmail
    } |
    Select-Object -ExpandProperty UserEmail -Unique |
    Where-Object { $_ }
)


    # Subject

    $MinimumDays = (
        $Group.Group |
        Sort-Object DaysRemaining |
        Select-Object -First 1
    ).DaysRemaining

    if ($MinimumDays -eq 0) {
        $Subject = "Urgent - AD Account Expiration Today"
    }
    else {
        #$Subject = "AD Account Expiration Notification - $MinimumDays Day(s) Remaining"
        $Subject = "Action Required - AD Account Expiration Notification"
    }

    # Email Body

$Body = @"
<html>

<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Calibri,Arial,sans-serif;">

<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"
style="background-color:#f3f4f6;padding:24px 0;">
<tr>
<td align="center">

<table role="presentation" width="800" cellspacing="0" cellpadding="0" border="0"
style="width:800px;max-width:98%;background:#ffffff;border:1px solid #e1e1e1;border-radius:8px;">

<tr>
<td style="background:#005a9e;color:#ffffff;padding:20px 32px;font-size:22px;font-weight:bold;">
AD Account Expiration Notification
</td>
</tr>

<tr>
<td style="padding:32px;">

<p style="margin:0 0 15px 0;font-size:16px;">
Hi $ManagerName,
</p>

<p style="margin:0 0 20px 0;font-size:14px;line-height:1.6;">
This is an automated notification that the Active Directory account(s) listed below are scheduled to expire soon.
Please review the details and take appropriate action if continued access is required.
</p>

<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;">

<tr style="background:#005a9e;color:#ffffff;">
<th style="padding:10px;border:1px solid #d9d9d9;text-align:left;">User Name</th>
<th style="padding:10px;border:1px solid #d9d9d9;text-align:left;">User ID</th>
<th style="padding:10px;border:1px solid #d9d9d9;text-align:left;">Expiration Date</th>
<th style="padding:10px;border:1px solid #d9d9d9;text-align:center;">Days Remaining</th>
</tr>

$Rows

</table>

<br>

<p style="margin:0 0 15px 0;font-size:14px;line-height:1.6;">
If continued access is required, please submit an extension request before the account expiration date.
</p>

<table role="presentation" cellspacing="0" cellpadding="0" border="0">
<tr>
<td bgcolor="#005a9e" style="border-radius:4px;">
<a href="https://your-company-helpdesk-url"
   style="display:inline-block;
          padding:12px 24px;
          color:#ffffff;
          text-decoration:none;
          font-weight:bold;">
Create Extension Request
</a>
</td>
</tr>
</table>

<br>

<p style="font-size:14px;font-weight:bold;">
Please ignore this email if:
</p>

<ul style="font-size:14px;line-height:1.6;">
<li>An extension request has already been submitted.</li>
<li>The user's Last Working Day (LWD) has been reached.</li>
<li>The account is no longer required and can be allowed to expire as scheduled.</li>
</ul>

<p style="font-size:12px;color:#666666;">
Affected users have been notified separately, where applicable.
</p>

</td>
</tr>

<tr>
<td style="padding:15px 32px;background-color:#f8f8f8;color:#666666;font-size:12px;">
IT Notification
</td>
</tr>

</table>

</td>
</tr>
</table>

</body>
</html>
"@

    try {

  $MailParams = @{
    To          = $ManagerEmail
    From        = "$FromDisplayName <$From>"
    Subject     = $Subject
    Body        = $Body
    BodyAsHtml  = $true
    SmtpServer  = $SmtpServer
    Port        = $SmtpPort
}
 if ($BCCUsers)
{
    $MailParams.Bcc = $BCCUsers
}

        if ($Credential) {
            $MailParams.Credential = $Credential
            $MailParams.UseSsl     = $UseSsl
        }
      #  Write-Host "Manager Email: $ManagerEmail"
       # Write-Host "CC Users:"
       # $CCUsers | ForEach-Object { Write-Host $_ }

        Send-MailMessage @MailParams

        Add-Content $LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Email sent to $ManagerEmail"

    }
    catch {

        Add-Content $LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Failed sending email to $ManagerEmail : $($_.Exception.Message)"

    }
}

Add-Content $LogFile "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Script completed."
