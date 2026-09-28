#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Sends production Active Directory password-expiry notifications.
.DESCRIPTION
    Normal Users OU: sends email to the user's mail address.
    Admin Users OU: sends email only to the admin account's manager.
    Sends notifications when passwords expire in 10 through 0 calendar days.
    Writes processing results to a timestamped CSV log.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# 1. CONFIGURATION - VERIFY THESE VALUES BEFORE PRODUCTION USE
# ============================================================
$NormalUsersOU = 'OU=Users,OU=Test OU,DC=Domain,DC=com'
$AdminUsersOU  = 'OU=Admins,OU=Test OU,DC=Domain,DC=com'

$NotifyFromDays = 10
$NotifyToDays   = 0

$SmtpServer = 'YourRelayServer'
$SmtpPort   = 25
$UseSsl     = $false

$MailFromAddress = 'noreply@yourdomain.com'
$MailFromName    = 'IT Support'
$MailSubjectPrefix = '[Password Expiry]'

# Leave as $null when the SMTP relay does not require authentication.
$SmtpCredential = $null

$LogDirectory = 'D:\Account_Expiration\Password_Logs'
$LogFile = Join-Path -Path $LogDirectory -ChildPath ('PasswordExpiry_{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# ============================================================
# 2. HELPER FUNCTIONS
# ============================================================
function ConvertTo-HtmlSafe {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Add-LogEntry {
    param(
        [AllowNull()]$Log,
        [AllowEmptyString()][string]$UserType = '',
        [AllowEmptyString()][string]$SamAccountName = '',
        [AllowEmptyString()][string]$DisplayName = '',
        [AllowEmptyString()][string]$Recipient = '',
        [AllowNull()]$ExpiryDate,
        [AllowNull()]$DaysRemaining,
        [AllowEmptyString()][string]$Status = '',
        [AllowEmptyString()][string]$Details = ''
    )

    if ($null -eq $Log) {
        return
    }

    $expiryText = ''
    if ($null -ne $ExpiryDate) {
        $expiryText = ([datetime]$ExpiryDate).ToString('yyyy-MM-dd HH:mm:ss')
    }

    $daysText = ''
    if ($null -ne $DaysRemaining) {
        $daysText = [string]$DaysRemaining
    }

    $Log.Add([PSCustomObject]@{
        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        UserType       = $UserType
        SamAccountName = $SamAccountName
        DisplayName    = $DisplayName
        Recipient      = $Recipient
        PasswordExpiry = $expiryText
        DaysRemaining  = $daysText
        Status         = $Status
        Details        = $Details
    }) | Out-Null
}

function Test-EmailAddress {
    param([AllowNull()][string]$EmailAddress)

    if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
        return $false
    }

    try {
        $parsedAddress = New-Object System.Net.Mail.MailAddress($EmailAddress.Trim())
        return ($parsedAddress.Address -eq $EmailAddress.Trim())
    }
    catch {
        return $false
    }
}

function Get-PasswordExpiryDate {
    param([Parameter(Mandatory = $true)]$AdUser)

    $rawValue = $AdUser.'msDS-UserPasswordExpiryTimeComputed'

    if ($null -eq $rawValue) {
        return $null
    }

    try {
        $fileTime = [int64]$rawValue
    }
    catch {
        return $null
    }

    if ($fileTime -le 0 -or $fileTime -eq [int64]::MaxValue) {
        return $null
    }

    try {
        return [datetime]::FromFileTime($fileTime)
    }
    catch {
        return $null
    }
}

function Get-ManagerDetails {
    param([Parameter(Mandatory = $true)]$AdUser)

    if ([string]::IsNullOrWhiteSpace([string]$AdUser.Manager)) {
        return $null
    }

    try {
        return Get-ADUser -Identity $AdUser.Manager -Properties DisplayName,mail,Enabled -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function New-PasswordExpiryHtmlBody {
param(
    [Parameter(Mandatory = $true)][string]$GreetingName,
    [Parameter(Mandatory = $true)][string]$AffectedUserName,
    [Parameter(Mandatory = $true)][string]$SamAccountName,
    [Parameter(Mandatory = $true)][string]$Domain,
    [Parameter(Mandatory = $true)][int]$DaysRemaining,
    [Parameter(Mandatory = $true)][datetime]$ExpiryDate,
    [Parameter(Mandatory = $true)][ValidateSet('Normal','Admin')][string]$UserType
)

    $safeGreeting = ConvertTo-HtmlSafe -Text $GreetingName
    $safeUser = ConvertTo-HtmlSafe -Text $AffectedUserName
    $expiryText = ConvertTo-HtmlSafe -Text $ExpiryDate.ToString('dddd, dd MMMM yyyy')

    if ($DaysRemaining -eq 0) {
        $expiryMessage = '<strong style="color:#c62828;">The password expires today.</strong>'
    }
    elseif ($DaysRemaining -eq 1) {
        $expiryMessage = '<strong style="color:#c62828;">The password expires in 1 day.</strong>'
    }
    else {
        $expiryMessage = "<strong style='color:#c62828;'>The password expires in $DaysRemaining days.</strong>"
    }

    if ($UserType -eq 'Admin') {
        $intro = "The password for admin account <strong>$safeUser</strong> is approaching expiry. $expiryMessage"
        $actionText = 'Please coordinate the password reset before the expiry date.'
    }
    else {
        $intro = "Your Active Directory password is approaching expiry. $expiryMessage"
        $actionText = 'Please reset your password before it expires to avoid sign-in disruption.'
    }

    return @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f3f4f6;font-family:Segoe UI,Arial,sans-serif;color:#242424;">

<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f3f4f6;padding:24px 0;">
<tr><td align="center">

<table role="presentation" width="800" cellspacing="0" cellpadding="0" border="0" style="width:800px;max-width:98%;background:#ffffff;border:1px solid #e1e1e1;border-radius:8px;overflow:hidden;">
<tr><td style="background:#005a9e;color:#ffffff;padding:20px 32px;font-size:22px;font-weight:600;">Password Expiry Notification</td></tr>
<tr><td style="padding:32px;">
<p style="margin:0 0 18px 0;font-size:16px;">Hi $safeGreeting,</p>
<p style="margin:0 0 16px 0;font-size:15px;line-height:1.6;">$intro</p>

<table role="presentation"
       width="100%"
       cellspacing="0"
       cellpadding="0"
       border="1"
       style="border-collapse:collapse;
              font-family:Segoe UI,Arial,sans-serif;
              font-size:14px;
              mso-table-lspace:0pt;
              mso-table-rspace:0pt;
              margin:15px 0;">

    <tr style="background-color:#005a9e;color:#ffffff;">

        <th width="30%"
            align="left"
            nowrap
            style="padding:8px;color:#ffffff;font-weight:bold;">
            Display Name
        </th>

        <th width="20%"
            align="left"
            nowrap
            style="padding:8px;color:#ffffff;font-weight:bold;">
            SamAccountName
        </th>

        <th width="15%"
            align="left"
            nowrap
            style="padding:8px;color:#ffffff;font-weight:bold;">
            Domain
        </th>

        <th width="20%"
            align="left"
            nowrap
            style="padding:8px;color:#ffffff;font-weight:bold;">
            Expiry Date
        </th>

        <th width="15%"
            align="left"
            nowrap
            style="padding:8px;color:#ffffff;font-weight:bold;">
            Days Left
        </th>

    </tr>

    <tr>

        <td nowrap style="padding:8px;border:1px solid #d0d0d0;">
            $safeUser
        </td>

        <td nowrap style="padding:8px;border:1px solid #d0d0d0;">
            $SamAccountName
        </td>

        <td nowrap style="padding:8px;border:1px solid #d0d0d0;">
            $Domain
        </td>

        <td nowrap style="padding:8px;border:1px solid #d0d0d0;">
            $expiryText
        </td>

        <td nowrap style="padding:8px;border:1px solid #d0d0d0;">
            $DaysRemaining
        </td>

    </tr>

</table>


<p style="margin:0 0 22px 0;font-size:15px;line-height:1.6;">$actionText You can use either option below:</p>

<table role="presentation" cellspacing="0" cellpadding="0" border="0">
<tr>
<td style="padding:0 12px 12px 0;"><a href="https://your-company-passwordreset-url" style="display:inline-block;background:#107c10;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 18px;border-radius:4px;">🔒Reset Password using SSPR</a></td> 
<td style="padding:0 0 12px 0;"><a href="https://your-company-helpdesk-url" style="display:inline-block;background:#005a9e;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 18px;border-radius:4px;">🎟ServiceNow Create Ticket</a></td> 
</tr>
</table>
<p style="margin:18px 0 0 0;font-size:13px;color:#605e5c;line-height:1.5;">This is an automated notification. If the password has already been reset, no further action is required.</p>
<p style="font-size:12px;color:#666666;">


</td></tr>
<tr><td style="background:#f8f9fa;padding:14px 28px;font-size:12px;color:#605e5c;">IT Support</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"@
}

function Send-HtmlMail {
    param(
        [Parameter(Mandatory = $true)][string]$To,
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$Body
    )

    if (-not (Test-EmailAddress -EmailAddress $To)) {
        throw "Invalid recipient email address: $To"
    }

    if (-not (Test-EmailAddress -EmailAddress $MailFromAddress)) {
        throw "Invalid sender email address: $MailFromAddress"
    }

    $mailMessage = $null
    $smtpClient = $null

    try {
        $mailMessage = New-Object System.Net.Mail.MailMessage
        $mailMessage.From = New-Object System.Net.Mail.MailAddress($MailFromAddress, $MailFromName)
        $mailMessage.To.Add($To)
        $mailMessage.Subject = $Subject
        $mailMessage.Body = $Body
        $mailMessage.IsBodyHtml = $true
        $mailMessage.BodyEncoding = [System.Text.Encoding]::UTF8
        $mailMessage.SubjectEncoding = [System.Text.Encoding]::UTF8

        $smtpClient = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtpClient.EnableSsl = $UseSsl

        if ($null -ne $SmtpCredential) {
            $smtpClient.UseDefaultCredentials = $false
            $smtpClient.Credentials = $SmtpCredential.GetNetworkCredential()
        }
        else {
            $smtpClient.UseDefaultCredentials = $false
        }

        $smtpClient.Send($mailMessage)
    }
    finally {
        if ($null -ne $mailMessage) { $mailMessage.Dispose() }
        if ($null -ne $smtpClient) { $smtpClient.Dispose() }
    }
}

function Process-OuUsers {
    param(
        [Parameter(Mandatory = $true)][string]$SearchBase,
        [Parameter(Mandatory = $true)][ValidateSet('Normal','Admin')][string]$UserType,
        [AllowNull()]$Log
    )

    $properties = @(
        'DisplayName',
        'mail',
        'Manager',
        'PasswordNeverExpires',
        'PasswordLastSet',
        'msDS-UserPasswordExpiryTimeComputed'
    )

    try {
        $users = @(Get-ADUser -SearchBase $SearchBase -SearchScope Subtree -Filter 'Enabled -eq $true' -Properties $properties -ErrorAction Stop)
    }
    catch {
        Add-LogEntry -Log $Log -UserType $UserType -Status 'OU_QUERY_FAILED' -Details $_.Exception.Message
        return
    }

    foreach ($user in $users) {
        $displayName = $user.DisplayName
        if ([string]::IsNullOrWhiteSpace($displayName)) {
            $displayName = $user.SamAccountName
        }

        if ($user.PasswordNeverExpires -eq $true) {
            Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Status 'SKIPPED' -Details 'PasswordNeverExpires is enabled.'
            continue
        }

        if ($null -eq $user.PasswordLastSet) {
            Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Status 'SKIPPED' -Details 'PasswordLastSet is empty.'
            continue
        }

        $expiryDate = Get-PasswordExpiryDate -AdUser $user
        if ($null -eq $expiryDate) {
            Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Status 'SKIPPED' -Details 'Password expiry date could not be calculated or the effective policy does not expire passwords.'
            continue
        }

        $daysRemaining = [int](New-TimeSpan -Start (Get-Date).Date -End $expiryDate.Date).TotalDays
        if ($daysRemaining -gt $NotifyFromDays -or $daysRemaining -lt $NotifyToDays) {
            continue
        }

        $recipient = ''
        $greetingName = ''

        if ($UserType -eq 'Normal') {
            if ([string]::IsNullOrWhiteSpace([string]$user.mail)) {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SKIPPED' -Details 'User mail attribute is empty.'
                continue
            }

            $recipient = $user.mail.Trim()
            $greetingName = $displayName

            if (-not (Test-EmailAddress -EmailAddress $recipient)) {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Recipient $recipient -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SKIPPED' -Details 'User mail attribute is invalid.'
                continue
            }
        }
        else {
            $manager = Get-ManagerDetails -AdUser $user

            if ($null -eq $manager) {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SKIPPED' -Details 'Manager is not configured or could not be retrieved.'
                continue
            }

            if ($manager.Enabled -ne $true) {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SKIPPED' -Details 'Manager account is disabled.'
                continue
            }

            if ([string]::IsNullOrWhiteSpace([string]$manager.mail)) {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SKIPPED' -Details 'Manager mail attribute is empty.'
                continue
            }

            $recipient = $manager.mail.Trim()
            if (-not (Test-EmailAddress -EmailAddress $recipient)) {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Recipient $recipient -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SKIPPED' -Details 'Manager mail attribute is invalid.'
                continue
            }

            if ([string]::IsNullOrWhiteSpace([string]$manager.DisplayName)) {
                $greetingName = $manager.SamAccountName
            }
            else {
                $greetingName = $manager.DisplayName
            }
        }

        if ($daysRemaining -eq 0) {
            $remainingText = 'Expires today'
        }
        elseif ($daysRemaining -eq 1) {
            $remainingText = '1 day remaining'
        }
        else {
            $remainingText = "$daysRemaining days remaining"
        }

        $subject = "$MailSubjectPrefix $displayName - $remainingText"
        $body = New-PasswordExpiryHtmlBody `
    -GreetingName $greetingName `
    -AffectedUserName $displayName `
    -SamAccountName $user.SamAccountName `
    -Domain $env:USERDNSDOMAIN `
    -DaysRemaining $daysRemaining `
    -ExpiryDate $expiryDate `
    -UserType $UserType

        try {
            if ($PSCmdlet.ShouldProcess($recipient, "Send password-expiry notification for $($user.SamAccountName)")) {
                Send-HtmlMail -To $recipient -Subject $subject -Body $body
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Recipient $recipient -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'SENT' -Details 'Notification sent successfully.'
            }
            else {
                Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Recipient $recipient -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'WHATIF' -Details 'Notification was not sent because WhatIf or confirmation prevented the action.'
            }
        }
        catch {
            Add-LogEntry -Log $Log -UserType $UserType -SamAccountName $user.SamAccountName -DisplayName $displayName -Recipient $recipient -ExpiryDate $expiryDate -DaysRemaining $daysRemaining -Status 'FAILED' -Details $_.Exception.Message
        }
    }
}

# ============================================================
# 3. MAIN EXECUTION
# ============================================================
$logEntries = New-Object 'System.Collections.Generic.List[object]'
$scriptFailed = $false

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if ($NotifyFromDays -lt $NotifyToDays) {
        throw 'NotifyFromDays must be greater than or equal to NotifyToDays.'
    }

    if ([string]::IsNullOrWhiteSpace($SmtpServer)) {
        throw 'SmtpServer is not configured.'
    }

    if (-not (Test-EmailAddress -EmailAddress $MailFromAddress)) {
        throw "MailFromAddress is invalid: $MailFromAddress"
    }

    Get-ADOrganizationalUnit -Identity $NormalUsersOU -ErrorAction Stop | Out-Null
    Get-ADOrganizationalUnit -Identity $AdminUsersOU -ErrorAction Stop | Out-Null

    Process-OuUsers -SearchBase $NormalUsersOU -UserType 'Normal' -Log $logEntries
    Process-OuUsers -SearchBase $AdminUsersOU -UserType 'Admin' -Log $logEntries
}
catch {
    $scriptFailed = $true
    Add-LogEntry -Log $logEntries -UserType 'Script' -Status 'SCRIPT_FAILED' -Details $_.Exception.Message
    Write-Error -Message $_.Exception.Message
}
finally {
    try {
        if (-not (Test-Path -LiteralPath $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        if ($logEntries.Count -eq 0) {
            Add-LogEntry -Log $logEntries -UserType 'Script' -Status 'COMPLETED' -Details 'No users required notification during this run.'
        }
        elseif (-not $scriptFailed) {
            Add-LogEntry -Log $logEntries -UserType 'Script' -Status 'COMPLETED' -Details 'Script execution completed.'
        }

        $logEntries | Export-Csv -LiteralPath $LogFile -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "Completed. CSV log: $LogFile" -ForegroundColor Green
    }
    catch {
        Write-Error -Message ("Unable to write the CSV log. " + $_.Exception.Message)
    }
}
