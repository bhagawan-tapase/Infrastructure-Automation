# Get a specific user from Active Directory
$user = Get-ADUser -Identity "SamAccountName" -Properties 'DisplayName', 'pwdLastSet', 'PasswordLastSet', 'PasswordNeverExpires', 'msDS-UserPasswordExpiryTimeComputed', 'LastLogon', 'LastLogonTimestamp'

# Calculate the required properties
$daysSincePasswordLastSet = $null
$passwordExpiryDate = $null
$passwordExpiresInDays = $null

# Check if the PasswordLastSet attribute is valid
if ($user.PasswordLastSet) {
    $daysSincePasswordLastSet = (Get-Date) - $user.PasswordLastSet
}

# Check if the msDS-UserPasswordExpiryTimeComputed attribute is valid and within a valid range
if ($user."msDS-UserPasswordExpiryTimeComputed" -and $user."msDS-UserPasswordExpiryTimeComputed" -gt 0) {
    $passwordExpiryDate = [datetime]::FromFileTime($user."msDS-UserPasswordExpiryTimeComputed")
    $passwordExpiresInDays = ($passwordExpiryDate - (Get-Date)).Days
}

# Create a custom object with the desired properties and convert dates to DD-MM-YYYY HH:MM format
$userData = [PSCustomObject]@{
    DisplayName                = $user.DisplayName
    Username                   = $user.SamAccountName
    LastPasswordSet            = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("dd-MM-yyyy HH:mm") } else { $null }
    PasswordNeverExpires       = $user.PasswordNeverExpires
    PasswordExpiryDate         = if ($passwordExpiryDate) { $passwordExpiryDate.ToString("dd-MM-yyyy HH:mm") } else { $null }
    DaysSincePasswordLastSet   = if ($daysSincePasswordLastSet) { $daysSincePasswordLastSet.Days } else { $null }
    PasswordExpiresInDays      = $passwordExpiresInDays
    LastLogon                  = if ($user.LastLogon) { [datetime]::FromFileTime($user.LastLogon).ToString("dd-MM-yyyy HH:mm") } else { $null }
    LastLogonTimestamp         = if ($user.LastLogonTimestamp) { [datetime]::FromFileTime($user.LastLogonTimestamp).ToString("dd-MM-yyyy HH:mm") } else { $null }
}

# Output the user data
$userData
