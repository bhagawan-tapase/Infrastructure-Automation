# Define all groups from the hierarchy
$groupsToCheck = @(
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "CC_L1_Admins",
    "CC_ServiceDesk",
    "mel-iv-impulse_administrators",
    "mel-iv-impora_administrator",
    "CC_Network_Team",
    "CC_FST_Admins",
    "CC_Helpdesk Admins"
)

# Cache direct group members
$directGroupMembers = @{}
$logErrors = @()

foreach ($group in $groupsToCheck) {
    try {
        $directGroupMembers[$group] = Get-ADGroupMember -Identity $group |
            Where-Object { $_.objectClass -eq 'user' } |
            Select-Object -ExpandProperty SamAccountName
    } catch {
        Write-Host "❌ Error fetching members for group: $group" -ForegroundColor Red
        $logErrors += "Error fetching members for group: $group - $($_.Exception.Message)"
        $directGroupMembers[$group] = @()
    }
}

# Save errors to a log file
if ($logErrors.Count -gt 0) {
    $logErrors | Out-File -FilePath "D:\GroupFetchErrors.log" -Encoding UTF8
}

# Get all users with required properties
$allUsers = Get-ADUser -Filter * -Properties DisplayName, SamAccountName, Enabled, Manager, whenCreated, CanonicalName

# Build result
$result = foreach ($user in $allUsers) {
    $userGroups = @()
    foreach ($group in $groupsToCheck) {
        if ($directGroupMembers[$group] -contains $user.SamAccountName) {
            $userGroups += $group
        }
    }

    [PSCustomObject]@{
        DisplayName    = $user.DisplayName
        SamAccountName = $user.SamAccountName
        Enabled        = $user.Enabled
        Manager        = $user.Manager
        CreatedDate    = $user.whenCreated
        OU             = ($user.CanonicalName -replace '^.*?/', '') # Extract OU
        Groups         = ($userGroups -join ", ")
    }
}

# Export to CSV
$result | Export-Csv -Path "D:\UserGroupMembership_DirectOnly1.csv" -NoTypeInformation -Encoding UTF8
Write-Host "✅ Export complete: D:\UserGroupMembership_DirectOnly1.csv"
