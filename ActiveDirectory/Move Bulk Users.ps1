# Define the target OU at the top
$TargetOU = "OU=All_Disabled_Users,DC=Domain,DC=com"

# Path to the CSV file
$CSVPath = "D:\Users.csv"

# Import the CSV
$Users = Import-Csv -Path $CSVPath

foreach ($User in $Users) {
    $SamAccountName = $User.SamAccountName

    # Get the user object
    $ADUser = Get-ADUser -Identity $SamAccountName -ErrorAction SilentlyContinue

    if ($ADUser) {
        # Move the user to the target OU
        Move-ADObject -Identity $ADUser.DistinguishedName -TargetPath $TargetOU
        Write-Host "Moved $SamAccountName to $TargetOU"
    } else {
        Write-Warning "User $SamAccountName not found in AD."
    }
}
