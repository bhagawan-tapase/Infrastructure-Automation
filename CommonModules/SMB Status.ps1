<#
Script Name : SMB_Security_Compliance_Check.ps1

Description :
This PowerShell script performs a security compliance assessment of SMB configuration on a Windows system. The script verifies whether the legacy SMBv1 protocol is enabled and checks the current SMB Signing configuration. Results are displayed in an easy-to-read format to help administrators identify systems that do not meet security hardening standards.

Key Features:
✅ Checks SMBv1 Server status
✅ Checks SMBv1 Client feature status
✅ Determines whether SMBv1 is enabled or disabled
✅ Verifies SMB Signing configuration
✅ Displays security signature requirements
✅ Provides clear compliance results
✅ Useful for security audits and hardening assessments
✅ Read-only validation with no configuration changes

Output:
- SMBv1 status (Enabled/Disabled)
- SMB Signing status (Enabled/Disabled)
- Security Signature configuration details
#>

Write-Host "===== SMBv1 Status =====" -ForegroundColor Cyan

# SMBv1 Server
$SMB1Server = (Get-SmbServerConfiguration).EnableSMB1Protocol

# SMBv1 Client
$SMB1Client = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State

Write-Host "SMBv1 Server Enabled : $SMB1Server"
Write-Host "SMBv1 Client State   : $SMB1Client"

if ($SMB1Server -eq $False -and $SMB1Client -ne "Enabled") {
    Write-Host "Result: SMBv1 is DISABLED" -ForegroundColor Green
} else {
    Write-Host "Result: SMBv1 is ENABLED" -ForegroundColor Red
}

Write-Host ""
Write-Host "===== SMB Signing Status =====" -ForegroundColor Cyan

$SMBConfig = Get-SmbServerConfiguration

Write-Host "Require Security Signature : $($SMBConfig.RequireSecuritySignature)"
Write-Host "Enable Security Signature  : $($SMBConfig.EnableSecuritySignature)"

if ($SMBConfig.EnableSecuritySignature -eq $True) {
    Write-Host "Result: SMB Signing is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Result: SMB Signing is DISABLED" -ForegroundColor Red
}
