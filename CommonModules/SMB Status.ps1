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
