$PngFile = "D:\Scripts\icon.png"
$IcoFile = "D:\Scripts\ADSecurityDashboard.ico"

$pngBytes = [System.IO.File]::ReadAllBytes($PngFile)

$fs = [System.IO.File]::Open($IcoFile, [System.IO.FileMode]::Create)

# ICO Header
$header = 0,0,1,0,1,0
$fs.Write($header,0,$header.Length)

# Directory Entry
$entry = 0,0,0,0,1,0,32,0
$fs.Write($entry,0,$entry.Length)

# PNG Size
$fs.Write([System.BitConverter]::GetBytes($pngBytes.Length),0,4)

# PNG Offset (6-byte header + 16-byte entry = 22)
$fs.Write([System.BitConverter]::GetBytes(22),0,4)

# PNG Data
$fs.Write($pngBytes,0,$pngBytes.Length)

$fs.Close()

Write-Host "ICO created: $IcoFile"


***********************************************************************

# Compile
Invoke-PS2EXE `
-InputFile "D:\Scripts\Audit Dashboard-MoreFeature.ps1" `
-OutputFile "D:\Scripts\ADSecurityConsole.exe" `
-IconFile "D:\Scripts\ADSecurityDashboard.ico" `
-Title "AD Security Console" `
-Description "Enterprise Active Directory Threat Monitoring Dashboard" `
-Company "Bhagawan Tapase" `
-Product "AD Security Console" `
-Copyright "Copyright © 2026" `
-Trademark "Bhagawan Tapase" `
-Version "1.0.0.0" `
-RequireAdmin `
-DPIAware `
-x64 `
-NoConsole `
-Verbose