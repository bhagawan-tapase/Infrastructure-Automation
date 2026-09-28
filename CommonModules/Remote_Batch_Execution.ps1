<#
Script Name : Remote_Batch_Execution.ps1

Description :
This PowerShell script automates the deployment and execution of a batch file on a remote Windows server using PowerShell Remoting (WinRM). The script establishes a remote PowerShell session, securely copies a batch file from a network share to the target system, executes the batch file remotely, and then closes the session after completion.

Key Features:
✅ PowerShell Remoting (PSSession) support
✅ Secure credential-based authentication
✅ Automated file transfer from network share to remote server
✅ Remote batch file execution
✅ Temporary file deployment to target system
✅ Session cleanup after execution
✅ Reduces manual intervention for remote administrative tasks
✅ Suitable for software deployment, maintenance, remediation, and BitLocker-related operations

Workflow:
1. Prompt for administrator credentials.
2. Create a PowerShell session to the target server.
3. Copy the batch file from a network share to the remote machine.
4. Execute the batch file remotely.
5. Close and remove the PowerShell session.

Requirements:
- PowerShell Remoting (WinRM) enabled.
- Administrative access to the target device.
- Network access to the source file share.
- Required execution permissions on the remote system.
#>

# create session
$cred = Get-Credential
$s = New-PSSession -ComputerName AGS-ID-GX13664 -Credential $cred

# copy the .bat from UNC to remote local temp
Copy-Item -Path '\\ags-av-ads2\Decryption_Logs\Bitlocker_Decrypt.bat' -Destination 'C:\Windows\Temp\script.bat' -ToSession $s

# run it on the remote machine
Invoke-Command -Session $s -ScriptBlock {
    Start-Process -FilePath 'C:\Windows\Temp\script.bat' -NoNewWindow -Wait
}

# cleanup
Remove-PSSession $s
