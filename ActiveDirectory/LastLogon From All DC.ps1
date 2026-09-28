#$(foreach ($DC in ((get-addomaincontroller -filter * | sort name).name) ){ $user = get-aduser a-btapase -properties lastlogon –server $dc | select name,lastlogon ; echo "$DC - $($user.lastlogon)" }  )

#Search-ADAccount -AccountInactive -DateTime ((get-date).adddays(-90)) -UsersOnly

$DCs = Get-ADDomainController -Filter * | Sort-Object Name
foreach ($DC in $DCs) {
    try {
        $user = Get-ADUser -Identity DXK3496 -Properties LastLogon, LastLogonDate -Server $DC.HostName
        $lastLogon = [DateTime]::FromFileTime($user.LastLogon)
        $lastLogonDate = $user.LastLogonDate
        Write-Output "$($DC.Name) - LastLogon: $lastLogon, LastLogonDate: $lastLogonDate"
    } catch {
        Write-Output "$($DC.Name) - Unable to contact the server."
    }
}
