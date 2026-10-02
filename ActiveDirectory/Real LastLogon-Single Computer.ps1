$DCs = Get-ADDomainController -Filter *
$Hostname = 'Hostname'
$MaxLastLogon = 0
$LastLogonDC = $null

foreach ($DC in $DCs) {

    $ADComputer = Get-ADComputer `
        -Identity $Hostname `
        -Server $DC.HostName `
        -Properties lastLogon

    if ([Int64]$ADComputer.lastLogon -gt $MaxLastLogon) {
        $MaxLastLogon = [Int64]$ADComputer.lastLogon
        $LastLogonDC = $DC.HostName
    }
}

[PSCustomObject]@{
    ComputerName = $Hostname
    RealLastLogon = [System.DateTime]::FromFileTimeUtc($MaxLastLogon).ToString('dd/MM/yyyy')
    LastLogonDC = $LastLogonDC
} | Format-List
