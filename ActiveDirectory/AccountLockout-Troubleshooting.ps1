#requires -Version 5.1
#requires -Modules ActiveDirectory

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module ActiveDirectory -ErrorAction Stop
[System.Windows.Forms.Application]::EnableVisualStyles()

$Theme = @{
    Bg      = '#1E2227'
    Card    = '#24292F'
    Field   = '#2C323A'
    Text    = '#F0F0F0'
    Muted   = '#B8C0CC'
    Accent  = '#0E7AC7'
    Success = '#49B06E'
    Warn    = '#D18A3B'
    Error   = '#E05A5A'
    Border  = '#3A424B'
}

function Convert-HexColor {
    param([Parameter(Mandatory)][string]$Hex)
    [System.Drawing.ColorTranslator]::FromHtml($Hex)
}

$script:ValidatedUser = $null
$script:ValidatedDC = $null
$script:SearchPowerShell = $null
$script:SearchAsync = $null

# ---------------- Form ----------------
$Form = New-Object System.Windows.Forms.Form
$Form.Text = 'AD Account Lockout Investigation'
$Form.StartPosition = 'CenterScreen'
$Form.FormBorderStyle = 'FixedDialog'
$Form.MaximizeBox = $false
$Form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None
$Form.Size = New-Object System.Drawing.Size(845,565)
$Form.MinimumSize = $Form.Size
$Form.MaximumSize = $Form.Size
$Form.Font = New-Object System.Drawing.Font('Segoe UI',9)

$TitleLabel = New-Object System.Windows.Forms.Label
$TitleLabel.Location = New-Object System.Drawing.Point(14,10)
$TitleLabel.Size = New-Object System.Drawing.Size(780,24)
$TitleLabel.Text = 'Active Directory Account Lockout Investigation'
$TitleLabel.Font = New-Object System.Drawing.Font('Segoe UI',12,[System.Drawing.FontStyle]::Bold)
$Form.Controls.Add($TitleLabel)

$SubtitleLabel = New-Object System.Windows.Forms.Label
$SubtitleLabel.Location = New-Object System.Drawing.Point(15,34)
$SubtitleLabel.Size = New-Object System.Drawing.Size(785,18)
$SubtitleLabel.Text = 'Validate a user, check status, search lockout events and unlock the account.'
$SubtitleLabel.Font = New-Object System.Drawing.Font('Segoe UI',8)
$Form.Controls.Add($SubtitleLabel)

# ---------------- Search controls ----------------
$SearchGroup = New-Object System.Windows.Forms.GroupBox
$SearchGroup.Location = New-Object System.Drawing.Point(12,58)
$SearchGroup.Size = New-Object System.Drawing.Size(805,125)
$SearchGroup.Text = 'Search Options'
$Form.Controls.Add($SearchGroup)

$DCLabel = New-Object System.Windows.Forms.Label
$DCLabel.Location = New-Object System.Drawing.Point(10,27)
$DCLabel.Size = New-Object System.Drawing.Size(112,22)
$DCLabel.Text = 'Domain Controller:'
$SearchGroup.Controls.Add($DCLabel)

$DCComboBox = New-Object System.Windows.Forms.ComboBox
$DCComboBox.Location = New-Object System.Drawing.Point(122,24)
$DCComboBox.Size = New-Object System.Drawing.Size(290,25)
$DCComboBox.DropDownWidth = 390
$DCComboBox.DropDownStyle = 'DropDownList'
$SearchGroup.Controls.Add($DCComboBox)

$RefreshDCButton = New-Object System.Windows.Forms.Button
$RefreshDCButton.Location = New-Object System.Drawing.Point(420,23)
$RefreshDCButton.Size = New-Object System.Drawing.Size(85,27)
$RefreshDCButton.Text = 'Refresh DC'
$SearchGroup.Controls.Add($RefreshDCButton)

$EventLabel = New-Object System.Windows.Forms.Label
$EventLabel.Location = New-Object System.Drawing.Point(520,27)
$EventLabel.Size = New-Object System.Drawing.Size(62,22)
$EventLabel.Text = 'Event ID:'
$SearchGroup.Controls.Add($EventLabel)

$EventComboBox = New-Object System.Windows.Forms.ComboBox
$EventComboBox.Location = New-Object System.Drawing.Point(582,24)
$EventComboBox.Size = New-Object System.Drawing.Size(205,25)
$EventComboBox.DropDownWidth = 205
$EventComboBox.DropDownStyle = 'DropDownList'
[void]$EventComboBox.Items.Add('Both - 4771 and 4740')
[void]$EventComboBox.Items.Add('4771 - Kerberos Failure')
[void]$EventComboBox.Items.Add('4740 - Account Lockout')
$EventComboBox.SelectedIndex = 0
$SearchGroup.Controls.Add($EventComboBox)

$UserLabel = New-Object System.Windows.Forms.Label
$UserLabel.Location = New-Object System.Drawing.Point(10,75)
$UserLabel.Size = New-Object System.Drawing.Size(112,22)
$UserLabel.Text = 'sAMAccountName:'
$SearchGroup.Controls.Add($UserLabel)

$UserTextBox = New-Object System.Windows.Forms.TextBox
$UserTextBox.Location = New-Object System.Drawing.Point(122,72)
$UserTextBox.Size = New-Object System.Drawing.Size(190,25)
$UserTextBox.MaxLength = 64
$SearchGroup.Controls.Add($UserTextBox)

$ValidateButton = New-Object System.Windows.Forms.Button
$ValidateButton.Location = New-Object System.Drawing.Point(320,70)
$ValidateButton.Size = New-Object System.Drawing.Size(95,28)
$ValidateButton.Text = 'Validate User'
$SearchGroup.Controls.Add($ValidateButton)

$SearchButton = New-Object System.Windows.Forms.Button
$SearchButton.Location = New-Object System.Drawing.Point(423,70)
$SearchButton.Size = New-Object System.Drawing.Size(100,28)
$SearchButton.Text = 'Search Events'
$SearchGroup.Controls.Add($SearchButton)

$ClearButton = New-Object System.Windows.Forms.Button
$ClearButton.Location = New-Object System.Drawing.Point(531,70)
$ClearButton.Size = New-Object System.Drawing.Size(68,28)
$ClearButton.Text = 'Clear'
$SearchGroup.Controls.Add($ClearButton)

$RangeLabel = New-Object System.Windows.Forms.Label
$RangeLabel.Location = New-Object System.Drawing.Point(615,75)
$RangeLabel.Size = New-Object System.Drawing.Size(50,22)
$RangeLabel.Text = 'Range:'
$SearchGroup.Controls.Add($RangeLabel)

$RangeComboBox = New-Object System.Windows.Forms.ComboBox
$RangeComboBox.Location = New-Object System.Drawing.Point(665,72)
$RangeComboBox.Size = New-Object System.Drawing.Size(122,25)
$RangeComboBox.DropDownWidth = 122
$RangeComboBox.DropDownStyle = 'DropDownList'
1..7 | ForEach-Object {
    $suffix = if ($_ -eq 1) { '' } else { 's' }
    [void]$RangeComboBox.Items.Add(('{0} day{1}' -f $_,$suffix))
}
$RangeComboBox.SelectedIndex = 1
$SearchGroup.Controls.Add($RangeComboBox)

# ---------------- User status ----------------
$StatusGroup = New-Object System.Windows.Forms.GroupBox
$StatusGroup.Location = New-Object System.Drawing.Point(12,193)
$StatusGroup.Size = New-Object System.Drawing.Size(805,140)
$StatusGroup.Text = 'User Validation and Current Status'
$Form.Controls.Add($StatusGroup)

function Add-StatusPair {
    param(
        [string]$Caption,
        [int]$CaptionX,
        [int]$ValueX,
        [int]$Y,
        [int]$CaptionWidth,
        [int]$ValueWidth
    )

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point($CaptionX,$Y)
    $label.Size = New-Object System.Drawing.Size($CaptionWidth,21)
    $label.Text = $Caption
    $StatusGroup.Controls.Add($label)

    $value = New-Object System.Windows.Forms.Label
    $value.Location = New-Object System.Drawing.Point($ValueX,$Y)
    $value.Size = New-Object System.Drawing.Size($ValueWidth,21)
    $value.Text = '-'
    $StatusGroup.Controls.Add($value)

    $value
}

$DisplayNameValue = Add-StatusPair 'Display Name:'      10 100 27 90 210
$SamAccountValue = Add-StatusPair 'SAM Account:'       320 410 27 90 110
$EnabledValue = Add-StatusPair 'Account Status:'       530 635 27 105 85
$UPNValue = Add-StatusPair 'UPN:'                      10 100 57 90 275
$LockedValue = Add-StatusPair 'Lockout Status:'        385 485 57 100 100
$PasswordExpiredValue = Add-StatusPair 'Password Expired:' 10 135 87 125 70
$LastBadPasswordValue = Add-StatusPair 'Last Bad Password:' 220 350 87 130 205

$UnlockButton = New-Object System.Windows.Forms.Button
$UnlockButton.Location = New-Object System.Drawing.Point(665,82)
$UnlockButton.Size = New-Object System.Drawing.Size(125,34)
$UnlockButton.Text = 'Unlock User'
$UnlockButton.Enabled = $false
$StatusGroup.Controls.Add($UnlockButton)

# ---------------- Grid / progress / status ----------------
$DataGrid = New-Object System.Windows.Forms.DataGridView
$DataGrid.Location = New-Object System.Drawing.Point(12,343)
$DataGrid.Size = New-Object System.Drawing.Size(805,155)
$DataGrid.ReadOnly = $true
$DataGrid.AllowUserToAddRows = $false
$DataGrid.AllowUserToDeleteRows = $false
$DataGrid.RowHeadersVisible = $false
$DataGrid.SelectionMode = 'FullRowSelect'
$DataGrid.AutoSizeColumnsMode = 'Fill'
$DataGrid.ColumnHeadersHeight = 25
$DataGrid.RowTemplate.Height = 22
$Form.Controls.Add($DataGrid)

$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Location = New-Object System.Drawing.Point(12,505)
$ProgressBar.Size = New-Object System.Drawing.Size(805,6)
$ProgressBar.Style = 'Marquee'
$ProgressBar.MarqueeAnimationSpeed = 30
$ProgressBar.Visible = $false
$Form.Controls.Add($ProgressBar)

$StatusLabel = New-Object System.Windows.Forms.Label
$StatusLabel.Location = New-Object System.Drawing.Point(14,518)
$StatusLabel.Size = New-Object System.Drawing.Size(800,22)
$StatusLabel.Text = 'Ready.'
$Form.Controls.Add($StatusLabel)

# ---------------- Helpers ----------------
function Set-StatusMessage {
    param(
        [string]$Message,
        [System.Drawing.Color]$Color
    )

    $StatusLabel.Text = $Message
    $StatusLabel.ForeColor = $Color
}

function Set-BusyState {
    param([bool]$Busy)

    $SearchButton.Enabled = -not $Busy
    $ValidateButton.Enabled = -not $Busy
    $RefreshDCButton.Enabled = -not $Busy
    $EventComboBox.Enabled = -not $Busy
    $RangeComboBox.Enabled = -not $Busy
    $DCComboBox.Enabled = -not $Busy
    $UserTextBox.Enabled = -not $Busy
    $ClearButton.Enabled = -not $Busy
    $ProgressBar.Visible = $Busy

    if ($Busy) {
        $UnlockButton.Enabled = $false
    }
}

function Reset-UserInformation {
    $script:ValidatedUser = $null
    $script:ValidatedDC = $null

    $DisplayNameValue.Text = '-'
    $SamAccountValue.Text = '-'
    $UPNValue.Text = '-'
    $EnabledValue.Text = '-'
    $LockedValue.Text = '-'
    $PasswordExpiredValue.Text = '-'
    $LastBadPasswordValue.Text = '-'

    $EnabledValue.ForeColor = Convert-HexColor $Theme.Muted
    $LockedValue.ForeColor = Convert-HexColor $Theme.Muted
    $PasswordExpiredValue.ForeColor = Convert-HexColor $Theme.Muted
    $UnlockButton.Enabled = $false
}

function Test-Inputs {
    $sam = $UserTextBox.Text.Trim()
    $dc = [string]$DCComboBox.SelectedItem

    if ([string]::IsNullOrWhiteSpace($dc)) {
        Set-StatusMessage 'Select a domain controller.' (Convert-HexColor $Theme.Error)
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($sam)) {
        Set-StatusMessage 'Enter a sAMAccountName.' (Convert-HexColor $Theme.Error)
        $UserTextBox.Focus()
        return $false
    }

    if ($sam -notmatch '^[A-Za-z0-9._-]+$') {
        Set-StatusMessage 'Invalid sAMAccountName. Use letters, numbers, dot, underscore or hyphen.' (Convert-HexColor $Theme.Error)
        return $false
    }

    return $true
}

function Update-UserStatus {
    param(
        [string]$SamAccountName,
        [string]$DomainController
    )

    try {
        Set-StatusMessage "Validating '$SamAccountName' on $DomainController..." (Convert-HexColor $Theme.Warn)

        $user = Get-ADUser `
            -Identity $SamAccountName `
            -Server $DomainController `
            -Properties DisplayName,UserPrincipalName,Enabled,LockedOut,PasswordExpired,LastBadPasswordAttempt `
            -ErrorAction Stop

        $script:ValidatedUser = $user
        $script:ValidatedDC = $DomainController

        $DisplayNameValue.Text = if ([string]::IsNullOrWhiteSpace($user.DisplayName)) { '-' } else { $user.DisplayName }
        $SamAccountValue.Text = $user.SamAccountName
        $UPNValue.Text = if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName)) { '-' } else { $user.UserPrincipalName }

        $EnabledValue.Text = if ($user.Enabled) { 'Enabled' } else { 'Disabled' }
        $EnabledValue.ForeColor = if ($user.Enabled) { Convert-HexColor $Theme.Success } else { Convert-HexColor $Theme.Error }

        $LockedValue.Text = if ($user.LockedOut) { 'Locked' } else { 'Not Locked' }
        $LockedValue.ForeColor = if ($user.LockedOut) { Convert-HexColor $Theme.Error } else { Convert-HexColor $Theme.Success }

        $PasswordExpiredValue.Text = if ($user.PasswordExpired) { 'Yes' } else { 'No' }
        $PasswordExpiredValue.ForeColor = if ($user.PasswordExpired) { Convert-HexColor $Theme.Error } else { Convert-HexColor $Theme.Success }

        $LastBadPasswordValue.Text = if ($null -eq $user.LastBadPasswordAttempt) {
            'No value available'
        }
        else {
            $user.LastBadPasswordAttempt.ToString('dd/MM/yyyy HH:mm:ss')
        }

        $UnlockButton.Enabled = [bool]$user.LockedOut
        Set-StatusMessage "User '$SamAccountName' validated successfully." (Convert-HexColor $Theme.Success)
        return $true
    }
    catch {
        Reset-UserInformation
        Set-StatusMessage "User validation failed: $($_.Exception.Message)" (Convert-HexColor $Theme.Error)
        return $false
    }
}

function Load-LocalDomainController {
    $DCComboBox.Items.Clear()

    try {
        $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
        [void]$DCComboBox.Items.Add($dc.HostName)
    }
    catch {
        [void]$DCComboBox.Items.Add($env:COMPUTERNAME)
    }

    $DCComboBox.SelectedIndex = 0
    Set-StatusMessage "Using domain controller: $($DCComboBox.SelectedItem)" (Convert-HexColor $Theme.Success)
}

function Apply-DarkTheme {
    $bg = Convert-HexColor $Theme.Bg
    $card = Convert-HexColor $Theme.Card
    $field = Convert-HexColor $Theme.Field
    $text = Convert-HexColor $Theme.Text
    $muted = Convert-HexColor $Theme.Muted
    $accent = Convert-HexColor $Theme.Accent
    $success = Convert-HexColor $Theme.Success
    $border = Convert-HexColor $Theme.Border

    $Form.BackColor = $bg
    $Form.ForeColor = $text
    $TitleLabel.ForeColor = $text
    $SubtitleLabel.ForeColor = $muted
    $StatusLabel.BackColor = $bg
    $StatusLabel.ForeColor = $text

    foreach ($group in @($SearchGroup,$StatusGroup)) {
        $group.BackColor = $card
        $group.ForeColor = $text
    }

    foreach ($valueLabel in @(
        $DisplayNameValue,$SamAccountValue,$UPNValue,$EnabledValue,
        $LockedValue,$PasswordExpiredValue,$LastBadPasswordValue
    )) {
        $valueLabel.ForeColor = $muted
    }

    foreach ($control in @($DCComboBox,$EventComboBox,$RangeComboBox)) {
        $control.BackColor = $field
        $control.ForeColor = $text
        $control.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    }

    $UserTextBox.BackColor = $field
    $UserTextBox.ForeColor = $text
    $UserTextBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    foreach ($button in @($RefreshDCButton,$ValidateButton,$ClearButton)) {
        $button.BackColor = $card
        $button.ForeColor = $accent
        $button.FlatStyle = 'Flat'
        $button.FlatAppearance.BorderColor = $accent
        $button.FlatAppearance.BorderSize = 1
    }

    $SearchButton.BackColor = $accent
    $SearchButton.ForeColor = [System.Drawing.Color]::White
    $SearchButton.FlatStyle = 'Flat'
    $SearchButton.FlatAppearance.BorderSize = 0

    $UnlockButton.BackColor = $success
    $UnlockButton.ForeColor = [System.Drawing.Color]::White
    $UnlockButton.FlatStyle = 'Flat'
    $UnlockButton.FlatAppearance.BorderSize = 0

    $DataGrid.BackgroundColor = $field
    $DataGrid.GridColor = $border
    $DataGrid.BorderStyle = 'None'
    $DataGrid.EnableHeadersVisualStyles = $false
    $DataGrid.ColumnHeadersDefaultCellStyle.BackColor = $card
    $DataGrid.ColumnHeadersDefaultCellStyle.ForeColor = $text
    $DataGrid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $card
    $DataGrid.ColumnHeadersDefaultCellStyle.SelectionForeColor = $text
    $DataGrid.DefaultCellStyle.BackColor = $field
    $DataGrid.DefaultCellStyle.ForeColor = $text
    $DataGrid.DefaultCellStyle.SelectionBackColor = $accent
    $DataGrid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $DataGrid.AlternatingRowsDefaultCellStyle.BackColor = $card
    $DataGrid.AlternatingRowsDefaultCellStyle.ForeColor = $text

    $ProgressBar.BackColor = $field
    $ProgressBar.ForeColor = $accent
}

# ---------------- Async runspace timer ----------------
$SearchTimer = New-Object System.Windows.Forms.Timer
$SearchTimer.Interval = 250

$SearchTimer.Add_Tick({
    if ($null -eq $script:SearchAsync -or $null -eq $script:SearchPowerShell) {
        $SearchTimer.Stop()
        return
    }

    if (-not $script:SearchAsync.IsCompleted) {
        return
    }

    $SearchTimer.Stop()

    try {
        $rows = @($script:SearchPowerShell.EndInvoke($script:SearchAsync))
        $errors = @($script:SearchPowerShell.Streams.Error | ForEach-Object { $_.ToString() })

        if ($errors.Count -gt 0) {
            throw ($errors -join ' | ')
        }

        if ($rows.Count -gt 0) {
           $DataGrid.DataSource = [System.Collections.ArrayList]@(
    $rows | Select-Object EventID,TimeCreated,UserName,ClientAddress,FailureCode,CallerComputer
)

            Set-StatusMessage "$($rows.Count) record(s) found. Maximum: 3 for 4771 and 1 for 4740." (Convert-HexColor $Theme.Success)
        }
        else {
            $DataGrid.DataSource = $null
            Set-StatusMessage 'No matching events found in the selected range.' (Convert-HexColor $Theme.Text)
        }
    }
    catch {
        $DataGrid.DataSource = $null
        Set-StatusMessage "Event search failed: $($_.Exception.Message)" (Convert-HexColor $Theme.Error)
    }
    finally {
        if ($null -ne $script:SearchPowerShell) {
            $script:SearchPowerShell.Dispose()
        }

        $script:SearchPowerShell = $null
        $script:SearchAsync = $null
        Set-BusyState $false

        if ($null -ne $script:ValidatedUser) {
            $UnlockButton.Enabled = [bool]$script:ValidatedUser.LockedOut
        }
    }
})

Apply-DarkTheme

# ---------------- Events ----------------
$ValidateButton.Add_Click({
    if (-not (Test-Inputs)) {
        return
    }

    [void](Update-UserStatus `
        -SamAccountName $UserTextBox.Text.Trim() `
        -DomainController ([string]$DCComboBox.SelectedItem))
})

$SearchButton.Add_Click({
    if (-not (Test-Inputs)) {
        return
    }

    $sam = $UserTextBox.Text.Trim()
    $dc = [string]$DCComboBox.SelectedItem
    $days = $RangeComboBox.SelectedIndex + 1
    $selection = [string]$EventComboBox.SelectedItem

    if (
        $null -eq $script:ValidatedUser -or
        $script:ValidatedUser.SamAccountName -ine $sam -or
        $script:ValidatedDC -ine $dc
    ) {
        if (-not (Update-UserStatus -SamAccountName $sam -DomainController $dc)) {
            return
        }
    }

    if ($null -ne $script:SearchPowerShell) {
        try {
            $script:SearchPowerShell.Stop()
        }
        catch {
        }

        $script:SearchPowerShell.Dispose()
    }

    $DataGrid.DataSource = $null
    Set-BusyState $true
    Set-StatusMessage "Searching $dc for the last $days day(s)..." (Convert-HexColor $Theme.Warn)

    $worker = {
        param(
            [string]$DomainController,
            [string]$SamAccountName,
            [int]$Days,
            [string]$Selection
        )

        function Read-Value {
            param(
                [xml]$Xml,
                [string]$Name
            )

            $item = $Xml.Event.EventData.Data |
                Where-Object { $_.Name -eq $Name } |
                Select-Object -First 1

            if ($null -eq $item) {
                return ''
            }

            return [string]$item.'#text'
        }

        function Read-Events {
            param(
                [int]$Id,
                [int]$Max
            )

            [int64]$milliseconds = [int64]$Days * 86400000
            $xpath = "*[System[(EventID=$Id) and TimeCreated[timediff(@SystemTime) <= $milliseconds]]] and *[EventData[Data[@Name='TargetUserName']='$SamAccountName']]"

            try {
                return @(
                    Get-WinEvent `
                        -ComputerName $DomainController `
                        -LogName Security `
                        -FilterXPath $xpath `
                        -MaxEvents $Max `
                        -ErrorAction Stop
                )
            }
            catch {
                if (
                    $_.Exception.Message -like '*No events were found*' -or
                    $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'
                ) {
                    return @()
                }

                throw
            }
        }

        function Get-CallerComputer4740 {
            param(
                [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
                [xml]$Xml
            )

            # In the event format used in this environment, Event Viewer displays
            # Caller Computer Name from TargetDomainName. Try that first.
            $callerComputer = Read-Value -Xml $Xml -Name 'TargetDomainName'

            # Some systems expose a dedicated CallerComputerName XML field.
            if ([string]::IsNullOrWhiteSpace($callerComputer)) {
                $callerComputer = Read-Value -Xml $Xml -Name 'CallerComputerName'
            }

            # Event 4740 property index 1 commonly contains the same value.
            if ([string]::IsNullOrWhiteSpace($callerComputer)) {
                try {
                    if ($Event.Properties.Count -gt 1 -and $null -ne $Event.Properties[1].Value) {
                        $callerComputer = [string]$Event.Properties[1].Value
                    }
                }
                catch {
                    $callerComputer = ''
                }
            }

            # Final fallback: extract exactly what Event Viewer renders.
            if ([string]::IsNullOrWhiteSpace($callerComputer)) {
                try {
                    $message = $Event.FormatDescription()

                    if ($message -match '(?im)^\s*Caller\s+Computer\s+Name\s*:\s*([^\r\n]+)') {
                        $callerComputer = $Matches[1].Trim()
                    }
                }
                catch {
                    $callerComputer = ''
                }
            }

            if ([string]::IsNullOrWhiteSpace($callerComputer)) {
                return 'Not Recorded'
            }

            return $callerComputer.Trim()
        }

        $out = @()

        # Event 4771: latest three matching records.
        if (
            $Selection -eq 'Both - 4771 and 4740' -or
            $Selection -eq '4771 - Kerberos Failure'
        ) {
            foreach ($event in (Read-Events -Id 4771 -Max 3)) {
                $xml = [xml]$event.ToXml()
                $ip = Read-Value -Xml $xml -Name 'IpAddress'

                if ($ip -like '::ffff:*') {
                    $ip = $ip.Substring(7)
                }

                $out += [PSCustomObject]@{
                    EventID          = 4771
                    SortTime         = $event.TimeCreated
                    TimeCreated      = $event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss')
                    UserName         = Read-Value -Xml $xml -Name 'TargetUserName'
                    ClientAddress    = $ip
                    ClientPort       = Read-Value -Xml $xml -Name 'IpPort'
                    FailureCode      = Read-Value -Xml $xml -Name 'Status'
                    CallerComputer   = ''
                    DomainController = $DomainController
                }
            }
        }

        # Event 4740: latest one matching record.
        if (
            $Selection -eq 'Both - 4771 and 4740' -or
            $Selection -eq '4740 - Account Lockout'
        ) {
            foreach ($event in (Read-Events -Id 4740 -Max 1)) {
                $xml = [xml]$event.ToXml()
                $callerComputer = Get-CallerComputer4740 -Event $event -Xml $xml

                $out += [PSCustomObject]@{
                    EventID          = 4740
                    SortTime         = $event.TimeCreated
                    TimeCreated      = $event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss')
                    UserName         = Read-Value -Xml $xml -Name 'TargetUserName'
                    ClientAddress    = ''
                    ClientPort       = ''
                    FailureCode      = ''
                    CallerComputer   = $callerComputer
                    DomainController = $DomainController
                }
            }
        }

$out |
    Sort-Object SortTime -Descending |
    Select-Object EventID,TimeCreated,UserName,ClientAddress,FailureCode,CallerComputer
    }

    try {
        $script:SearchPowerShell = [PowerShell]::Create()
        [void]$script:SearchPowerShell.AddScript($worker.ToString())
        [void]$script:SearchPowerShell.AddArgument($dc)
        [void]$script:SearchPowerShell.AddArgument($sam)
        [void]$script:SearchPowerShell.AddArgument($days)
        [void]$script:SearchPowerShell.AddArgument($selection)

        $script:SearchAsync = $script:SearchPowerShell.BeginInvoke()
        $SearchTimer.Start()
    }
    catch {
        if ($null -ne $script:SearchPowerShell) {
            $script:SearchPowerShell.Dispose()
        }

        $script:SearchPowerShell = $null
        $script:SearchAsync = $null
        Set-BusyState $false
        Set-StatusMessage "Unable to start event search: $($_.Exception.Message)" (Convert-HexColor $Theme.Error)
    }
})

$UnlockButton.Add_Click({
    if ($null -eq $script:ValidatedUser) {
        return
    }

    $sam = $script:ValidatedUser.SamAccountName
    $dc = [string]$DCComboBox.SelectedItem

    if (-not $script:ValidatedUser.LockedOut) {
        Set-StatusMessage "Account '$sam' is not locked." (Convert-HexColor $Theme.Text)
        return
    }

    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Unlock account '$sam' using '$dc'?",
        'Confirm Account Unlock',
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button2
    )

    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
        return
    }

    try {
        Unlock-ADAccount `
            -Identity $script:ValidatedUser.DistinguishedName `
            -Server $dc `
            -Confirm:$false `
            -ErrorAction Stop

        Start-Sleep -Milliseconds 500
        [void](Update-UserStatus -SamAccountName $sam -DomainController $dc)

        [void][System.Windows.Forms.MessageBox]::Show(
            "Account '$sam' was unlocked successfully.",
            'Account Unlocked',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        Set-StatusMessage "Unlock failed: $($_.Exception.Message)" (Convert-HexColor $Theme.Error)
    }
})

$RefreshDCButton.Add_Click({
    Set-BusyState $true
    Set-StatusMessage 'Loading domain controllers...' (Convert-HexColor $Theme.Warn)

    try {
        $DCComboBox.Items.Clear()

        foreach ($dc in @(Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object HostName)) {
            [void]$DCComboBox.Items.Add($dc.HostName)
        }

        if ($DCComboBox.Items.Count -gt 0) {
            $DCComboBox.SelectedIndex = 0
        }

        Set-StatusMessage "$($DCComboBox.Items.Count) domain controller(s) loaded." (Convert-HexColor $Theme.Success)
    }
    catch {
        Set-StatusMessage "Unable to load DCs: $($_.Exception.Message)" (Convert-HexColor $Theme.Error)
    }
    finally {
        Set-BusyState $false
    }
})

$ClearButton.Add_Click({
    $UserTextBox.Clear()
    $DataGrid.DataSource = $null
    Reset-UserInformation
    $EventComboBox.SelectedIndex = 0
    $RangeComboBox.SelectedIndex = 1
    Set-StatusMessage 'Ready.' (Convert-HexColor $Theme.Text)
    $UserTextBox.Focus()
})

$DCComboBox.Add_SelectedIndexChanged({
    Reset-UserInformation
    $DataGrid.DataSource = $null
})

$UserTextBox.Add_TextChanged({
    if (
        $null -ne $script:ValidatedUser -and
        $UserTextBox.Text.Trim() -ine $script:ValidatedUser.SamAccountName
    ) {
        Reset-UserInformation
        $DataGrid.DataSource = $null
    }
})

$EventComboBox.Add_SelectedIndexChanged({
    $DataGrid.DataSource = $null
})

$RangeComboBox.Add_SelectedIndexChanged({
    $DataGrid.DataSource = $null
})

$Form.Add_FormClosing({
    $SearchTimer.Stop()

    if ($null -ne $script:SearchPowerShell) {
        try {
            $script:SearchPowerShell.Stop()
        }
        catch {
        }

        $script:SearchPowerShell.Dispose()
    }
})

$Form.AcceptButton = $ValidateButton
$Form.Add_Shown({
    Load-LocalDomainController
    $UserTextBox.Focus()
})

[void]$Form.ShowDialog()
