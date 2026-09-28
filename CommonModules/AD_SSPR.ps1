
# AdSelfService-GUI-3x4-MainAndDialogs.ps1
# Fixed-size WPF GUI: 3 inches (288 DIP) x 4 inches (384 DIP)
# Main window has Username + 2 buttons + Comment box.
# Clicking buttons opens compact child dialogs (GUI-only; no business logic yet).

#region Bootstrap: Windows + STA
if (-not $IsWindows) {
    $plat = [Environment]::OSVersion.Platform
    $isWin = ($plat -eq 'Win32NT' -or $plat -eq 2 -or $plat -eq 1)
    if (-not $isWin) { Write-Error "Windows-only GUI (WPF)."; return }
}
try { $apt = [System.Threading.Thread]::CurrentThread.ApartmentState } catch { $apt = 'Unknown' }
function Restart-AsSTA {
    $psExe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh' } else { 'powershell' }
    Start-Process -FilePath $psExe -ArgumentList @('-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") | Out-Null
    exit
}
if ($host.Name -notlike '*ISE*' -and $apt -ne 'STA') { Restart-AsSTA }
#endregion

# Load WPF
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase, System.Xaml | Out-Null

# ---------------------------
# Common helpers / resources
# ---------------------------
$Theme = @{
  Bg        = '#1E2227'
  Card      = '#24292F'
  Field     = '#2C323A'
  Text      = '#F0F0F0'
  Muted     = '#B8C0CC'
  Accent    = '#0E7AC7'
  AccentHi  = '#2EA7FF'
  Success   = '#4BB06E'
  Border    = '#3A424B'
}

# Toggle reveal helper (swap PasswordBox <-> TextBox, preserving text)
function Toggle-Reveal {
    param([Parameter(Mandatory)]$pwd, [Parameter(Mandatory)]$tb)
    if ($tb.Visibility -eq 'Collapsed') {
        $tb.Text = $pwd.Password
        $tb.Visibility  = 'Visible'
        $pwd.Visibility = 'Collapsed'
        $tb.Focus(); $tb.CaretIndex = $tb.Text.Length
    } else {
        $pwd.Password = $tb.Text
        $pwd.Visibility = 'Visible'
        $tb.Visibility  = 'Collapsed'
        $pwd.Focus()
    }
}

# ---------------------------------------
# Child dialog: Generate Password (GUI)
# ---------------------------------------
function Show-GenerateDialog {
    param(
        [Parameter(Mandatory)]$OwnerWindow,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)]$CommentBox   # TextBlock from main window
    )

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Generate Password"
        Width="270" Height="320" MinWidth="270" MinHeight="320"
        WindowStartupLocation="CenterOwner"
        Background="$($Theme.Bg)" ResizeMode="NoResize"
        SnapsToDevicePixels="True" UseLayoutRounding="True"
        ShowInTaskbar="False">
  <Window.Resources>
    <SolidColorBrush x:Key="Card" Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text"  Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <Style TargetType="TextBlock" x:Key="Lbl">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,6,0,2"/>
    </Style>
    <Style TargetType="TextBox" x:Key="Txt">
      <Setter Property="Background" Value="{StaticResource Field}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="#3A424B"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,2"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Height" Value="24"/>
    </Style>
    <Style TargetType="PasswordBox" x:Key="Pwd">
      <Setter Property="Background" Value="{StaticResource Field}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="#3A424B"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,2"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Height" Value="24"/>
    </Style>
    <Style TargetType="Button" x:Key="Primary">
      <Setter Property="Background" Value="$($Theme.Accent)"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="26"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="Button" x:Key="Secondary">
      <Setter Property="Background" Value="{StaticResource Card}"/>
      <Setter Property="Foreground" Value="{StaticResource Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Accent}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="26"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid Margin="8">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="6" Padding="6" Margin="0,0,0,6">
      <StackPanel>
        <TextBlock Text="Generate Password" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13"/>
        <TextBlock Text="$Username" Foreground="{StaticResource Muted}" FontSize="11"/>
      </StackPanel>
    </Border>

    <!-- Content -->
    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="6" Padding="8">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Current -->
        <TextBlock Grid.Row="0" Text="Current password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="1">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <TextBox     x:Name="txtOldPlain" Visibility="Collapsed" Style="{StaticResource Txt}"/>
            <PasswordBox x:Name="pwdOld"      Visibility="Visible"   Style="{StaticResource Pwd}"/>
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealOld" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1" ToolTip="Show/Hide"/>
        </Grid>

        <!-- New -->
        <TextBlock Grid.Row="2" Text="New password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <TextBox     x:Name="txtNewPlain" Visibility="Collapsed" Style="{StaticResource Txt}"/>
            <PasswordBox x:Name="pwdNew"      Visibility="Visible"   Style="{StaticResource Pwd}"/>
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealNew" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1" ToolTip="Show/Hide"/>
        </Grid>

        <!-- Confirm -->
        <TextBlock Grid.Row="4" Text="Confirm password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="5">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <TextBox     x:Name="txtConfirmPlain" Visibility="Collapsed" Style="{StaticResource Txt}"/>
            <PasswordBox x:Name="pwdConfirm"      Visibility="Visible"   Style="{StaticResource Pwd}"/>
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealConfirm" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1" ToolTip="Show/Hide"/>
        </Grid>
      </Grid>
    </Border>

    <!-- Buttons -->
    <Grid Grid.Row="2" Margin="0,6,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Button x:Name="btnCancel"   Grid.Column="0" Style="{StaticResource Secondary}" Content="Cancel"/>
      <Button x:Name="btnGenerate" Grid.Column="1" Style="{StaticResource Primary}"   Content="Generate" Margin="6,0,0,0"/>
    </Grid>
  </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $win = [Windows.Markup.XamlReader]::Load($reader)
    function F([string]$n){ $win.FindName($n) }

    $pwdOld = F 'pwdOld'; $txtOldPlain = F 'txtOldPlain'; $btnRevealOld = F 'btnRevealOld'
    $pwdNew = F 'pwdNew'; $txtNewPlain = F 'txtNewPlain'; $btnRevealNew = F 'btnRevealNew'
    $pwdConfirm = F 'pwdConfirm'; $txtConfirmPlain = F 'txtConfirmPlain'; $btnRevealConfirm = F 'btnRevealConfirm'
    $btnGenerate = F 'btnGenerate'; $btnCancel = F 'btnCancel'

    $win.Owner = $OwnerWindow

    # Reveal toggles
    $btnRevealOld.Add_Click({ Toggle-Reveal -pwd $pwdOld -tb $txtOldPlain })
    $btnRevealNew.Add_Click({ Toggle-Reveal -pwd $pwdNew -tb $txtNewPlain })
    $btnRevealConfirm.Add_Click({ Toggle-Reveal -pwd $pwdConfirm -tb $txtConfirmPlain })

    # Actions (GUI-only; post to main CommentBox)
    $btnGenerate.Add_Click({
        $CommentBox.Text = "Generate Password: UI received inputs for $Username (not processed yet)."
        $win.Close()
    })
    $btnCancel.Add_Click({ $win.Close() })

    [void]$win.ShowDialog()
}

# -------------------------------------
# Child dialog: Change Password (GUI)
# -------------------------------------
function Show-ChangeDialog {
    param(
        [Parameter(Mandatory)]$OwnerWindow,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)]$CommentBox
    )

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Change Password"
        Width="270" Height="320" MinWidth="270" MinHeight="320"
        WindowStartupLocation="CenterOwner"
        Background="$($Theme.Bg)" ResizeMode="NoResize"
        SnapsToDevicePixels="True" UseLayoutRounding="True"
        ShowInTaskbar="False">
  <Window.Resources>
    <SolidColorBrush x:Key="Card" Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text"  Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <Style TargetType="TextBlock" x:Key="Lbl">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,6,0,2"/>
    </Style>
    <Style TargetType="TextBox" x:Key="Txt">
      <Setter Property="Background" Value="{StaticResource Field}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="#3A424B"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,2"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Height" Value="24"/>
    </Style>
    <Style TargetType="PasswordBox" x:Key="Pwd">
      <Setter Property="Background" Value="{StaticResource Field}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="#3A424B"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,2"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Height" Value="24"/>
    </Style>
    <Style TargetType="Button" x:Key="Primary">
      <Setter Property="Background" Value="$($Theme.Accent)"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="26"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="Button" x:Key="Secondary">
      <Setter Property="Background" Value="{StaticResource Card}"/>
      <Setter Property="Foreground" Value="{StaticResource Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Accent}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="26"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid Margin="8">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="6" Padding="6" Margin="0,0,0,6">
      <StackPanel>
        <TextBlock Text="Change Password" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13"/>
        <TextBlock Text="$Username" Foreground="{StaticResource Muted}" FontSize="11"/>
      </StackPanel>
    </Border>

    <!-- Content -->
    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="6" Padding="8">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Current -->
        <TextBlock Grid.Row="0" Text="Current password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="1">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <TextBox     x:Name="txtOldPlain" Visibility="Collapsed" Style="{StaticResource Txt}"/>
            <PasswordBox x:Name="pwdOld"      Visibility="Visible"   Style="{StaticResource Pwd}"/>
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealOld" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1" ToolTip="Show/Hide"/>
        </Grid>

        <!-- New -->
        <TextBlock Grid.Row="2" Text="New password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="3">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <TextBox     x:Name="txtNewPlain" Visibility="Collapsed" Style="{StaticResource Txt}"/>
            <PasswordBox x:Name="pwdNew"      Visibility="Visible"   Style="{StaticResource Pwd}"/>
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealNew" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1" ToolTip="Show/Hide"/>
        </Grid>

        <!-- Confirm -->
        <TextBlock Grid.Row="4" Text="Confirm password:" Style="{StaticResource Lbl}"/>
        <Grid Grid.Row="5">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <Grid Grid.Column="0">
            <TextBox     x:Name="txtConfirmPlain" Visibility="Collapsed" Style="{StaticResource Txt}"/>
            <PasswordBox x:Name="pwdConfirm"      Visibility="Visible"   Style="{StaticResource Pwd}"/>
          </Grid>
          <Button Grid.Column="1" x:Name="btnRevealConfirm" Content="👁" Width="26" Height="24" Background="{StaticResource Field}" BorderBrush="#3A424B" BorderThickness="1" ToolTip="Show/Hide"/>
        </Grid>
      </Grid>
    </Border>

    <!-- Buttons -->
    <Grid Grid.Row="2" Margin="0,6,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <Button x:Name="btnCancel" Grid.Column="0" Style="{StaticResource Secondary}" Content="Cancel"/>
      <Button x:Name="btnSubmit" Grid.Column="1" Style="{StaticResource Primary}"   Content="Submit" Margin="6,0,0,0"/>
    </Grid>
  </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $win = [Windows.Markup.XamlReader]::Load($reader)
    function F([string]$n){ $win.FindName($n) }

    $pwdOld = F 'pwdOld'; $txtOldPlain = F 'txtOldPlain'; $btnRevealOld = F 'btnRevealOld'
    $pwdNew = F 'pwdNew'; $txtNewPlain = F 'txtNewPlain'; $btnRevealNew = F 'btnRevealNew'
    $pwdConfirm = F 'pwdConfirm'; $txtConfirmPlain = F 'txtConfirmPlain'; $btnRevealConfirm = F 'btnRevealConfirm'
    $btnSubmit = F 'btnSubmit'; $btnCancel = F 'btnCancel'

    $win.Owner = $OwnerWindow

    # Reveal toggles
    $btnRevealOld.Add_Click({ Toggle-Reveal -pwd $pwdOld -tb $txtOldPlain })
    $btnRevealNew.Add_Click({ Toggle-Reveal -pwd $pwdNew -tb $txtNewPlain })
    $btnRevealConfirm.Add_Click({ Toggle-Reveal -pwd $pwdConfirm -tb $txtConfirmPlain })

    # Actions (GUI-only; post to main CommentBox)
    $btnSubmit.Add_Click({
        $CommentBox.Text = "Change Password: UI received inputs for $Username (not processed yet)."
        $win.Close()
    })
    $btnCancel.Add_Click({ $win.Close() })

    [void]$win.ShowDialog()
}

# ------------------------
# Main 3x4 window (fixed)
# ------------------------
[xml]$mainXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Self Password Change"
        Width="288" Height="384" MinWidth="288" MinHeight="384"
        WindowStartupLocation="CenterScreen"
        Background="$($Theme.Bg)"
        ResizeMode="NoResize"
        SnapsToDevicePixels="True" UseLayoutRounding="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Card"  Color="$($Theme.Card)"/>
    <SolidColorBrush x:Key="Field" Color="$($Theme.Field)"/>
    <SolidColorBrush x:Key="Text"  Color="$($Theme.Text)"/>
    <SolidColorBrush x:Key="Muted" Color="$($Theme.Muted)"/>
    <SolidColorBrush x:Key="Accent" Color="$($Theme.Accent)"/>
    <Style TargetType="TextBlock" x:Key="Lbl">
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Margin" Value="0,6,0,2"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
    </Style>
    <Style TargetType="TextBox" x:Key="Txt">
      <Setter Property="Background" Value="{StaticResource Field}"/>
      <Setter Property="Foreground" Value="{StaticResource Text}"/>
      <Setter Property="BorderBrush" Value="#3A424B"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,2"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Height" Value="24"/>
      <Setter Property="HorizontalAlignment" Value="Stretch"/>
    </Style>
    <Style TargetType="Button" x:Key="Primary">
      <Setter Property="Background" Value="{StaticResource Accent}"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="26"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="Button" x:Key="Secondary">
      <Setter Property="Background" Value="{StaticResource Card}"/>
      <Setter Property="Foreground" Value="{StaticResource Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Accent}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Height" Value="26"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <Grid Margin="6">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="{StaticResource Card}" CornerRadius="6" Padding="8" Margin="0,0,0,6">
      <TextBlock Text="Self Password Change" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13"/>
    </Border>

    <!-- Content -->
    <Border Grid.Row="1" Background="{StaticResource Card}" CornerRadius="6" Padding="8">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>   <!-- Comment area stretches -->
        </Grid.RowDefinitions>

        <!-- Username -->
        <TextBlock Grid.Row="0" Text="User Name (DOMAIN\user or user@domain):" Style="{StaticResource Lbl}"/>
        <TextBox   Grid.Row="1" x:Name="txtUser" Style="{StaticResource Txt}"/>

        <!-- Two buttons -->
        <Grid Grid.Row="2" Margin="0,10,0,0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Button x:Name="btnGenerate" Grid.Column="0" Style="{StaticResource Secondary}" Content="Generate Password"/>
          <Button x:Name="btnChange"   Grid.Column="1" Style="{StaticResource Primary}"   Content="Change Password" Margin="6,0,0,0"/>
        </Grid>

        <!-- Comment box (fills remaining space; no fixed height) -->
        <Grid Grid.Row="3" Margin="0,10,0,0">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <TextBlock Grid.Row="0" Text="Comment:" Style="{StaticResource Lbl}" Margin="0,0,0,2"/>
          <Border Grid.Row="1" Background="{StaticResource Field}" CornerRadius="4" Padding="4">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <TextBlock x:Name="txtComment" Text="Ready." Foreground="{StaticResource Text}" TextWrapping="Wrap"/>
            </ScrollViewer>
          </Border>
        </Grid>
      </Grid>
    </Border>

    <!-- Footer -->
    <Border Grid.Row="2" Background="{StaticResource Card}" CornerRadius="6" Padding="6" Margin="0,6,0,0">
      <TextBlock Text="Tips: Enter = Change • Esc = Close" Foreground="{StaticResource Muted}" FontSize="11"/>
    </Border>
  </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $mainXaml
$main = [Windows.Markup.XamlReader]::Load($reader)
function M([string]$n){ $main.FindName($n) }

$txtUser    = M 'txtUser'
$btnGenerate= M 'btnGenerate'
$btnChange  = M 'btnChange'
$txtComment = M 'txtComment'

# Defaults
$txtUser.Text = if ($env:USERDOMAIN -and $env:USERNAME) { "$($env:USERDOMAIN)\$($env:USERNAME)" } else { "" }

# Keyboard shortcuts
$main.Add_KeyDown({
    param($s,$e)
    if ($e.Key -eq 'Escape') { $main.Close() }
    if ($e.Key -eq 'Return') { $btnChange.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) }
})

# Button actions: open child dialogs (GUI-only)
$btnGenerate.Add_Click({
    $u = $txtUser.Text.Trim()
    if (-not $u) { $txtComment.Text = "Please enter a username first."; return }
    Show-GenerateDialog -OwnerWindow $main -Username $u -CommentBox $txtComment
})

$btnChange.Add_Click({
    $u = $txtUser.Text.Trim()
    if (-not $u) { $txtComment.Text = "Please enter a username first."; return }
    Show-ChangeDialog -OwnerWindow $main -Username $u -CommentBox $txtComment
})

# Show main window
[void]$main.ShowDialog()
