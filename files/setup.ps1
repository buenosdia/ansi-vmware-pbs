$null = New-Item C:\Temp -ItemType Directory -Force -EA 0
$null = Start-Transcript -Path C:\Temp\Cleanup.log -Force
$null = gpupdate /target:computer /force /wait:0
#$reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
#Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 0
#Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -ErrorAction SilentlyContinue
#Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -ErrorAction SilentlyContinue
$null = Set-Service -Name "WinRM" -StartupType Automatic -Confirm:$false
$null = Start-Service -Name "WinRM" -Confirm:$false
Get-Certificate -Template "GSI WinRM" -Url ldap: -CertStoreLocation Cert:\LocalMachine\My
Get-Certificate -Template "GSI RDP" -Url ldap: -CertStoreLocation Cert:\LocalMachine\My

$ruleDisplayName = 'Windows Remote Management (HTTPS-In)'

if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore)) {
    $new5985RuleParams = @{
        DisplayName   = $ruleDisplayName
        Direction     = 'Inbound'
        LocalPort     = 5986
        RemoteAddress = 'Any'
        Protocol      = 'TCP'
        Action        = 'Allow'
        Enabled       = 'True'
        Group         = 'Windows Remote Management'
    }

    $new5986RuleParams = @{
        DisplayName   = $ruleDisplayName
        Direction     = 'Inbound'
        LocalPort     = 5985
        RemoteAddress = 'Any'
        Protocol      = 'TCP'
        Action        = 'Allow'
        Enabled       = 'True'
        Group         = 'Windows Remote Management'
    }
    $null = New-NetFirewallRule @new5985RuleParams
    $null = New-NetFirewallRule @new5986RuleParams
	 
}

netsh advfirewall set allprofiles state off
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {

    Enable-PSRemoting -SkipNetworkProfileCheck -Force
	
}

if ((Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate).Transport -notcontains 'HTTPS') {

    try {
   
        $null = winrm quickconfig -transport:https -quiet
        $Result = "CertFound: $CertFound`nWinRM HTTPS configured"

    }
    catch {

        $Ansible.Failed = $true
        $Result = "ERROR - CertFound: $CertFound`nWinRM HTTPS configured`n$($Error[0].Exception.Message)"
        $return = 1

    }
}

net user Administrator /ACTIVE:YES /LOGONPASSWORDCHG:NO /EXPIRES:NEVER /PASSWORDREQ:YES
WMIC USERACCOUNT WHERE "Name='Administrator'" SET PasswordExpires=FALSE
$null = Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value * -Force    

REG LOAD HKU\DefaultUser C:\Users\Default\NTUSER.DAT
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f 
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f 
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AlwaysShowClassicMenu" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "RestrictWelcomeCenter" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutoRun" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d "00000000" /t REG_DWORD /f
REG UNLOAD HKU\DefaultUser
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -PropertyType DWORD -Value '0' -Force
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HibernteEnabled  /d 0 /t REG_DWORD /f
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' -Force
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' -Force
REG LOAD HKLM\DefaultUser C:\Users\Default\NTUSER.DAT
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AlwaysShowClassicMenu" /d "00000001" /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "RestrictWelcomeCenter" /d "00000001" /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutoRun" /d "00000001" /t REG_DWORD /f
REG ADD "HKLM\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AlwaysShowClassicMenu" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "RestrictWelcomeCenter" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutoRun" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /d "00000001" /t REG_DWORD /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1000&DEV_0054&SUBSYS_197615AD&REV_01\4&1f16fef7&0&00A8" /v Capabilities /t REG_DWORD /d 2 /f
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_100F&SUBSYS_075015AD&REV_01\4&3ad87e0a&0&0088" /v Capabilities /t REG_DWORD /d 2 /f
REG UNLOAD HKLM\DefaultUser
reg add "HKLM\Software\Policies\Microsoft\Windows\Server\ServerManager" /v "DoNotOpenAtLogon" /t REG_DWORD /d 1 /f
REG Delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v SusClientId  /f
REG Delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate /v SusClientIdValidation  /f
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' -Force
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' -Force
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ServerManager' -Name DoNotOpenServerManagerAtLogon -Value 1
Set-ItemProperty 'HKCU:\Software\Microsoft\ServerManager' -Name CheckedUnattendLaunchSetting -Value 0
REG LOAD HKU\DefaultUser c:\Users\Default\NTUSER.DAT
REG ADD 'HKU\DefaultUser\Software\Microsoft\ServerManager' /v "CheckedUnattendLaunchSetting" /d 0 /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Internet Explorer\New Windows" /v "PopupMgr" /d 0 /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\New Windows" /v "PopupMgr" /d 0 /t REG_DWORD /f
REG ADD "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /d 1 /t REG_DWORD /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /d 1 /t REG_DWORD /f
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f 
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f 
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v MinimizedStateTabletModeOff /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v MinimizedStateTabletModeOff /t REG_DWORD /d 0 /f
reg add "HKU\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
REG ADD 'HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' /V 'NewStartPanel'  /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"/d "0" /t REG_DWORD /f
REG ADD 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' /V 'NewStartPanel' /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"/d "0" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d "00000000" /t REG_DWORD /f
REG ADD "HKCU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /d "00000000" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d "00000000" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" /d "00000000" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /d "00000000" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AlwaysShowClassicMenu" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "RestrictWelcomeCenter" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutoRun" /d "00000001" /t REG_DWORD /f
REG ADD "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AlwaysShowClassicMenu" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "RestrictWelcomeCenter" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutoRun" /d "00000001" /t REG_DWORD /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /d "00000001" /t REG_DWORD /f
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
REG UNLOAD HKU\DefaultUser
$null = Stop-Transcript
