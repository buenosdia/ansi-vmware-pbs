$null = Start-Transcript -Path C:\Temp\Cleanup.log -Force
$null = gpupdate /target:computer /force /wait:0
#$reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
#Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 0
#Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -ErrorAction SilentlyContinue
#Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -ErrorAction SilentlyContinue
$null = Set-Service -Name "WinRM" -StartupType Automatic -Confirm:$false
$null = Start-Service -Name "WinRM" -Confirm:$false

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

$null = Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value * -Force    
$null = Stop-Transcript
