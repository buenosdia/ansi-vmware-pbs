$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager 
$WsusSearcher = $UpdateSession.CreateUpdateSearcher()
try { 
    $IsHiddenInstalled = @($WsusSearcher.Search("IsHidden=0 and IsInstalled=0").Update)
}
catch {
    $IsHiddenInstalled = $null
    $JSON = = @{Result = 'No Pending Updates' } | ConvertTo-Json
}
if ($null -ne $IsHiddenInstalled) {

    $PendingMissingUpdates = @($IsHiddenInstalled | ForEach-Object {

            if ($null -ne $_) {

                [pscustomobject]@{
                    Date                     = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
                    Computername             = $env:ComputerName.ToUpper() 
                    Title                    = $_.Title
                    Description              = $_.Description
                    CveIDs                   = $($_.CveIDs -join ',')
                    KB                       = $($_.KBArticleIDs -join ',')
                    Severity                 = $_.MsrcSeverity
                    LastDeploymentChangeTime = ( $_.LastDeploymentChangeTime ).tostring()
                    UninstallationNotes      = $_.UninstallationNotes
                    Categories               = $($_.categories).Name -join ', '
                    Type                     = $(switch ($_.type) { 1 { 'Software' }2 { 'Driver' } })
                    SupportURL               = $_.SupportURL

                }
            }
        })
    #  $Downloader = $UpdateSession.CreateUpdateDownloader()
    #  $Downloader.Updates = $IsHiddenInstalled
    #  $Downloader.Download()

    #  $Installer = New-Object -ComObject Microsoft.Update.Installer
    #  $Installer.Updates = $IsHiddenInstalled

    #  $pending_updates = $Installer.Install()
    $JSON = @{Result = @($PendingMissingUpdates | ConvertTo-Json) }
}

Write-Output $JSON