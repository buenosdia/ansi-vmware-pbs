# ansi_vmware_pbs
Ansible VMware Playbooks

#Requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true,
               HelpMessage = "Enter the target host (e.g., localhost, google.com).")]
    [string]$HostName,

    [Parameter(Mandatory = $true,
               HelpMessage = "Enter the target port (e.g., 443, 1433).")]
    [int]$Port,

    [Parameter(HelpMessage = "Disables server certificate validation. Use this if you only want to test protocol support against a server with an invalid, expired, or self-signed certificate.")]
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = 'SilentlyContinue'

$tlsVersions = @(
    [System.Security.Authentication.SslProtocols]::Ssl2,
    [System.Security.Authentication.SslProtocols]::Ssl3,
    [System.Security.Authentication.SslProtocols]::Tls,
    [System.Security.Authentication.SslProtocols]::Tls11,
    [System.Security.Authentication.SslProtocols]::Tls12,
    [System.Security.Authentication.SslProtocols]::Tls13
)

if ($SkipCertificateCheck.IsPresent) {
    $validationCallback = { return $true }
    Write-Host "ℹ️ Server certificate validation is disabled." -ForegroundColor Yellow
} else {
    $validationCallback = {
        param($sender, $certificate, $chain, $sslPolicyErrors)

        if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
            return $true
        }

        Write-Warning "Server certificate validation failed."
        
        if ($sslPolicyErrors.HasFlag([System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch)) {
            Write-Warning "  - Error: The certificate name does not match the target host '$HostName'."
        }
        if ($sslPolicyErrors.HasFlag([System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable)) {
            Write-Warning "  - Error: The remote certificate was not provided."
        }
        if ($sslPolicyErrors.HasFlag([System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors)) {
            Write-Warning "  - Error: The certificate chain has one or more errors."
            foreach ($status in $chain.ChainStatus) {
                Write-Warning "    - Chain Status: $($status.Status) - $($status.StatusInformation.Trim())"
            }
        }
        
        return $false
    }
}

Write-Host ""

foreach ($version in $tlsVersions) {
    Write-Host "Attempting to connect with $($version.ToString())..." -ForegroundColor Cyan

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($HostName, $Port)
        
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            $validationCallback
        )

        $sslStream.AuthenticateAsClient($HostName, $null, $version, $false)

        if ($sslStream.IsAuthenticated) {
            Write-Host "  ✅ Successfully connected using $($sslStream.SslProtocol) with cipher suite $($sslStream.NegotiatedCipherSuite)." -ForegroundColor Green
            if (-not $SkipCertificateCheck.IsPresent) {
                 Write-Host "  ✅ Server certificate is valid." -ForegroundColor Green
            }
        }
        
        $sslStream.Close()
        $tcpClient.Close()

    }
    catch [System.Security.Authentication.AuthenticationException] {
        Write-Host "  ❌ Failed to authenticate. This could be due to an unsupported protocol or a certificate validation failure." -ForegroundColor Red
        Write-Host "     Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.Exception.InnerException) {
            Write-Host "     Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor DarkRed
        }
    }
    catch {
        Write-Host "  ❌ An unexpected error occurred." -ForegroundColor Red
        Write-Host "     Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.Exception.InnerException) {
            Write-Host "     Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor DarkRed
        }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Dispose() }
        Write-Host ""
    }
}
