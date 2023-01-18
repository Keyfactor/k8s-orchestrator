$username = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_USERNAME", "User")
$password = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_PASSWORD", "User")
$hostname = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_HOSTNAME", "User")
$domain = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_DOMAIN", "User")

Set-Alias -Name kfutil -Value 'C:\Program Files\Keyfactor\kfutil\kfutil.exe' # Comment this out if you have kfutil in your PATH or somewhere custom

if ((Get-Command "kfutil" -ErrorAction SilentlyContinue) -eq $null)
{
    Write-Host "kfutil could not be found in your PATH. Please install kfutil"
    Write-Host "See the official docs: https://github.com/Keyfactor/kfutil#quickstart"
}

if (-not $username -or -not $password -or -not $hostname -or -not $domain) {
   Write-Host "Please set the environment variables KEYFACTOR_USERNAME, KEYFACTOR_PASSWORD, KEYFACTOR_HOSTNAME and KEYFACTOR_DOMAIN"
   & kfutil login
}

& kfutil store-types create --name "K8SCert"
& kfutil store-types create --name "K8SSecret"
& kfutil store-types create --name "K8STLSSecr"


