# Creates all 7 Kubernetes Orchestrator store types using kfutil.
# kfutil reads store type definitions from the Keyfactor integration catalog.
#
# Prerequisites:
#   - kfutil installed: https://github.com/Keyfactor/kfutil#quickstart
#   - Auth environment variables (see README.md for options)
#
# Auto-generated from integration-manifest.json — do not edit by hand.
# Regenerate with: make store-types-gen-scripts

# Uncomment if kfutil is not in your PATH
# Set-Alias -Name kfutil -Value 'C:\Program Files\Keyfactor\kfutil\kfutil.exe'

if ($null -eq (Get-Command "kfutil" -ErrorAction SilentlyContinue)) {
    Write-Host "kfutil could not be found in your PATH. Please install kfutil"
    Write-Host "See the official docs: https://github.com/Keyfactor/kfutil#quickstart"
    exit 1
}

if (-not $env:KEYFACTOR_HOSTNAME) {
    Write-Host "KEYFACTOR_HOSTNAME not set — launching kfutil login"
    & kfutil login
}

& kfutil store-types create --name "K8SCert"
& kfutil store-types create --name "K8SCluster"
& kfutil store-types create --name "K8SJKS"
& kfutil store-types create --name "K8SNS"
& kfutil store-types create --name "K8SPKCS12"
& kfutil store-types create --name "K8SSecret"
& kfutil store-types create --name "K8STLSSecr"

Write-Host "Done. All store types created."
