$username = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_USERNAME", "User")
$password = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_PASSWORD", "User")
$hostname = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_HOSTNAME", "User")
$domain = [System.Environment]::GetEnvironmentVariable("KEYFACTOR_DOMAIN", "User")

if (-not $username -or -not $password -or -not $hostname -or -not $domain) {
   Write-Host "Please set the environment variables KEYFACTOR_USERNAME, KEYFACTOR_PASSWORD, KEYFACTOR_HOSTNAME and KEYFACTOR_DOMAIN"
   exit
}

$uri = "https://$hostname/keyfactorapi/certificatestoretypes"
$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${username}@${domain}:${password}"))
$headers = @{
   'Authorization' = "Basic $auth"
   'Content-Type' = "application/json"
   'x-keyfactor-requested-with' = "APIClient"
}



Write-Host "Creating K8SCert store type"
$body = @"
{
    "Name": "K8SCert",
    "ShortName": "K8SCert",
    "Capability": "K8SCert",
    "LocalStore": false,
    "SupportedOperations": {
      "Add": false,
      "Create": false,
      "Discovery": true,
      "Enrollment": false,
      "Remove": false
    },
    "Properties": [
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeNamespace",
        "DisplayName": "KubeNamespace",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": "default",
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSecretName",
        "DisplayName": "KubeSecretName",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": null,
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSecretType",
        "DisplayName": "KubeSecretType",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": "cert",
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSvcCreds",
        "DisplayName": "KubeSvcCreds",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": null,
        "Required": true
      }
    ],
    "EntryParameters": [],
    "PasswordOptions": {
      "EntrySupported": false,
      "StoreRequired": false,
      "Style": "Default"
    },
    "StorePathType": "",
    "StorePathValue": "",
    "PrivateKeyAllowed": "Forbidden",
    "JobProperties": [],
    "ServerRequired": false,
    "PowerShell": false,
    "BlueprintAllowed": false,
    "CustomAliasAllowed": "Forbidden"
  }
"@
Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType "application/json"

Write-Host "Creating K8SSecret store type"
$body = @"
{
    "Name": "K8SSecret",
    "ShortName": "K8SSecret",
    "Capability": "K8SSecret",
    "LocalStore": false,
    "SupportedOperations": {
      "Add": true,
      "Create": true,
      "Discovery": true,
      "Enrollment": false,
      "Remove": true
    },
    "Properties": [
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeNamespace",
        "DisplayName": "KubeNamespace",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": "default",
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSecretName",
        "DisplayName": "KubeSecretName",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": null,
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSecretType",
        "DisplayName": "KubeSecretType",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": "secret",
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSvcCreds",
        "DisplayName": "KubeSvcCreds",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": null,
        "Required": true
      }
    ],
    "EntryParameters": [],
    "PasswordOptions": {
      "EntrySupported": false,
      "StoreRequired": false,
      "Style": "Default"
    },
    "StorePathType": "",
    "StorePathValue": "",
    "PrivateKeyAllowed": "Optional",
    "JobProperties": [],
    "ServerRequired": false,
    "PowerShell": false,
    "BlueprintAllowed": false,
    "CustomAliasAllowed": "Forbidden"
  }
"@

Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType "application/json"

Write-Host "Creating K8STLSSecr store type"
$body = @"
{
    "Name": "K8STLSSecr",
    "ShortName": "K8STLSSecr",
    "Capability": "K8STLSSecr",
    "LocalStore": false,
    "SupportedOperations": {
      "Add": true,
      "Create": true,
      "Discovery": true,
      "Enrollment": false,
      "Remove": true
    },
    "Properties": [
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeNamespace",
        "DisplayName": "KubeNamespace",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": "default",
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSecretName",
        "DisplayName": "KubeSecretName",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": null,
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSecretType",
        "DisplayName": "KubeSecretType",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": "tls_secret",
        "Required": true
      },
      {
        "StoreTypeId;omitempty": 0,
        "Name": "KubeSvcCreds",
        "DisplayName": "KubeSvcCreds",
        "Type": "String",
        "DependsOn": "",
        "DefaultValue": null,
        "Required": true
      }
    ],
    "EntryParameters": [],
    "PasswordOptions": {
      "EntrySupported": false,
      "StoreRequired": false,
      "Style": "Default"
    },
    "StorePathType": "",
    "StorePathValue": "",
    "PrivateKeyAllowed": "Optional",
    "JobProperties": [],
    "ServerRequired": false,
    "PowerShell": false,
    "BlueprintAllowed": false,
    "CustomAliasAllowed": "Forbidden"
  }
"@