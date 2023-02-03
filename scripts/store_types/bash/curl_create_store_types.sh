###CURL script to create DER certificate store type

###Replacement Variables - Manually replace these before running###
# {URL} - Base URL for your Keyfactor deployment
# {UserName} - User name with access to run Keyfactor APIs
# {UserPassword} - Password for the UserName above

export KEYFACTOR_USERNAME="<your username>"
export KEYFACTOR_PASSWORD="<your password>"
export KEYFACTOR_HOSTNAME="<your Keyfactor command hostname>"
export KEYFACTOR_DOMAIN="<your AD domain name>"

# Check environment variables are set
if [ -z "$KEYFACTOR_USERNAME" ] || [ -z "$KEYFACTOR_PASSWORD" ] || [ -z "$KEYFACTOR_HOSTNAME" ] || [ -z "$KEYFACTOR_DOMAIN" ]; then
    echo "Please set the environment variables KEYFACTOR_USERNAME, KEYFACTOR_PASSWORD, KEYFACTOR_HOSTNAME and KEYFACTOR_DOMAIN"
    exit 1
fi

echo "Creating K8SCert store type"
curl -X POST "https://${KEYFACTOR_HOSTNAME}/keyfactorapi/certificatestoretypes" \
  -H "Content-Type: application/json" \
  -H "x-keyfactor-requested-with: APIClient" \
  -u "${KEYFACTOR_USERNAME}:${KEYFACTOR_PASSWORD}" -d \
'{
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
}'

echo "Creating K8SSecret store type"
curl -X POST "https://$KEYFACTOR_HOSTNAME/keyfactorapi/certificatestoretypes" \
  -H "Content-Type: application/json" \
  -H "x-keyfactor-requested-with: APIClient" \
  -u {UserName}:{UserPassword} -d \
'{
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
}'

echo "Creating K8STLSSecr store type"
curl -X POST "https://$KEYFACTOR_HOSTNAME/keyfactorapi/certificatestoretypes" \
  -H "Content-Type: application/json" \
  -H "x-keyfactor-requested-with: APIClient" \
  -u {UserName}:{UserPassword} -d \
'{
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
}'

echo "Completed"