# Store Type Scripts

Scripts to create all 7 Kubernetes Orchestrator certificate store types in a Keyfactor Command instance.

> **Note:** These scripts are auto-generated from `integration-manifest.json`.
> Regenerate with `make store-types-gen-scripts` after updating the manifest.

## Store Types

| Store Type  | Kubernetes Resource          | Operations                       |
|-------------|------------------------------|----------------------------------|
| K8SCert     | CertificateSigningRequest    | Inventory, Discovery             |
| K8SCluster  | Opaque + TLS secrets (all NS)| Inventory, Management            |
| K8SJKS      | Opaque secret (JKS file)     | Inventory, Management, Discovery |
| K8SNS       | Opaque + TLS secrets (1 NS)  | Inventory, Management, Discovery |
| K8SPKCS12   | Opaque secret (PKCS12 file)  | Inventory, Management, Discovery |
| K8SSecret   | Opaque secret (PEM)          | Inventory, Management, Discovery |
| K8STLSSecr  | kubernetes.io/tls secret     | Inventory, Management, Discovery |

## Authentication

All scripts support three authentication methods (first matching wins):

| Method | Environment Variables |
|--------|-----------------------|
| OAuth access token | `KEYFACTOR_AUTH_ACCESS_TOKEN` |
| OAuth client credentials | `KEYFACTOR_AUTH_CLIENT_ID` + `KEYFACTOR_AUTH_CLIENT_SECRET` + `KEYFACTOR_AUTH_TOKEN_URL` |
| Basic auth (AD) | `KEYFACTOR_USERNAME` + `KEYFACTOR_PASSWORD` + `KEYFACTOR_DOMAIN` |

Always required regardless of auth method: `KEYFACTOR_HOSTNAME`

## Methods

### kfutil (recommended)

`kfutil` reads store type definitions from the Keyfactor integration catalog and handles auth automatically via its own env vars.

**Bash:**
```bash
bash/kfutil_create_store_types.sh
```

**PowerShell:**
```powershell
.\powershell\kfutil_create_store_types.ps1
```

**Prerequisites:** [kfutil](https://github.com/Keyfactor/kfutil#quickstart) installed and authenticated.

Create all store types from the local `integration-manifest.json` in one command:
```bash
kfutil store-types create --from-file integration-manifest.json
# or via Make:
make store-types-create
```

### curl (Bash)

```bash
export KEYFACTOR_HOSTNAME="my-command.example.com"
# OAuth (token):
export KEYFACTOR_AUTH_ACCESS_TOKEN="eyJ..."
# or OAuth (client credentials):
export KEYFACTOR_AUTH_CLIENT_ID="my-client"
export KEYFACTOR_AUTH_CLIENT_SECRET="secret"
export KEYFACTOR_AUTH_TOKEN_URL="https://auth.example.com/realms/keyfactor/protocol/openid-connect/token"
# or Basic auth:
export KEYFACTOR_USERNAME="svc-account"
export KEYFACTOR_PASSWORD="hunter2"
export KEYFACTOR_DOMAIN="corp"

bash/curl_create_store_types.sh
```

### Invoke-RestMethod (PowerShell)

```powershell
$env:KEYFACTOR_HOSTNAME = "my-command.example.com"
# OAuth (token):
$env:KEYFACTOR_AUTH_ACCESS_TOKEN = "eyJ..."
# or OAuth (client credentials):
$env:KEYFACTOR_AUTH_CLIENT_ID     = "my-client"
$env:KEYFACTOR_AUTH_CLIENT_SECRET = "secret"
$env:KEYFACTOR_AUTH_TOKEN_URL     = "https://auth.example.com/realms/keyfactor/protocol/openid-connect/token"
# or Basic auth:
$env:KEYFACTOR_USERNAME = "svc-account"
$env:KEYFACTOR_PASSWORD = "hunter2"
$env:KEYFACTOR_DOMAIN   = "corp"

.\powershell\restmethod_create_store_types.ps1
```

## Regenerating Scripts

After updating `integration-manifest.json`, regenerate these scripts with:

```bash
make store-types-gen-scripts   # uses doctool if installed, otherwise python3
```

Or directly:
```bash
# via doctool
doctool generate-store-type-scripts --manifest-path integration-manifest.json --output-dir scripts/store_types

# via standalone script
python3 scripts/store_types/generate_scripts.py
```
