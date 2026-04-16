# K8SPKCS12 - PKCS12 Keystores in Kubernetes Secrets

Manages a Keyfactor Command certificate store for PKCS12/PFX files stored as base64-encoded data in Kubernetes Opaque secrets.

PKCS12 keystores require a password, which can be provided directly or referenced from a separate Kubernetes secret ("buddy password" pattern).

## Usage

### Basic PKCS12 store with direct password

```hcl
module "pkcs12_store" {
  source = "../modules/k8s-pkcs12"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/my-namespace/my-pkcs12-secret"
  kubeconfig_path  = "./kubeconfig.json"
  store_password   = var.pkcs12_password
}
```

### PKCS12 store with buddy password (separate K8S secret)

```hcl
module "pkcs12_store" {
  source = "../modules/k8s-pkcs12"

  client_machine                 = "my-orchestrator"
  agent_identifier               = "my-orchestrator"
  store_path                     = "my-cluster/my-namespace/my-pkcs12-secret"
  kubeconfig_path                = "./kubeconfig.json"
  store_password_k8s_secret_path = "my-namespace/my-password-secret"
  password_field_name            = "store-password"
}
```

### With custom field name and certificate deployments

```hcl
module "pkcs12_store" {
  source = "../modules/k8s-pkcs12"

  client_machine              = "my-orchestrator"
  agent_identifier            = "my-orchestrator"
  store_path                  = "my-cluster/my-namespace/my-pkcs12-secret"
  kubeconfig_path             = "./kubeconfig.json"
  store_password              = var.pkcs12_password
  certificate_data_field_name = "keystore.pfx"

  certificate_ids = [
    keyfactor_certificate.my_cert.certificate_id,
  ]
}
```

## Password Options

PKCS12 keystores require a password. You have two options:

1. **Direct password** - Set `store_password` to the keystore password. This is stored in Keyfactor Command as the store password.

2. **Buddy password** - Set `store_password_k8s_secret_path` to point to a Kubernetes secret that contains the password. The `password_field_name` specifies which field in that secret holds the password. This automatically sets `PasswordIsK8SSecret = true`.

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5 |
| keyfactor | >= 2.1.11 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| client_machine | The client machine name of the orchestrator. | `string` | n/a | yes |
| agent_identifier | The orchestrator agent GUID or client machine name. | `string` | n/a | yes |
| store_path | The store path. Format: `<cluster>/<namespace>/<secret-name>`. | `string` | n/a | yes |
| kubeconfig_path | Path to the kubeconfig JSON file. | `string` | n/a | yes |
| store_password | Direct keystore password. | `string` | `null` | no* |
| store_password_k8s_secret_path | Path to K8S secret with password (`<ns>/<name>`). | `string` | `null` | no* |
| password_field_name | Field name for the password in the K8S secret. | `string` | `"password"` | no |
| kube_namespace | Kubernetes namespace (overrides store_path). | `string` | `null` | no |
| kube_secret_name | Kubernetes secret name (overrides store_path). | `string` | `null` | no |
| certificate_data_field_name | Field name for PKCS12 data in the K8S secret. | `string` | `".p12"` | no |
| include_cert_chain | Include the full certificate chain when deploying. | `bool` | `true` | no |
| server_use_ssl | Use SSL for the K8S API connection. | `bool` | `true` | no |
| inventory_schedule | How often to run inventory. | `string` | `"1d"` | no |
| certificate_ids | List of certificate IDs to deploy to this store. | `list(string)` | `[]` | no |

\* One of `store_password` or `store_password_k8s_secret_path` should be provided.

## Outputs

| Name | Description |
|------|-------------|
| store_id | The ID of the created certificate store. |
| store_path | The store path of the certificate store. |
| store_type | The store type (always K8SPKCS12). |
| password_is_k8s_secret | Whether the password is stored in a separate K8S secret. |
| deployment_ids | Map of certificate ID to deployment resource ID. |
