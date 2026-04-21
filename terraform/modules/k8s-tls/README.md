# K8STLSSecr - Kubernetes TLS Secrets

Manages a Keyfactor Command certificate store for Kubernetes TLS secrets (`kubernetes.io/tls`).

TLS secrets use the standard Kubernetes format with `tls.crt` and `tls.key` fields. This module supports deploying certificates and optionally storing the certificate chain separately in the `ca.crt` field.

## Usage

### Basic TLS secret store

```hcl
module "tls_store" {
  source = "../modules/k8s-tls"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/my-namespace/my-tls-secret"
  kubeconfig_path  = "./kubeconfig.json"
}
```

### With certificate deployments and separate chain

```hcl
module "tls_store" {
  source = "../modules/k8s-tls"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/my-namespace/my-tls-secret"
  kubeconfig_path  = "./kubeconfig.json"
  separate_chain   = true

  certificate_ids = [
    keyfactor_certificate.web_cert.certificate_id,
    keyfactor_certificate.api_cert.certificate_id,
  ]
}
```

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
| kube_namespace | Kubernetes namespace (overrides store_path). | `string` | `null` | no |
| kube_secret_name | Kubernetes secret name (overrides store_path). | `string` | `null` | no |
| include_cert_chain | Include the full certificate chain when deploying. | `bool` | `true` | no |
| separate_chain | Store chain separately in the `ca.crt` field. | `bool` | `false` | no |
| server_use_ssl | Use SSL for the K8S API connection. | `bool` | `true` | no |
| inventory_schedule | How often to run inventory. | `string` | `"1d"` | no |
| certificate_ids | List of certificate IDs to deploy to this store. | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| store_id | The ID of the created certificate store. |
| store_path | The store path of the certificate store. |
| store_type | The store type (always K8STLSSecr). |
| deployment_ids | Map of certificate ID to deployment resource ID. |
