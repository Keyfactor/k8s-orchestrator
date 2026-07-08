# K8SNS - Namespace-Level Secret Management

Manages a Keyfactor Command certificate store that represents all Opaque and TLS secrets within a single Kubernetes namespace.

A single K8SNS store acts as a container for all `K8SSecret` and `K8STLSSecr` secrets in the namespace. This is useful for managing all certificates in a namespace from a single store.

## Usage

### Basic namespace store

```hcl
module "ns_store" {
  source = "../modules/k8s-ns"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/namespace/my-namespace"
  kubeconfig_path  = "./kubeconfig.json"
  kube_namespace   = "my-namespace"
}
```

### With certificate deployments

```hcl
module "ns_store" {
  source = "../modules/k8s-ns"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/namespace/production"
  kubeconfig_path  = "./kubeconfig.json"
  kube_namespace   = "production"

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
| store_path | The store path for the namespace. | `string` | n/a | yes |
| kubeconfig_path | Path to the kubeconfig JSON file. | `string` | n/a | yes |
| kube_namespace | Kubernetes namespace (overrides store_path). | `string` | `null` | no |
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
| store_type | The store type (always K8SNS). |
| deployment_ids | Map of certificate ID to deployment resource ID. |
