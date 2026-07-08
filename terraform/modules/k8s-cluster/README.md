# K8SCluster - Cluster-Wide Secret Management

Manages a Keyfactor Command certificate store that represents an entire Kubernetes cluster's Opaque and TLS secrets across all namespaces.

A single K8SCluster store acts as a container for all `K8SSecret` and `K8STLSSecr` secrets in the cluster. This is useful for centralized inventory and management of all certificates across namespaces.

## Usage

### Basic cluster store

```hcl
module "cluster_store" {
  source = "../modules/k8s-cluster"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-k8s-cluster"
  kubeconfig_path  = "./kubeconfig.json"
}
```

### With certificate deployments

```hcl
module "cluster_store" {
  source = "../modules/k8s-cluster"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-k8s-cluster"
  kubeconfig_path  = "./kubeconfig.json"
  separate_chain   = true

  certificate_ids = [
    keyfactor_certificate.web_cert.certificate_id,
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
| store_path | The store path (typically the cluster name). | `string` | n/a | yes |
| kubeconfig_path | Path to the kubeconfig JSON file. | `string` | n/a | yes |
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
| store_type | The store type (always K8SCluster). |
| deployment_ids | Map of certificate ID to deployment resource ID. |
