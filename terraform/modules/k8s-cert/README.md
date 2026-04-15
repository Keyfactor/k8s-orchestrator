# K8SCert - Kubernetes Certificate Signing Requests

Manages a Keyfactor Command certificate store for Kubernetes Certificate Signing Requests (`certificates.k8s.io/v1`).

This store type is **read-only** - it supports inventory and discovery only. Certificates cannot be deployed through this store type (use [k8s-csr-signer](https://github.com/Keyfactor/k8s-csr-signer) for CSR provisioning).

## Usage

```hcl
module "k8s_cert_store" {
  source = "../modules/k8s-cert"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-k8s-cluster"
  kubeconfig_path  = "./kubeconfig.json"
}
```

### Inventory a specific CSR

```hcl
module "k8s_cert_store" {
  source = "../modules/k8s-cert"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-k8s-cluster"
  kubeconfig_path  = "./kubeconfig.json"
  kube_secret_name = "my-specific-csr"
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
| kube_secret_name | Name of a specific CSR to inventory, or empty/'*' for all. | `string` | `""` | no |
| server_use_ssl | Whether to use SSL for the K8S API connection. | `bool` | `true` | no |
| inventory_schedule | How often to run inventory. | `string` | `"1d"` | no |

## Outputs

| Name | Description |
|------|-------------|
| store_id | The ID of the created certificate store. |
| store_path | The store path of the certificate store. |
| store_type | The store type (always K8SCert). |
