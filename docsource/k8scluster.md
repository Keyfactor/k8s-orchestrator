## Overview

The `K8SCluster` store type allows for a single store to manage a Kubernetes cluster's secrets of type `Opaque` and `kubernetes.io/tls`.

## Certificate Store Configuration

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SCluster` store types, they must
have specific keys in the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns
- `<cluster_name>`

### Alias Patterns
- `<namespace_name>/secrets/<tls|opaque>/<secret_name>`

## Terraform

A reusable Terraform module is available for this store type. See [terraform/modules/k8s-cluster](../terraform/modules/k8s-cluster/) for full documentation.

```hcl
module "cluster_store" {
  source = "./terraform/modules/k8s-cluster"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-k8s-cluster"
  kubeconfig_path  = "./kubeconfig.json"
}
```
