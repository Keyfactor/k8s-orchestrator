## Overview

The `K8SSecret` store type is used to manage Kubernetes secrets of type `Opaque`.

## Discovery Job Configuration

For discovery of `K8SSecret` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*

## Certificate Store Configuration

In order for certificates of type `Opaque` to be inventoried as `K8SSecret` store types, they must have specific keys in
the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns

- `<secret_name>`
- `<namespace_name>/<secret_name>`

### Alias Patterns

- `<secret_name>` (when certificate is stored directly)

## Terraform

A reusable Terraform module is available for this store type. See [terraform/modules/k8s-secret](../terraform/modules/k8s-secret/) for full documentation.

```hcl
module "secret_store" {
  source = "./terraform/modules/k8s-secret"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/my-namespace/my-opaque-secret"
  kubeconfig_path  = "./kubeconfig.json"

  certificate_ids = ["12345"]
}
```

