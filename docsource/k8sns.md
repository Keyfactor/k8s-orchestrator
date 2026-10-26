## Overview

The `K8SNS` store type is used to manage Kubernetes secrets of type `kubernetes.io/tls` and/or type `Opaque` in a single
Keyfactor Command certificate store. This store type manages all secrets within a specific Kubernetes namespace.

## Discovery Job Configuration

A `K8SNS` store is an entire namespace, so discovery returns **one store per namespace** (not one per secret). Each
discovered store location has the form `<cluster-name>/namespace/<namespace>` (for example `my-cluster/namespace/prod`) and
can be approved in Command as a `K8SNS` store as-is.

For discovery of `K8SNS` stores you can use the following params to select which namespaces are returned:
- `Directories to search` - comma separated list of namespaces to return OR `all` to return every namespace in the
  cluster. Namespace names are trimmed and `all` is case-insensitive. If left blank, only the `default` namespace is returned.
  A namespace that does not exist in the cluster is not returned (a warning is logged).
- `Directories to ignore` - comma separated list of namespaces to exclude from the discovery results. Applies to every
  namespace in `Directories to search`, including when it is `all`. Namespace names are trimmed and compared case-insensitively.

Every namespace matched by `Directories to search` (and not ignored) is returned, whether or not it currently contains
any certificate secrets. Secret-level filters such as `File name patterns to match` do not apply to `K8SNS` discovery.

## Certificate Store Configuration

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SNS` store types, they must 
have specific keys in the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns

- `<namespace_name>`
- `<cluster_name>/<namespace_name>`
- `<cluster_name>/namespace/<namespace_name>` (the form returned by discovery)

### Alias Patterns

- `secrets/<tls|opaque>/<secret_name>`

## Terraform

A reusable Terraform module is available for this store type. See [terraform/modules/k8s-ns](../terraform/modules/k8s-ns/) for full documentation.

```hcl
module "ns_store" {
  source = "./terraform/modules/k8s-ns"

  client_machine   = "my-orchestrator"
  agent_identifier = "my-orchestrator"
  store_path       = "my-cluster/namespace/my-namespace"
  kubeconfig_path  = "./kubeconfig.json"
  kube_namespace   = "my-namespace"
}
```
