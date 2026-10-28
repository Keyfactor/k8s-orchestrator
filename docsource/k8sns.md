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
  Ignored namespaces are skipped before anything is listed in them, so the service account does not need permission to
  list secrets there (for example `kube-system`).

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

The namespace in the store path is always matched literally (case-insensitive), with no wildcard meaning. In particular, a
namespace that is really named `all` is inventoried like any other namespace and returns only its own secrets. The word
`all` is a keyword only in the discovery `Directories to search` field, where it selects every namespace, so such a
namespace cannot be selected by name there; add its store manually using the store path above.

### Alias Patterns

Inventory reports one entry per secret, keyed by the alias `<tls|opaque>/<secret_name>`
(for example `tls/my-tls-secret` or `opaque/my-opaque-secret`). Each entry holds the full certificate chain found in
that secret.

- `<tls|opaque>/<secret_name>` (the alias returned by inventory in 2.0 and later)
- `secrets/<tls|opaque>/<secret_name>` (the 1.x alias form; still accepted by Management Add/Remove, which uses the
  last two segments of the alias)

> **Upgrade note (1.x to 2.0):** 1.x inventory reported these entries as `secrets/<tls|opaque>/<secret_name>`. Existing
> inventory entries in Command are re-keyed on the first 2.0 inventory. See the 2.0.0 Breaking Changes in `CHANGELOG.md`.

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
