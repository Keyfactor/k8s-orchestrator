## Overview

The `K8SCluster` store type allows for a single store to manage a Kubernetes cluster's secrets of type `Opaque` and `kubernetes.io/tls`.

## Certificate Store Configuration

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SCluster` store types, they must
have specific keys in the Kubernetes secret.
- `kubernetes.io/tls` secrets: required key `tls.crt`; optional keys `tls.key` and `ca.crt`. A secret with `tls.crt` but
  no `tls.key` is inventoried with its certificate(s) and no private key. A TLS secret without a non-empty `tls.crt` is
  not inventoried.
- `Opaque` secrets: every `Opaque` secret in the cluster is visited. A certificate is read from the first of `tls.crt`,
  `certificate`, `cert`, `crt`, `cert.pem`, `certificate.pem` (then `ca`, `ca-bundle`, `ca-bundle.crt`) that holds one,
  and certificates in `ca.crt` are added to it. A secret with no certificate (for example one that only holds a private
  key) contributes no inventory entry and is logged at Debug level only.
- Private key: a secret is reported as having a private key when `tls.key` (TLS) or one of `tls.key`, `key`,
  `private-key`, `key.pem`, `private-key.pem` (Opaque) is present.

### Storepath Patterns
- `<cluster_name>`

### Alias Patterns
- `<namespace_name>/secrets/<tls|opaque>/<secret_name>`

Inventory reports one entry per secret, holding the full certificate chain found in that secret. This alias format is
the same as in 1.x. Management Add/Remove requires exactly this form (at least four `/`-separated segments; the
namespace, type and secret name are taken from segments 1, 3 and 4).

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
