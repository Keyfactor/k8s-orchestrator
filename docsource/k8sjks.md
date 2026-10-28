## Overview

The `K8SJKS` store type is used to manage Kubernetes secrets of type `Opaque`.  These secrets
must have a field that ends in `.jks`. The orchestrator will inventory and manage using a *custom alias* of the following
pattern: `<k8s_secret_field_name>/<keystore_alias>`.  For example, if the secret has a field named `mykeystore.jks` and
the keystore contains a certificate with an alias of `mycert`, the orchestrator will manage the certificate using the
alias `mykeystore.jks/mycert`. *NOTE* *This store type cannot be managed at the `cluster` or `namespace` level as they
should all require unique credentials.*

## Supported Key Types

The K8SJKS store type supports certificates with the following key algorithms:

| Key Type | Supported |
|----------|-----------|
| RSA (1024, 2048, 4096, 8192 bit) | Yes |
| ECDSA (P-256, P-384, P-521) | Yes |
| DSA (1024, 2048 bit) | Yes |
| Ed25519 | Yes |
| Ed448 | Yes |

## Discovery Job Configuration

For discovery of `K8SJKS` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all 
namespaces. Namespace names are trimmed and `all` is case-insensitive. If left blank, only the `default` namespace is searched.
- `File name patterns to match` - comma separated list of additional K8S secret data keys (or extensions) to look for
  JKS data in. Added to the default keys: `jks`, `keystore.jks`, `truststore.jks`.
- `File name extensions to match` - comma separated list of additional secret data key names/extensions to look for. Treated
  the same as `File name patterns to match` and added to the default keys.
- `Directories to ignore` - comma separated list of namespaces to exclude from the discovery results. Applies to every
  namespace in `Directories to search`, including when it is `all`. Namespace names are trimmed and compared case-insensitively.

Only `Opaque` secrets that contain at least one matching data key are discovered; other `Opaque` secrets are skipped. A data
key matches when it equals an allowed key or ends with `.<allowed key>`, case-insensitively, so the default `jks` matches
`keystore.jks`, `truststore.jks` and `my-app.jks`. A keystore stored under a data key with no extension (for example
`keystore`) is not discovered unless that exact name is added via `File name patterns to match`.

## Certificate Store Configuration

In order for certificates of type `Opaque` to be inventoried as `K8SJKS` store types, they must have specific keys in
the Kubernetes secret.
- Valid Keys: `*.jks`

### Storepath Patterns
- `<namespace_name>/<secret_name>`
- `<namespace_name>/secrets/<secret_name>`
- `<cluster_name>/<namespace_name>/secrets/<secret_name>`

### Alias Patterns
- `<k8s_secret_field_name>/<keystore_alias>`

This alias format is unchanged from 1.x. One entry is reported per keystore alias in every keystore field of the secret.
Private-key entries are reported with their certificate chain and the private-key flag set. Trusted-certificate entries
(for example CA trust anchors) are reported as a single certificate with the private-key flag cleared, and can be added
and removed through Management like any other alias. Before 2.0.2, trusted-certificate entries were not inventoried.

Example: `test.jks/load_balancer` where `test.jks` is the field name on the `Opaque` secret and `load_balancer` is
the certificate alias in the `jks` data store.

## Terraform

A reusable Terraform module is available for this store type. See [terraform/modules/k8s-jks](../terraform/modules/k8s-jks/) for full documentation.

```hcl
module "jks_store" {
  source = "./terraform/modules/k8s-jks"

  client_machine              = "my-orchestrator"
  agent_identifier            = "my-orchestrator"
  store_path                  = "my-cluster/my-namespace/my-jks-secret"
  kubeconfig_path             = "./kubeconfig.json"
  store_password              = var.jks_password
  certificate_data_field_name = "keystore.jks"

  certificate_ids = ["12345"]
}
```
