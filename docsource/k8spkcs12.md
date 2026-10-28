## Overview

The `K8SPKCS12` store type is used to manage Kubernetes secrets of type `Opaque`.  These secrets
must have a field that ends in `.pkcs12`. The orchestrator will inventory and manage using a *custom alias* of the following
pattern: `<k8s_secret_field_name>/<keystore_alias>`.  For example, if the secret has a field named `mykeystore.pkcs12` and
the keystore contains a certificate with an alias of `mycert`, the orchestrator will manage the certificate using the
alias `mykeystore.pkcs12/mycert`. *NOTE* *This store type cannot be managed at the `cluster` or `namespace` level as they
should all require unique credentials.*

## Supported Key Types

The K8SPKCS12 store type supports certificates with the following key algorithms:

| Key Type | Supported |
|----------|-----------|
| RSA (1024, 2048, 4096, 8192 bit) | Yes |
| ECDSA (P-256, P-384, P-521) | Yes |
| DSA (1024, 2048 bit) | Yes |
| Ed25519 | Yes |
| Ed448 | Yes |

## Discovery Job Configuration

For discovery of `K8SPKCS12` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. Namespace names are trimmed and `all` is case-insensitive. If left blank, only the `default` namespace is searched.
- `File name patterns to match` - comma separated list of additional K8S secret data keys (or extensions) to look for
  PKCS12 data in. Added to the default keys: `pkcs12`, `p12`, `pfx`, `keystore.p12`, `keystore.pfx`.
- `File name extensions to match` - comma separated list of additional secret data key names/extensions to look for. Treated
  the same as `File name patterns to match` and added to the default keys.
- `Directories to ignore` - comma separated list of namespaces to exclude from the discovery results. Applies to every
  namespace in `Directories to search`, including when it is `all`. Namespace names are trimmed and compared case-insensitively.

Only `Opaque` secrets that contain at least one matching data key are discovered; other `Opaque` secrets are skipped. A data
key matches when it equals an allowed key or ends with `.<allowed key>`, case-insensitively, so the default `pfx` matches
`keystore.pfx` and `server.pfx`, and `p12` matches `keystore.p12`. A keystore stored under a data key with no extension (for
example `keystore`) is not discovered unless that exact name is added via `File name patterns to match`.

## Certificate Store Configuration

In order for certificates of type `Opaque` to be inventoried as `K8SPKCS12` store types, they must have specific keys in
the Kubernetes secret.
- Valid Keys: `*.pfx`, `*.pkcs12`, `*.p12`

### Storepath Patterns

- `<namespace_name>/<secret_name>`
- `<namespace_name>/secrets/<secret_name>`
- `<cluster_name>/<namespace_name>/secrets/<secret_name>`

### Alias Patterns

- `<k8s_secret_field_name>/<keystore_alias>`

This alias format is unchanged from 1.x. One entry is reported per keystore alias in every keystore field of the secret.
The private-key flag is set only for aliases that contain a private key. Certificate-only aliases (for example CA trust
anchors) are reported as a single certificate without the flag. Before 2.0.2, every alias was flagged as having a key.

Example: `test.pkcs12/load_balancer` where `test.pkcs12` is the field name on the `Opaque` secret and `load_balancer` is
the certificate alias in the `pkcs12` data store.

## Terraform

A reusable Terraform module is available for this store type. See [terraform/modules/k8s-pkcs12](../terraform/modules/k8s-pkcs12/) for full documentation.

```hcl
module "pkcs12_store" {
  source = "./terraform/modules/k8s-pkcs12"

  client_machine              = "my-orchestrator"
  agent_identifier            = "my-orchestrator"
  store_path                  = "my-cluster/my-namespace/my-pkcs12-secret"
  kubeconfig_path             = "./kubeconfig.json"
  store_password              = var.pkcs12_password
  certificate_data_field_name = "keystore.pfx"

  certificate_ids = ["12345"]
}
```

