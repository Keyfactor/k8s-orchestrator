## Overview

The `K8STLSSecr` store type is used to manage Kubernetes secrets of type `kubernetes.io/tls`.

## Discovery Job Configuration

For discovery of `K8STLSSecr` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. Namespace names are trimmed and `all` is case-insensitive. If left blank, only the `default` namespace is searched.
- `Directories to ignore` - comma separated list of namespaces to exclude from the discovery results. Applies to every
  namespace in `Directories to search`, including when it is `all`. Namespace names are trimmed and compared case-insensitively.
  Ignored namespaces are skipped before anything is listed in them, so the service account does not need permission to
  list secrets there (for example `kube-system`).

Only secrets of type `kubernetes.io/tls` that contain a non-empty `tls.crt` are discovered. `tls.key` is not required: a
secret with `tls.crt` but no `tls.key` (a certificate-only TLS secret) is discovered and inventoried with its
certificate(s) and no private key.

## Certificate Store Configuration

In order for certificates of type `kubernetes.io/tls` to be inventoried, they must have specific keys in
the Kubernetes secret.
- Required keys: `tls.crt`
- Optional keys: `tls.key`, `ca.crt`

A secret without `tls.key` is inventoried with its certificate(s) and reported as having no private key. A secret
without a non-empty `tls.crt` is not a certificate store: discovery skips it, and inventory of a configured store
returns no certificates (a warning is logged).

### Storepath Patterns

- `<secret_name>`
- `<namespace_name>/<secret_name>`

### Alias Patterns

- `<secret_name>` (the TLS secret name)

Inventory reports a single entry for the secret, keyed by the secret name and holding the full certificate chain
(leaf first). Management Add/Remove operates on the whole secret and does not use the alias value to select content.

> **Upgrade note (1.x to 2.0):** 1.x keyed the inventory entry by the thumbprint of the first (leaf) certificate in the
> secret. 2.0 keys it by the secret name. Existing inventory entries in Command are re-keyed on the first 2.0 inventory.
> See the 2.0.0 Breaking Changes in `CHANGELOG.md`.

