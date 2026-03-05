## Overview

The `K8STLSSecr` store type is used to manage Kubernetes secrets of type `kubernetes.io/tls`.

## Discovery Job Configuration

For discovery of `K8STLSSecr` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*

## Certificate Store Configuration

In order for certificates of type `kubernetes.io/tls` to be inventoried, they must have specific keys in
the Kubernetes secret.
- Required keys: `tls.crt` and `tls.key`
- Optional keys: `ca.crt`

### Storepath Patterns

- `<secret_name>`
- `<namespace_name>/<secret_name>`

### Alias Patterns

- `<secret_name>` (the TLS secret name)

