## Overview

The `K8SSecret` store type is used to manage Kubernetes secrets of type `Opaque`.

## Discovery Job Configuration

For discovery of `K8SSecret` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. Namespace names are trimmed and `all` is case-insensitive. If left blank, only the `default` namespace is searched.
- `Directories to ignore` - comma separated list of namespaces to exclude from the discovery results. Applies to every
  namespace in `Directories to search`, including when it is `all`. Namespace names are trimmed and compared case-insensitively.

Only `Opaque` secrets that contain at least one of the following data keys are discovered (other `Opaque` secrets, e.g.
ones holding only a username/password, are skipped): `tls.crt`, `tls.key`, `ca.crt`, `certificate`, `cert`, `crt`, `cert.pem`,
`certificate.pem`, `key`, `private-key`, `key.pem`, `private-key.pem`, `ca`, `ca-bundle`, `ca-bundle.crt`. A key also matches by
extension (for example `server.crt` matches `crt`) and matching is case-insensitive.

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


