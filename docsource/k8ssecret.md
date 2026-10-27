## Overview

The `K8SSecret` store type is used to manage Kubernetes secrets of type `Opaque`.

## Discovery Job Configuration

For discovery of `K8SSecret` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. Namespace names are trimmed and `all` is case-insensitive. If left blank, only the `default` namespace is searched.
- `Directories to ignore` - comma separated list of namespaces to exclude from the discovery results. Applies to every
  namespace in `Directories to search`, including when it is `all`. Namespace names are trimmed and compared case-insensitively.

An `Opaque` secret is discovered only when it contains a data key that `K8SSecret` inventory reads as a certificate.
Keys are matched exactly and case-sensitively: `tls.crt`, `certificate`, `cert`, `crt`, `cert.pem`, `certificate.pem`.
Secrets that hold only a private key (`tls.key`, `key`, `private-key`, ...), only CA data (`ca`, `ca.crt`, `ca-bundle`),
or a key that merely ends in one of these names (for example `server.crt`) are not discovered.

Entries in `File name patterns to match` are added to this list and are also matched exactly (`my-bundle` matches a data
key named `my-bundle`, not `prod.my-bundle`).

> **Known limitation:** `K8SSecret` has no `CertificateDataFieldName` store property, so a secret discovered only through
> a custom pattern is listed by discovery but inventory will not read certificates from that key. Rename the key to one of
> the supported names above.

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


