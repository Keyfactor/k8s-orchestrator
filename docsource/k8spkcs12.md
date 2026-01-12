## Overview

The `K8SPKCS12` store type is used to manage Kubernetes secrets of type `Opaque`.  These secrets
must have a field that ends in `.pkcs12`. The orchestrator will inventory and manage using a *custom alias* of the following
pattern: `<k8s_secret_field_name>/<keystore_alias>`.  For example, if the secret has a field named `mykeystore.pkcs12` and
the keystore contains a certificate with an alias of `mycert`, the orchestrator will manage the certificate using the
alias `mykeystore.pkcs12/mycert`. *NOTE* *This store type cannot be managed at the `cluster` or `namespace` level as they
should all require unique credentials.*

## Discovery Job Configuration

For discovery of `K8SPKCS12` stores toy can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*
- `File name patterns to match` - comma separated list of K8S secret keys to search for PKCS12 or PKCS12 data. Will use
  the following keys by default: `tls.pfx`,`tls.pkcs12`,`pfx`,`pkcs12`,`tls.pkcs12`,`pkcs12`.

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

Example: `test.pkcs12/load_balancer` where `test.pkcs12` is the field name on the `Opaque` secret and `load_balancer` is
the certificate alias in the `pkcs12` data store. 

