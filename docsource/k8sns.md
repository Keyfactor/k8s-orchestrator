## Overview

The `K8SNS` store type is used to manage Kubernetes secrets of type `kubernetes.io/tls` and/or type `Opaque` in a single 
Keyfactor Command certificate store using an alias pattern of

## Discovery Job Configuration

For discovery of K8SNS stores toy can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all 
namespaces. *This cannot be left blank.*

## Certificate Store Configuration

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SNS` store types, they must 
have specific keys in the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns
- `<namespace_name>`
- `<cluster_name>/<namespace_name>`

### Alias Patterns
- `secrets/<tls|opaque>/<secret_name>`


