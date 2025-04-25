## Overview

The `K8SCluster` store type allows for a single store to manage a k8s cluster's secrets or type `Opaque` and `kubernetes.io/tls`.

## Certificate Store Configuration

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SCluster` store types, they must
have specific keys in the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns
- `<cluster_name>`

### Alias Patterns
- `<namespace_name>/secrets/<tls|opaque>/<secret_name>`


