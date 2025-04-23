## Overview

The `K8SSecret` store type is used to manage Kubernetes secrets of type `Opaque`.

## Discovery Job Configuration

For discovery of K8SNS stores toy can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*

## Certificate Store Configuration

In order for certificates of type `Opaque` to be inventoried as `K8SSecret` store types, they must have specific keys in 
the Kubernetes secret.  
- Required keys: `tls.crt` or `ca.crt` 
- Additional keys: `tls.key`


