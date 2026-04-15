## Overview

The `K8SCert` store type is used to manage Kubernetes Certificate Signing Requests (CSRs) of type `certificates.k8s.io/v1`.

**NOTE**: Only `inventory` and `discovery` of these resources is supported with this extension. CSRs are read-only - to provision certificates through CSRs, use the [k8s-csr-signer](https://github.com/Keyfactor/k8s-csr-signer).

## Inventory Modes

K8SCert supports two inventory modes:

### Single CSR Mode (Legacy)

When `KubeSecretName` is set to a specific CSR name, the store inventories only that single CSR. This is useful when you want to track a specific certificate issued through a CSR.

**Configuration:**
- `KubeSecretName`: The name of the specific CSR to inventory (e.g., `my-app-csr`)

### Cluster-Wide Mode

When `KubeSecretName` is left empty or set to `*`, the store inventories ALL issued CSRs in the cluster. This provides a single-pane view of all certificates issued through Kubernetes CSRs.

**Configuration:**
- `KubeSecretName`: Leave empty or set to `*`

**Note:** Only CSRs that have been approved AND have an issued certificate are included in the inventory. Pending or denied CSRs are skipped.

## Store Configuration

| Property | Description | Required |
|----------|-------------|----------|
| **Client Machine** | A descriptive name for the Kubernetes cluster | Yes |
| **Store Path** | Can be any value (not used for CSR inventory) | Yes |
| **Server Username** | Leave empty or set to `kubeconfig` | No |
| **Server Password** | The kubeconfig JSON for connecting to the cluster | Yes |
| **KubeSecretName** | CSR name for single mode, or empty/`*` for cluster-wide mode | No |

## Discovery

Discovery will find all CSRs in the cluster that have issued certificates and return them as potential store locations. Each discovered CSR can be added as a separate K8SCert store (single CSR mode).

## Example Use Cases

### Track All Cluster Certificates

Create a single K8SCert store with `KubeSecretName` empty to get visibility into all certificates issued through Kubernetes CSRs:

1. Create a K8SCert store
2. Set `Client Machine` to your cluster name
3. Leave `KubeSecretName` empty
4. Run inventory to see all issued CSR certificates

### Track a Specific Application Certificate

Create a K8SCert store for a specific CSR:

1. Create a K8SCert store
2. Set `Client Machine` to your cluster name
3. Set `KubeSecretName` to the CSR name (e.g., `my-app-client-cert`)
4. Run inventory to track that specific certificate

## Limitations

- **Read-Only**: K8SCert does not support Add or Remove operations. CSRs must be created and approved through Kubernetes APIs or kubectl.
- **No Private Keys**: CSR certificates do not include private keys in Kubernetes (the private key stays with the requestor).
- **Cluster-Scoped**: CSRs are cluster-scoped resources (not namespaced).
