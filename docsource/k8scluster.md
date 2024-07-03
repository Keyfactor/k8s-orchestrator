## Overview

The K8SCluster Certificate Store Type enables the management of certificates across an entire Kubernetes cluster. This store type is designed to handle Kubernetes secrets of type `Opaque` and `kubernetes.io/tls` across all namespaces within a cluster, acting as a container for `K8SSecret` and `K8STLSSecret` stores.

### Representation

K8SCluster represents a higher-level aggregation of secrets management, providing a unified interface to manage certificates across multiple namespaces. This is particularly useful for organizations wanting centralized control over their certificate infrastructure within a Kubernetes environment.

### Usage and SDK

The K8SCluster Certificate Store Type does not require any additional SDKs as it relies on Kubernetes’ native API capabilities. The orchestrator uses a service account to interact with the Kubernetes API, performing operations needed to inventory and manage secrets across the cluster.

### Caveats and Limitations

There are some important considerations when using the K8SCluster Certificate Store Type:

- **Service Account Permissions**: The service account should have sufficient permissions to list, create, update, and delete secrets across all namespaces. The lack of such permissions can hinder the orchestrator's ability to manage certificates.
- **Resource Scope**: Managing certificates at the cluster level can be complex due to the varied configurations and security policies across different namespaces. It's important to ensure that sensitive data is properly segregated and managed according to security best practices.
- **Configuration Complexity**: Given the broad scope of management, initial configuration can be intricate. Proper attention to detail is required to ensure all namespaces and their resources are correctly configured for certificate management.

The K8SCluster Certificate Store Type offers a comprehensive solution for managing certificates across a Kubernetes cluster, providing centralized control while ensuring secure and efficient certificate lifecycle management.

## Requirements

### Security Considerations
For the Kubernetes Orchestrator Extension to be able to communicate with a Kubernetes cluster, it must
be able to authenticate with the cluster.  This is done by providing the extension with a service account
token that has the appropriate permissions to perform the desired operations. The service account token
can be provided to the extension in one of two ways:
- As a raw JSON file that contains the service account credentials
- As a base64 encoded string that contains the service account credentials

### Service Account Setup
To set up a service account user on your Kubernetes cluster to be used by the Kubernetes Orchestrator Extension, use the following example as a guide:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: keyfactor
  namespace: keyfactor
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keyfactor
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: keyfactor
roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: keyfactor
subjects:
- kind: ServiceAccount
  name: keyfactor
  namespace: keyfactor
```

### Service Account Setup
To set up a service account user on your Kubernetes cluster to be used by the Kubernetes Orchestrator Extension, use the following example as a guide:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: keyfactor
  namespace: keyfactor
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keyfactor
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: keyfactor
roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: keyfactor
subjects:
- kind: ServiceAccount
  name: keyfactor
  namespace: keyfactor
```

