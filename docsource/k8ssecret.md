## Overview

The K8SSecret Certificate Store Type is designed to manage Kubernetes secrets of type `Opaque`. This store type provides functionality for storing and managing various certificates and their associated private keys within Kubernetes secrets, allowing for secure and organized certificate management.

### Representation

K8SSecret represents Kubernetes `Opaque` secrets that can contain arbitrary fields. However, the orchestrator specifically manages fields named `certificates` and `private_keys`, ensuring that certificate and key data is handled securely and efficiently. This is useful for various applications and services within a Kubernetes cluster that need to securely store and access certificates.

### Usage and SDK

The K8SSecret Certificate Store Type communicates directly with the Kubernetes API using a service account, eliminating the need for any additional SDKs. The orchestrator leverages the permissions of the service account to perform necessary operations such as inventory, add, and remove certificates within the Kubernetes secrets.

### Caveats and Limitations

Several important considerations should be noted when using the K8SSecret Certificate Store Type:

- **Service Account Permissions**: The service account must have the appropriate permissions to create, list, update, and delete secrets within the specified Kubernetes namespace. Without sufficient permissions, the orchestrator will not be able to manage the secrets effectively.

- **Field Constraints**: The orchestrator will only manage the fields named `certificates` and `private_keys` within the secret. Any other fields will be ignored, which means users must ensure that the relevant data is stored in these fields.

- **Single Certificate Management**: This store type supports the management of a single certificate within each secret. Adding a new certificate will overwrite the existing fields in the secret. Users should be cautious of this behavior to avoid unintentional data loss.

By considering these factors, the K8SSecret Certificate Store Type offers a reliable way to manage `Opaque` secrets in Kubernetes, ensuring secure and efficient certificate lifecycle management within the cluster.

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

