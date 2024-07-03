## Overview

The K8SNS Certificate Store Type is designed to manage certificates within a specific Kubernetes namespace. This store type aggregates secrets of type `Opaque` and `kubernetes.io/tls` within a defined namespace, effectively acting as a container for `K8SSecret` and `K8STLSSecret` stores in that namespace.

### Representation

K8SNS represents a high-level grouping of secrets management focused on a single Kubernetes namespace. By managing all relevant secrets within this scope, it allows for more centralized and controlled certificate management across that namespace. This is particularly useful for segmenting and managing certificates in multi-tenant environments or environments with specific namespace-based security policies.

### Usage and SDK

The K8SNS Certificate Store Type interacts directly with the Kubernetes API through a service account, thus it does not require any additional SDKs. The orchestrator uses the permissions granted to the service account to manage secrets efficiently within the specified namespace.

### Caveats and Limitations

There are important considerations when using the K8SNS Certificate Store Type:

- **Service Account Permissions**: The service account must have sufficient permissions to list, create, update, and delete secrets within the target namespace. Insufficient permissions can prevent the orchestrator from functioning correctly.
- **Namespace Scope**: While this store type is useful for managing certificates within a single namespace, it does not provide a cross-namespace management capability. Users must set up individual stores for each namespace they want to manage.
- **Field Requirements**: This store type will only inventory secrets that contain the keys `tls.crt` and `tls.key`. Other data within the secret will be ignored.

By taking these considerations into account, the K8SNS Certificate Store Type provides an effective solution for managing certificates within a Kubernetes namespace, supporting secure and organized certificate lifecycle management.

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

