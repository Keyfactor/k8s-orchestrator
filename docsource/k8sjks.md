## Overview

The K8SJKS Certificate Store Type is designed to manage Java Keystores (JKS) that are stored within Kubernetes secrets of type `Opaque`. This store type specifically interacts with fields in Kubernetes secrets that contain JKS data, allowing for the inventory and management of certificates within these keystores.

### Representation

K8SJKS represents Kubernetes secrets that include one or more JKS files. Each entry within a JKS file is treated as a separate certificate entity, managed using a custom alias pattern. This is particularly useful for applications and services hosted within a Kubernetes cluster that require Java Keystore management.

### Usage and SDK

The K8SJKS Certificate Store Type does not require any additional SDKs and relies on direct interaction with the Kubernetes API through a service account. This interaction allows the orchestrator to inventory and manage secrets efficiently without needing any third-party libraries.

### Caveats and Limitations

There are a few important considerations when using the K8SJKS Certificate Store Type:

- **Service Account Permissions**: The service account must have the necessary permissions to list, create, update, and delete secrets within the Kubernetes namespace. Without sufficient permissions, the orchestrator will be unable to manage the JKS secrets.
- **Custom Alias Pattern**: The orchestrator manages certificates using a custom alias of the pattern `k8s_secret_field_name/keystore_alias`. Users must understand this pattern to correctly reference and manage specific certificates within a JKS.
- **Unique Credentials**: Each JKS requires unique credentials, making it impossible to manage them collectively at the cluster or namespace level. This granularity necessitates careful configuration to ensure each keystore is correctly managed.

By recognizing these considerations, the K8SJKS Certificate Store Type offers a robust solution for managing Java Keystores within Kubernetes, facilitating secure and efficient certificate lifecycle management for Java applications deployed in the cluster.

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

