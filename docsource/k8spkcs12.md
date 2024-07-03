## Overview

The K8SPKCS12 Certificate Store Type is designed to manage PKCS12 files stored within Kubernetes secrets of type `Opaque`. This store type focuses on secrets containing PKCS12 data, allowing for the inventory and management of certificates and keys within these files.

### Representation

K8SPKCS12 represents Kubernetes secrets that include one or more PKCS12 files. Each file within a secret is treated as a separate certificate entity, managed using a custom alias pattern. This is particularly useful for applications requiring PKCS12 format for their keystores, commonly seen in Java applications and other use-cases requiring bundled certificates and keys.

### Usage and SDK

The K8SPKCS12 Certificate Store Type does not require any additional SDKs beyond the orchestrator’s capabilities. It communicates directly with the Kubernetes API using a service account to perform its operations. No third-party libraries are needed.

### Caveats and Limitations

Several important considerations should be noted when using the K8SPKCS12 Certificate Store Type:

- **Service Account Permissions**: The service account must have sufficient permissions to list, create, update, and delete secrets in the Kubernetes namespace where the secrets reside. Without these permissions, the orchestrator cannot function correctly.

- **Custom Alias Pattern**: The orchestrator uses a custom alias pattern for managing certificates: `<k8s_secret_field_name>/<keystore_alias>`. Users should be familiar with this pattern to correctly reference and manage specific certificates within a PKCS12 file.

- **Password Management**: PKCS12 files often require passwords to access their contents. The orchestrator supports various methods for password management, including specifying passwords directly in the secrets or through other configuration fields.

- **Unique Credentials**: Each PKCS12 file may require unique credentials, which makes it challenging to manage them collectively at the cluster or namespace level. This requires detailed configuration to ensure each PKCS12 keystore is managed correctly.

By considering these factors, the K8SPKCS12 Certificate Store Type offers a robust solution for managing PKCS12 files within Kubernetes, facilitating secure and efficient certificate lifecycle management for applications that rely on this format.

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

