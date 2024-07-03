## Overview

The K8STLSSecr Certificate Store Type is designed to manage Kubernetes secrets of type `kubernetes.io/tls`. This store type specifically deals with secrets formatted for storing TLS certificates and their corresponding private keys, facilitating secure and structured certificate management within Kubernetes.

### Representation

K8STLSSecr represents Kubernetes `tls` secrets, which are used to store SSL/TLS certificates and their associated private keys. These secrets are critical for securing communications within a Kubernetes cluster, particularly for web services and other applications requiring SSL/TLS encryption.

### Usage and SDK

The K8STLSSecr Certificate Store Type does not require any additional SDKs. It directly communicates with the Kubernetes API using a service account, leveraging native Kubernetes capabilities to manage the inventory and lifecycle of TLS secrets.

### Caveats and Limitations

There are several important considerations to keep in mind when using the K8STLSSecr Certificate Store Type:

- **Service Account Permissions**: The service account must have sufficient permissions to create, list, update, and delete secrets within the designated namespace. Without adequate permissions, the orchestrator will be unable to manage the TLS secrets properly.

- **Field Requirements**: The `tls` secret must contain the `tls.crt` and `tls.key` fields. The orchestrator also supports the `ca.crt` field for storing the certificate chain. It's important to ensure these fields are present and correctly formatted.

- **Single Certificate Management**: This store type supports the storage and management of a single certificate and its private key per secret. Adding a new certificate will overwrite the existing data in the secret. Users should take care to avoid unintentional data loss.

- **Separate Chain Handling**: The orchestrator can handle the deployment of certificate chains. If the `SeparateChain` custom field is set to true, the chain will be stored in the `ca.crt` field, separated from the leaf certificate in `tls.crt`.

By considering these factors, the K8STLSSecr Certificate Store Type provides an effective solution for managing TLS secrets in Kubernetes, ensuring secure and efficient certificate lifecycle management for applications requiring SSL/TLS encryption.

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

