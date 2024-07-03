## Overview

The K8SCert Certificate Store Type is designed to manage Kubernetes certificates of type `certificates.k8s.io/v1`. This store type interacts with Kubernetes' native CertificateSigningRequest (CSR) resources and manages the lifecycle of Kubernetes certificates, ensuring they are deployed and updated as needed within the cluster.

### Representation

K8SCert represents the certificates requested and issued via Kubernetes' CSR API. These certificates are often employed for various internal Kubernetes operations, such as securing API calls and container-to-container communications within the cluster. By managing these certificates, the orchestrator ensures that communication between different Kubernetes components remains secure.

### Usage and SDK

The K8SCert Certificate Store Type does not require any additional SDKs as it communicates directly with the Kubernetes API using a service account. This integration leverages Kubernetes’ native capabilities to handle certificate requests and issuances, making use of the service account's permissions to perform necessary operations.

### Caveats and Limitations

There are a few important considerations when using the K8SCert Certificate Store Type:

- **Service Account Permissions**: The service account used by the orchestrator must have the necessary permissions to create, view, update, and delete CSRs within the cluster. Insufficient permissions will result in failures to manage certificates properly.
- **Chain of Trust**: Be aware of the chain of trust for certificates managed by the K8SCert store type. Properly configuring and maintaining the trust chain is critical to maintain secure communications.
- **Private Key Handling**: This store type doesn't handle private keys directly within Kubernetes secrets but rather relies on the managed CSR’s mechanisms to secure keys.

The K8SCert Certificate Store Type offers a robust approach to managing Kubernetes-native certificates, ensuring secure and authenticated communication within your Kubernetes environment.

## Requirements

### Security Considerations
For the Kubernetes Orchestrator Extension to be able to communicate with a Kubernetes cluster, it must
be able to authenticate with the cluster.  This is done by providing the extension with a service account
token that has the appropriate permissions to perform the desired operations. The service account token
can be provided to the extension in one of two ways:
- As a raw JSON file that contains the service account credentials
- As a base64 encoded string that contains the service account credentials

#### Service Account Setup
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

