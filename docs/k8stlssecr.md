## K8STLSSecr

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



### Supported Job Types

| Job Name | Supported |
| -------- | --------- |
| Inventory | ✅ |
| Management Add | ✅ |
| Management Remove | ✅ |
| Discovery | ✅ |
| Create | ✅ |
| Reenrollment |  |

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



## Certificate Store Type Configuration

The recommended method for creating the `K8STLSSecr` Certificate Store Type is to use [kfutil](https://github.com/Keyfactor/kfutil). After installing, use the following command to create the `` Certificate Store Type:

```shell
kfutil store-types create K8STLSSecr
```

<details><summary>K8STLSSecr</summary>

Create a store type called `K8STLSSecr` with the attributes in the tables below:

### Basic Tab
| Attribute | Value | Description |
| --------- | ----- | ----- |
| Name | K8STLSSecr | Display name for the store type (may be customized) |
| Short Name | K8STLSSecr | Short display name for the store type |
| Capability | K8STLSSecr | Store type name orchestrator will register with. Check the box to allow entry of value |
| Supported Job Types (check the box for each) | Add, Discovery, Remove | Job types the extension supports |
| Supports Add | ✅ | Check the box. Indicates that the Store Type supports Management Add |
| Supports Remove | ✅ | Check the box. Indicates that the Store Type supports Management Remove |
| Supports Discovery | ✅ | Check the box. Indicates that the Store Type supports Discovery |
| Supports Reenrollment |  |  Indicates that the Store Type supports Reenrollment |
| Supports Create | ✅ | Check the box. Indicates that the Store Type supports store creation |
| Needs Server | ✅ | Determines if a target server name is required when creating store |
| Blueprint Allowed |  | Determines if store type may be included in an Orchestrator blueprint |
| Uses PowerShell |  | Determines if underlying implementation is PowerShell |
| Requires Store Password |  | Determines if a store password is required when configuring an individual store. |
| Supports Entry Password |  | Determines if an individual entry within a store can have a password. |

The Basic tab should look like this:

![K8STLSSecr Basic Tab](../docsource/images/K8STLSSecr-basic-store-type-dialog.png)

### Advanced Tab
| Attribute | Value | Description |
| --------- | ----- | ----- |
| Supports Custom Alias | Forbidden | Determines if an individual entry within a store can have a custom Alias. |
| Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
| PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

The Advanced tab should look like this:

![K8STLSSecr Advanced Tab](../docsource/images/K8STLSSecr-advanced-store-type-dialog.png)

### Custom Fields Tab
Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

| Name | Display Name | Type | Default Value/Options | Required | Description |
| ---- | ------------ | ---- | --------------------- | -------- | ----------- |


The Custom Fields tab should look like this:

![K8STLSSecr Custom Fields Tab](../docsource/images/K8STLSSecr-custom-fields-store-type-dialog.png)



</details>

## Certificate Store Configuration

After creating the `K8STLSSecr` Certificate Store Type and installing the Kubernetes Universal Orchestrator extension, you can create new [Certificate Stores](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store) to manage certificates in the remote platform.

The following table describes the required and optional fields for the `K8STLSSecr` certificate store type.

| Attribute | Description | Attribute is PAM Eligible |
| --------- | ----------- | ------------------------- |
| Category | Select "K8STLSSecr" or the customized certificate store name from the previous step. | |
| Container | Optional container to associate certificate store with. | |
| Client Machine | The `Client Machine` field should contain the IP address or hostname of the Kubernetes cluster's API server. For example, 'https://k8s.cluster.local:6443'. | |
| Store Path | The `Store Path` field should contain the namespace and name of the Kubernetes TLS secret in the format 'namespace/secretName'. For example, 'default/my-tls-secret'. | |
| Orchestrator | Select an approved orchestrator capable of managing `K8STLSSecr` certificates. Specifically, one with the `K8STLSSecr` capability. | |

* **Using kfutil**

    ```shell
    # Generate a CSV template for the AzureApp certificate store
    kfutil stores import generate-template --store-type-name K8STLSSecr --outpath K8STLSSecr.csv

    # Open the CSV file and fill in the required fields for each certificate store.

    # Import the CSV file to create the certificate stores
    kfutil stores import csv --store-type-name K8STLSSecr --file K8STLSSecr.csv
    ```

* **Manually with the Command UI**: In Keyfactor Command, navigate to Certificate Stores from the Locations Menu. Click the Add button to create a new Certificate Store using the attributes in the table above.