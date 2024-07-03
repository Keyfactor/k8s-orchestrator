## K8SJKS

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

The recommended method for creating the `K8SJKS` Certificate Store Type is to use [kfutil](https://github.com/Keyfactor/kfutil). After installing, use the following command to create the `` Certificate Store Type:

```shell
kfutil store-types create K8SJKS
```

<details><summary>K8SJKS</summary>

Create a store type called `K8SJKS` with the attributes in the tables below:

### Basic Tab
| Attribute | Value | Description |
| --------- | ----- | ----- |
| Name | K8SJKS | Display name for the store type (may be customized) |
| Short Name | K8SJKS | Short display name for the store type |
| Capability | K8SJKS | Store type name orchestrator will register with. Check the box to allow entry of value |
| Supported Job Types (check the box for each) | Add, Discovery, Remove | Job types the extension supports |
| Supports Add | ✅ | Check the box. Indicates that the Store Type supports Management Add |
| Supports Remove | ✅ | Check the box. Indicates that the Store Type supports Management Remove |
| Supports Discovery | ✅ | Check the box. Indicates that the Store Type supports Discovery |
| Supports Reenrollment |  |  Indicates that the Store Type supports Reenrollment |
| Supports Create | ✅ | Check the box. Indicates that the Store Type supports store creation |
| Needs Server | ✅ | Determines if a target server name is required when creating store |
| Blueprint Allowed |  | Determines if store type may be included in an Orchestrator blueprint |
| Uses PowerShell |  | Determines if underlying implementation is PowerShell |
| Requires Store Password | ✅ | Determines if a store password is required when configuring an individual store. |
| Supports Entry Password |  | Determines if an individual entry within a store can have a password. |

The Basic tab should look like this:

![K8SJKS Basic Tab](../docsource/images/K8SJKS-basic-store-type-dialog.png)

### Advanced Tab
| Attribute | Value | Description |
| --------- | ----- | ----- |
| Supports Custom Alias | Required | Determines if an individual entry within a store can have a custom Alias. |
| Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
| PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

The Advanced tab should look like this:

![K8SJKS Advanced Tab](../docsource/images/K8SJKS-advanced-store-type-dialog.png)

### Custom Fields Tab
Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

| Name | Display Name | Type | Default Value/Options | Required | Description |
| ---- | ------------ | ---- | --------------------- | -------- | ----------- |


The Custom Fields tab should look like this:

![K8SJKS Custom Fields Tab](../docsource/images/K8SJKS-custom-fields-store-type-dialog.png)



</details>

## Certificate Store Configuration

After creating the `K8SJKS` Certificate Store Type and installing the Kubernetes Universal Orchestrator extension, you can create new [Certificate Stores](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store) to manage certificates in the remote platform.

The following table describes the required and optional fields for the `K8SJKS` certificate store type.

| Attribute | Description | Attribute is PAM Eligible |
| --------- | ----------- | ------------------------- |
| Category | Select "K8SJKS" or the customized certificate store name from the previous step. | |
| Container | Optional container to associate certificate store with. | |
| Client Machine | For the Client Machine field when instantiating new Certificate Stores of type 'K8SJKS', enter the Kubernetes cluster endpoint or API server URL. Example: 'https://api.k8s.cluster.local:6443'. | |
| Store Path | For the Store Path field when instantiating new Certificate Stores of type 'K8SJKS', enter the namespace and the secret name containing the JKS data in the format 'namespace/secretName'. Example: 'default/my-jks-secret'. | |
| Orchestrator | Select an approved orchestrator capable of managing `K8SJKS` certificates. Specifically, one with the `K8SJKS` capability. | |

* **Using kfutil**

    ```shell
    # Generate a CSV template for the AzureApp certificate store
    kfutil stores import generate-template --store-type-name K8SJKS --outpath K8SJKS.csv

    # Open the CSV file and fill in the required fields for each certificate store.

    # Import the CSV file to create the certificate stores
    kfutil stores import csv --store-type-name K8SJKS --file K8SJKS.csv
    ```

* **Manually with the Command UI**: In Keyfactor Command, navigate to Certificate Stores from the Locations Menu. Click the Add button to create a new Certificate Store using the attributes in the table above.