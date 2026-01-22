<h1 align="center" style="border-bottom: none">
    Kubernetes Universal Orchestrator Extension
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/k8s-orchestrator/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/k8s-orchestrator?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/k8s-orchestrator?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/k8s-orchestrator/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=orchestrator">
    <b>Related Integrations</b>
  </a>
</p>

## Overview

The Kubernetes Orchestrator allows for the remote management of certificate stores defined in a Kubernetes cluster. 
The following types of Kubernetes resources are supported: kubernetes secrets of `kubernetes.io/tls` or `Opaque` and 
kubernetes certificates `certificates.k8s.io/v1`

The certificate store types that can be managed in the current version are:
- `K8SCert` - Kubernetes certificates of type `certificates.k8s.io/v1`
- `K8SSecret` - Kubernetes secrets of type `Opaque`
- `K8STLSSecret` - Kubernetes secrets of type `kubernetes.io/tls`
- `K8SCluster` - This allows for a single store to manage a k8s cluster's secrets or type `Opaque` and `kubernetes.io/tls`.
  This can be thought of as a container of `K8SSecret` and `K8STLSSecret` stores across all k8s namespaces.
- `K8SNS` - This allows for a single store to manage a k8s namespace's secrets or type `Opaque` and `kubernetes.io/tls`.
  This can be thought of as a container of `K8SSecret` and `K8STLSSecret` stores for a single k8s namespace.
- `K8SJKS` - Kubernetes secrets of type `Opaque` that contain one or more Java Keystore(s). These cannot be managed at the
  cluster or namespace level as they should all require unique credentials.
- `K8SPKCS12` - Kubernetes secrets of type `Opaque` that contain one or more PKCS12(s). These cannot be managed at the
  cluster or namespace level as they should all require unique credentials.

This orchestrator extension makes use of the Kubernetes API by using a service account
to communicate remotely with certificate stores. The service account must have the correct permissions
in order to perform the desired operations.  For more information on the required permissions, see the
[service account setup guide](#service-account-setup).

The Kubernetes Universal Orchestrator extension implements 7 Certificate Store Types. Depending on your use case, you may elect to use one, or all of these Certificate Store Types. Descriptions of each are provided below.

- [K8SCert](#K8SCert)

- [K8SCluster](#K8SCluster)

- [K8SJKS](#K8SJKS)

- [K8SNS](#K8SNS)

- [K8SPKCS12](#K8SPKCS12)

- [K8SSecret](#K8SSecret)

- [K8STLSSecr](#K8STLSSecr)


## Compatibility

This integration is compatible with Keyfactor Universal Orchestrator version 12.4 and later.

## Support
The Kubernetes Universal Orchestrator extension is supported by Keyfactor. If you require support for any issues or have feature request, please open a support ticket by either contacting your Keyfactor representative or via the Keyfactor Support Portal at https://support.keyfactor.com.

> If you want to contribute bug fixes or additional enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements & Prerequisites

Before installing the Kubernetes Universal Orchestrator extension, we recommend that you install [kfutil](https://github.com/Keyfactor/kfutil). Kfutil is a command-line tool that simplifies the process of creating store types, installing extensions, and instantiating certificate stores in Keyfactor Command.


### Kubernetes API Access
This orchestrator extension makes use of the Kubernetes API by using a service account
to communicate remotely with certificate stores. The service account must exist and have the appropriate permissions.
The service account token can be provided to the extension in one of two ways:
- As a raw JSON file that contains the service account credentials
- As a base64 encoded string that contains the service account credentials

#### Service Account Setup
To set up a service account user on your Kubernetes cluster to be used by the Kubernetes Orchestrator Extension. For full 
information on the required permissions, see the [service account setup guide](./scripts/kubernetes/README.md).


## Certificate Store Types

To use the Kubernetes Universal Orchestrator extension, you **must** create the Certificate Store Types required for your use-case. This only needs to happen _once_ per Keyfactor Command instance.

The Kubernetes Universal Orchestrator extension implements 7 Certificate Store Types. Depending on your use case, you may elect to use one, or all of these Certificate Store Types.

### K8SCert

<details><summary>Click to expand details</summary>


The `K8SCert` store type is used to manage Kubernetes certificates of type `certificates.k8s.io/v1`. 

**NOTE**: only `inventory` and `discovery` of these resources is supported with this extension. To provision these certs use the 
[k8s-csr-signer](https://github.com/Keyfactor/k8s-csr-signer).




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | 🔲 Unchecked        |
| Remove       | 🔲 Unchecked     |
| Discovery    | ✅ Checked  |
| Reenrollment | 🔲 Unchecked |
| Create       | 🔲 Unchecked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8SCert kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8SCert
   kfutil store-types create K8SCert
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8SCert store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8SCert details</summary>

   Create a store type called `K8SCert` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8SCert | Display name for the store type (may be customized) |
   | Short Name | K8SCert | Short display name for the store type |
   | Capability | K8SCert | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | 🔲 Unchecked |  Indicates that the Store Type supports Management Add |
   | Supports Remove | 🔲 Unchecked |  Indicates that the Store Type supports Management Remove |
   | Supports Discovery | ✅ Checked | Check the box. Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | 🔲 Unchecked |  Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | 🔲 Unchecked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8SCert Basic Tab](docsource/images/K8SCert-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Forbidden | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Forbidden | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8SCert Advanced Tab](docsource/images/K8SCert-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | ✅ Checked |
   | KubeNamespace | KubeNamespace | The K8S namespace to use to manage the K8S secret object. | String | default | 🔲 Unchecked |
   | KubeSecretName | KubeSecretName | The name of the K8S secret object. | String |  | 🔲 Unchecked |
   | KubeSecretType | KubeSecretType | This defaults to and must be `csr` | String | cert | ✅ Checked |

   The Custom Fields tab should look like this:

   ![K8SCert Custom Fields Tab](docsource/images/K8SCert-custom-fields-store-type-dialog.png)


   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### KubeNamespace
   The K8S namespace to use to manage the K8S secret object.

   ![K8SCert Custom Field - KubeNamespace](docsource/images/K8SCert-custom-field-KubeNamespace-dialog.png)
   ![K8SCert Custom Field - KubeNamespace](docsource/images/K8SCert-custom-field-KubeNamespace-validation-options-dialog.png)



   ###### KubeSecretName
   The name of the K8S secret object.

   ![K8SCert Custom Field - KubeSecretName](docsource/images/K8SCert-custom-field-KubeSecretName-dialog.png)
   ![K8SCert Custom Field - KubeSecretName](docsource/images/K8SCert-custom-field-KubeSecretName-validation-options-dialog.png)



   ###### KubeSecretType
   This defaults to and must be `csr`

   ![K8SCert Custom Field - KubeSecretType](docsource/images/K8SCert-custom-field-KubeSecretType-dialog.png)
   ![K8SCert Custom Field - KubeSecretType](docsource/images/K8SCert-custom-field-KubeSecretType-validation-options-dialog.png)





   </details>
</details>

### K8SCluster

<details><summary>Click to expand details</summary>


The `K8SCluster` store type allows for a single store to manage a k8s cluster's secrets or type `Opaque` and `kubernetes.io/tls`.




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | ✅ Checked        |
| Remove       | ✅ Checked     |
| Discovery    | 🔲 Unchecked  |
| Reenrollment | 🔲 Unchecked |
| Create       | ✅ Checked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8SCluster kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8SCluster
   kfutil store-types create K8SCluster
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8SCluster store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8SCluster details</summary>

   Create a store type called `K8SCluster` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8SCluster | Display name for the store type (may be customized) |
   | Short Name | K8SCluster | Short display name for the store type |
   | Capability | K8SCluster | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | ✅ Checked | Check the box. Indicates that the Store Type supports Management Add |
   | Supports Remove | ✅ Checked | Check the box. Indicates that the Store Type supports Management Remove |
   | Supports Discovery | 🔲 Unchecked |  Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | ✅ Checked | Check the box. Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | 🔲 Unchecked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8SCluster Basic Tab](docsource/images/K8SCluster-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Required | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8SCluster Advanced Tab](docsource/images/K8SCluster-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | IncludeCertChain | Include Certificate Chain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. | Bool | true | 🔲 Unchecked |
   | SeparateChain | Separate Chain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. | Bool | false | 🔲 Unchecked |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | 🔲 Unchecked |

   The Custom Fields tab should look like this:

   ![K8SCluster Custom Fields Tab](docsource/images/K8SCluster-custom-fields-store-type-dialog.png)


   ###### Include Certificate Chain
   Will default to `true` if not set. If set to `false` only the leaf cert will be deployed.

   ![K8SCluster Custom Field - IncludeCertChain](docsource/images/K8SCluster-custom-field-IncludeCertChain-dialog.png)
   ![K8SCluster Custom Field - IncludeCertChain](docsource/images/K8SCluster-custom-field-IncludeCertChain-validation-options-dialog.png)



   ###### Separate Chain
   Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets.

   ![K8SCluster Custom Field - SeparateChain](docsource/images/K8SCluster-custom-field-SeparateChain-dialog.png)
   ![K8SCluster Custom Field - SeparateChain](docsource/images/K8SCluster-custom-field-SeparateChain-validation-options-dialog.png)



   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.






   </details>
</details>

### K8SJKS

<details><summary>Click to expand details</summary>


The `K8SJKS` store type is used to manage Kubernetes secrets of type `Opaque`.  These secrets
must have a field that ends in `.jks`. The orchestrator will inventory and manage using a *custom alias* of the following
pattern: `<k8s_secret_field_name>/<keystore_alias>`.  For example, if the secret has a field named `mykeystore.jks` and
the keystore contains a certificate with an alias of `mycert`, the orchestrator will manage the certificate using the
alias `mykeystore.jks/mycert`. *NOTE* *This store type cannot be managed at the `cluster` or `namespace` level as they 
should all require unique credentials.*




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | ✅ Checked        |
| Remove       | ✅ Checked     |
| Discovery    | ✅ Checked  |
| Reenrollment | 🔲 Unchecked |
| Create       | ✅ Checked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8SJKS kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8SJKS
   kfutil store-types create K8SJKS
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8SJKS store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8SJKS details</summary>

   Create a store type called `K8SJKS` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8SJKS | Display name for the store type (may be customized) |
   | Short Name | K8SJKS | Short display name for the store type |
   | Capability | K8SJKS | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | ✅ Checked | Check the box. Indicates that the Store Type supports Management Add |
   | Supports Remove | ✅ Checked | Check the box. Indicates that the Store Type supports Management Remove |
   | Supports Discovery | ✅ Checked | Check the box. Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | ✅ Checked | Check the box. Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | ✅ Checked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8SJKS Basic Tab](docsource/images/K8SJKS-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Required | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8SJKS Advanced Tab](docsource/images/K8SJKS-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | KubeNamespace | KubeNamespace | The K8S namespace to use to manage the K8S secret object. | String | default | 🔲 Unchecked |
   | KubeSecretName | KubeSecretName | The name of the K8S secret object. | String | None | 🔲 Unchecked |
   | KubeSecretType | KubeSecretType | This defaults to and must be `jks` | String | jks | ✅ Checked |
   | CertificateDataFieldName | CertificateDataFieldName | The field name to use when looking for certificate data in the K8S secret. | String | None | 🔲 Unchecked |
   | PasswordFieldName | PasswordFieldName | The field name to use when looking for the JKS keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`. | String | password | 🔲 Unchecked |
   | PasswordIsK8SSecret | PasswordIsK8SSecret | Indicates whether the password to the JKS keystore is stored in a separate K8S secret. | Bool | false | 🔲 Unchecked |
   | IncludeCertChain | Include Certificate Chain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. | Bool | true | 🔲 Unchecked |
   | StorePasswordPath | StorePasswordPath | The path to the K8S secret object to use as the password to the JKS keystore. Example: `<namespace>/<secret_name>` | String | None | 🔲 Unchecked |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | 🔲 Unchecked |

   The Custom Fields tab should look like this:

   ![K8SJKS Custom Fields Tab](docsource/images/K8SJKS-custom-fields-store-type-dialog.png)


   ###### KubeNamespace
   The K8S namespace to use to manage the K8S secret object.

   ![K8SJKS Custom Field - KubeNamespace](docsource/images/K8SJKS-custom-field-KubeNamespace-dialog.png)
   ![K8SJKS Custom Field - KubeNamespace](docsource/images/K8SJKS-custom-field-KubeNamespace-validation-options-dialog.png)



   ###### KubeSecretName
   The name of the K8S secret object.

   ![K8SJKS Custom Field - KubeSecretName](docsource/images/K8SJKS-custom-field-KubeSecretName-dialog.png)
   ![K8SJKS Custom Field - KubeSecretName](docsource/images/K8SJKS-custom-field-KubeSecretName-validation-options-dialog.png)



   ###### KubeSecretType
   This defaults to and must be `jks`

   ![K8SJKS Custom Field - KubeSecretType](docsource/images/K8SJKS-custom-field-KubeSecretType-dialog.png)
   ![K8SJKS Custom Field - KubeSecretType](docsource/images/K8SJKS-custom-field-KubeSecretType-validation-options-dialog.png)



   ###### CertificateDataFieldName
   The field name to use when looking for certificate data in the K8S secret.

   ![K8SJKS Custom Field - CertificateDataFieldName](docsource/images/K8SJKS-custom-field-CertificateDataFieldName-dialog.png)
   ![K8SJKS Custom Field - CertificateDataFieldName](docsource/images/K8SJKS-custom-field-CertificateDataFieldName-validation-options-dialog.png)



   ###### PasswordFieldName
   The field name to use when looking for the JKS keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`.

   ![K8SJKS Custom Field - PasswordFieldName](docsource/images/K8SJKS-custom-field-PasswordFieldName-dialog.png)
   ![K8SJKS Custom Field - PasswordFieldName](docsource/images/K8SJKS-custom-field-PasswordFieldName-validation-options-dialog.png)



   ###### PasswordIsK8SSecret
   Indicates whether the password to the JKS keystore is stored in a separate K8S secret.

   ![K8SJKS Custom Field - PasswordIsK8SSecret](docsource/images/K8SJKS-custom-field-PasswordIsK8SSecret-dialog.png)
   ![K8SJKS Custom Field - PasswordIsK8SSecret](docsource/images/K8SJKS-custom-field-PasswordIsK8SSecret-validation-options-dialog.png)



   ###### Include Certificate Chain
   Will default to `true` if not set. If set to `false` only the leaf cert will be deployed.

   ![K8SJKS Custom Field - IncludeCertChain](docsource/images/K8SJKS-custom-field-IncludeCertChain-dialog.png)
   ![K8SJKS Custom Field - IncludeCertChain](docsource/images/K8SJKS-custom-field-IncludeCertChain-validation-options-dialog.png)



   ###### StorePasswordPath
   The path to the K8S secret object to use as the password to the JKS keystore. Example: `<namespace>/<secret_name>`

   ![K8SJKS Custom Field - StorePasswordPath](docsource/images/K8SJKS-custom-field-StorePasswordPath-dialog.png)
   ![K8SJKS Custom Field - StorePasswordPath](docsource/images/K8SJKS-custom-field-StorePasswordPath-validation-options-dialog.png)



   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.






   </details>
</details>

### K8SNS

<details><summary>Click to expand details</summary>


The `K8SNS` store type is used to manage Kubernetes secrets of type `kubernetes.io/tls` and/or type `Opaque` in a single 
Keyfactor Command certificate store using an alias pattern of




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | ✅ Checked        |
| Remove       | ✅ Checked     |
| Discovery    | ✅ Checked  |
| Reenrollment | 🔲 Unchecked |
| Create       | ✅ Checked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8SNS kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8SNS
   kfutil store-types create K8SNS
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8SNS store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8SNS details</summary>

   Create a store type called `K8SNS` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8SNS | Display name for the store type (may be customized) |
   | Short Name | K8SNS | Short display name for the store type |
   | Capability | K8SNS | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | ✅ Checked | Check the box. Indicates that the Store Type supports Management Add |
   | Supports Remove | ✅ Checked | Check the box. Indicates that the Store Type supports Management Remove |
   | Supports Discovery | ✅ Checked | Check the box. Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | ✅ Checked | Check the box. Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | 🔲 Unchecked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8SNS Basic Tab](docsource/images/K8SNS-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Required | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8SNS Advanced Tab](docsource/images/K8SNS-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | KubeNamespace | Kube Namespace | The K8S namespace to use to manage the K8S secret object. | String | default | 🔲 Unchecked |
   | IncludeCertChain | Include Certificate Chain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. | Bool | true | 🔲 Unchecked |
   | SeparateChain | Separate Chain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. | Bool | false | 🔲 Unchecked |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | 🔲 Unchecked |

   The Custom Fields tab should look like this:

   ![K8SNS Custom Fields Tab](docsource/images/K8SNS-custom-fields-store-type-dialog.png)


   ###### Kube Namespace
   The K8S namespace to use to manage the K8S secret object.

   ![K8SNS Custom Field - KubeNamespace](docsource/images/K8SNS-custom-field-KubeNamespace-dialog.png)
   ![K8SNS Custom Field - KubeNamespace](docsource/images/K8SNS-custom-field-KubeNamespace-validation-options-dialog.png)



   ###### Include Certificate Chain
   Will default to `true` if not set. If set to `false` only the leaf cert will be deployed.

   ![K8SNS Custom Field - IncludeCertChain](docsource/images/K8SNS-custom-field-IncludeCertChain-dialog.png)
   ![K8SNS Custom Field - IncludeCertChain](docsource/images/K8SNS-custom-field-IncludeCertChain-validation-options-dialog.png)



   ###### Separate Chain
   Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets.

   ![K8SNS Custom Field - SeparateChain](docsource/images/K8SNS-custom-field-SeparateChain-dialog.png)
   ![K8SNS Custom Field - SeparateChain](docsource/images/K8SNS-custom-field-SeparateChain-validation-options-dialog.png)



   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.






   </details>
</details>

### K8SPKCS12

<details><summary>Click to expand details</summary>


The `K8SPKCS12` store type is used to manage Kubernetes secrets of type `Opaque`.  These secrets
must have a field that ends in `.pkcs12`. The orchestrator will inventory and manage using a *custom alias* of the following
pattern: `<k8s_secret_field_name>/<keystore_alias>`.  For example, if the secret has a field named `mykeystore.pkcs12` and
the keystore contains a certificate with an alias of `mycert`, the orchestrator will manage the certificate using the
alias `mykeystore.pkcs12/mycert`. *NOTE* *This store type cannot be managed at the `cluster` or `namespace` level as they
should all require unique credentials.*




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | ✅ Checked        |
| Remove       | ✅ Checked     |
| Discovery    | ✅ Checked  |
| Reenrollment | 🔲 Unchecked |
| Create       | ✅ Checked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8SPKCS12 kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8SPKCS12
   kfutil store-types create K8SPKCS12
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8SPKCS12 store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8SPKCS12 details</summary>

   Create a store type called `K8SPKCS12` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8SPKCS12 | Display name for the store type (may be customized) |
   | Short Name | K8SPKCS12 | Short display name for the store type |
   | Capability | K8SPKCS12 | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | ✅ Checked | Check the box. Indicates that the Store Type supports Management Add |
   | Supports Remove | ✅ Checked | Check the box. Indicates that the Store Type supports Management Remove |
   | Supports Discovery | ✅ Checked | Check the box. Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | ✅ Checked | Check the box. Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | ✅ Checked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8SPKCS12 Basic Tab](docsource/images/K8SPKCS12-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Required | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8SPKCS12 Advanced Tab](docsource/images/K8SPKCS12-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | IncludeCertChain | Include Certificate Chain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. | Bool | true | 🔲 Unchecked |
   | CertificateDataFieldName | CertificateDataFieldName |  | String | .p12 | ✅ Checked |
   | PasswordFieldName | Password Field Name | The field name to use when looking for the PKCS12 keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`. | String | password | 🔲 Unchecked |
   | PasswordIsK8SSecret | Password Is K8S Secret | Indicates whether the password to the PKCS12 keystore is stored in a separate K8S secret object. | Bool | false | 🔲 Unchecked |
   | KubeNamespace | Kube Namespace | The K8S namespace to use to manage the K8S secret object. | String | default | 🔲 Unchecked |
   | KubeSecretName | Kube Secret Name | The name of the K8S secret object. | String | None | 🔲 Unchecked |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | 🔲 Unchecked |
   | KubeSecretType | Kube Secret Type | This defaults to and must be `pkcs12` | String | pkcs12 | ✅ Checked |
   | StorePasswordPath | StorePasswordPath | The path to the K8S secret object to use as the password to the PFX/PKCS12 data. Example: `<namespace>/<secret_name>` | String | None | 🔲 Unchecked |

   The Custom Fields tab should look like this:

   ![K8SPKCS12 Custom Fields Tab](docsource/images/K8SPKCS12-custom-fields-store-type-dialog.png)


   ###### Include Certificate Chain
   Will default to `true` if not set. If set to `false` only the leaf cert will be deployed.

   ![K8SPKCS12 Custom Field - IncludeCertChain](docsource/images/K8SPKCS12-custom-field-IncludeCertChain-dialog.png)
   ![K8SPKCS12 Custom Field - IncludeCertChain](docsource/images/K8SPKCS12-custom-field-IncludeCertChain-validation-options-dialog.png)



   ###### CertificateDataFieldName


   ![K8SPKCS12 Custom Field - CertificateDataFieldName](docsource/images/K8SPKCS12-custom-field-CertificateDataFieldName-dialog.png)
   ![K8SPKCS12 Custom Field - CertificateDataFieldName](docsource/images/K8SPKCS12-custom-field-CertificateDataFieldName-validation-options-dialog.png)



   ###### Password Field Name
   The field name to use when looking for the PKCS12 keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`.

   ![K8SPKCS12 Custom Field - PasswordFieldName](docsource/images/K8SPKCS12-custom-field-PasswordFieldName-dialog.png)
   ![K8SPKCS12 Custom Field - PasswordFieldName](docsource/images/K8SPKCS12-custom-field-PasswordFieldName-validation-options-dialog.png)



   ###### Password Is K8S Secret
   Indicates whether the password to the PKCS12 keystore is stored in a separate K8S secret object.

   ![K8SPKCS12 Custom Field - PasswordIsK8SSecret](docsource/images/K8SPKCS12-custom-field-PasswordIsK8SSecret-dialog.png)
   ![K8SPKCS12 Custom Field - PasswordIsK8SSecret](docsource/images/K8SPKCS12-custom-field-PasswordIsK8SSecret-validation-options-dialog.png)



   ###### Kube Namespace
   The K8S namespace to use to manage the K8S secret object.

   ![K8SPKCS12 Custom Field - KubeNamespace](docsource/images/K8SPKCS12-custom-field-KubeNamespace-dialog.png)
   ![K8SPKCS12 Custom Field - KubeNamespace](docsource/images/K8SPKCS12-custom-field-KubeNamespace-validation-options-dialog.png)



   ###### Kube Secret Name
   The name of the K8S secret object.

   ![K8SPKCS12 Custom Field - KubeSecretName](docsource/images/K8SPKCS12-custom-field-KubeSecretName-dialog.png)
   ![K8SPKCS12 Custom Field - KubeSecretName](docsource/images/K8SPKCS12-custom-field-KubeSecretName-validation-options-dialog.png)



   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Kube Secret Type
   This defaults to and must be `pkcs12`

   ![K8SPKCS12 Custom Field - KubeSecretType](docsource/images/K8SPKCS12-custom-field-KubeSecretType-dialog.png)
   ![K8SPKCS12 Custom Field - KubeSecretType](docsource/images/K8SPKCS12-custom-field-KubeSecretType-validation-options-dialog.png)



   ###### StorePasswordPath
   The path to the K8S secret object to use as the password to the PFX/PKCS12 data. Example: `<namespace>/<secret_name>`

   ![K8SPKCS12 Custom Field - StorePasswordPath](docsource/images/K8SPKCS12-custom-field-StorePasswordPath-dialog.png)
   ![K8SPKCS12 Custom Field - StorePasswordPath](docsource/images/K8SPKCS12-custom-field-StorePasswordPath-validation-options-dialog.png)





   </details>
</details>

### K8SSecret

<details><summary>Click to expand details</summary>


The `K8SSecret` store type is used to manage Kubernetes secrets of type `Opaque`.




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | ✅ Checked        |
| Remove       | ✅ Checked     |
| Discovery    | ✅ Checked  |
| Reenrollment | 🔲 Unchecked |
| Create       | ✅ Checked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8SSecret kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8SSecret
   kfutil store-types create K8SSecret
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8SSecret store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8SSecret details</summary>

   Create a store type called `K8SSecret` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8SSecret | Display name for the store type (may be customized) |
   | Short Name | K8SSecret | Short display name for the store type |
   | Capability | K8SSecret | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | ✅ Checked | Check the box. Indicates that the Store Type supports Management Add |
   | Supports Remove | ✅ Checked | Check the box. Indicates that the Store Type supports Management Remove |
   | Supports Discovery | ✅ Checked | Check the box. Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | ✅ Checked | Check the box. Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | 🔲 Unchecked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8SSecret Basic Tab](docsource/images/K8SSecret-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Forbidden | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8SSecret Advanced Tab](docsource/images/K8SSecret-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | KubeNamespace | KubeNamespace | The K8S namespace to use to manage the K8S secret object. | String | None | 🔲 Unchecked |
   | KubeSecretName | KubeSecretName | The name of the K8S secret object. | String | None | 🔲 Unchecked |
   | KubeSecretType | KubeSecretType | This defaults to and must be `secret` | String | secret | ✅ Checked |
   | IncludeCertChain | Include Certificate Chain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. | Bool | true | 🔲 Unchecked |
   | SeparateChain | Separate Chain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. | Bool | false | 🔲 Unchecked |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | 🔲 Unchecked |

   The Custom Fields tab should look like this:

   ![K8SSecret Custom Fields Tab](docsource/images/K8SSecret-custom-fields-store-type-dialog.png)


   ###### KubeNamespace
   The K8S namespace to use to manage the K8S secret object.

   ![K8SSecret Custom Field - KubeNamespace](docsource/images/K8SSecret-custom-field-KubeNamespace-dialog.png)
   ![K8SSecret Custom Field - KubeNamespace](docsource/images/K8SSecret-custom-field-KubeNamespace-validation-options-dialog.png)



   ###### KubeSecretName
   The name of the K8S secret object.

   ![K8SSecret Custom Field - KubeSecretName](docsource/images/K8SSecret-custom-field-KubeSecretName-dialog.png)
   ![K8SSecret Custom Field - KubeSecretName](docsource/images/K8SSecret-custom-field-KubeSecretName-validation-options-dialog.png)



   ###### KubeSecretType
   This defaults to and must be `secret`

   ![K8SSecret Custom Field - KubeSecretType](docsource/images/K8SSecret-custom-field-KubeSecretType-dialog.png)
   ![K8SSecret Custom Field - KubeSecretType](docsource/images/K8SSecret-custom-field-KubeSecretType-validation-options-dialog.png)



   ###### Include Certificate Chain
   Will default to `true` if not set. If set to `false` only the leaf cert will be deployed.

   ![K8SSecret Custom Field - IncludeCertChain](docsource/images/K8SSecret-custom-field-IncludeCertChain-dialog.png)
   ![K8SSecret Custom Field - IncludeCertChain](docsource/images/K8SSecret-custom-field-IncludeCertChain-validation-options-dialog.png)



   ###### Separate Chain
   Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets.

   ![K8SSecret Custom Field - SeparateChain](docsource/images/K8SSecret-custom-field-SeparateChain-dialog.png)
   ![K8SSecret Custom Field - SeparateChain](docsource/images/K8SSecret-custom-field-SeparateChain-validation-options-dialog.png)



   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.






   </details>
</details>

### K8STLSSecr

<details><summary>Click to expand details</summary>


The `K8STLSSecret` store type is used to manage Kubernetes secrets of type `kubernetes.io/tls`




#### Supported Operations

| Operation    | Is Supported                                                                                                           |
|--------------|------------------------------------------------------------------------------------------------------------------------|
| Add          | ✅ Checked        |
| Remove       | ✅ Checked     |
| Discovery    | ✅ Checked  |
| Reenrollment | 🔲 Unchecked |
| Create       | ✅ Checked     |

#### Store Type Creation

##### Using kfutil:
`kfutil` is a custom CLI for the Keyfactor Command API and can be used to create certificate store types.
For more information on [kfutil](https://github.com/Keyfactor/kfutil) check out the [docs](https://github.com/Keyfactor/kfutil?tab=readme-ov-file#quickstart)
   <details><summary>Click to expand K8STLSSecr kfutil details</summary>

   ##### Using online definition from GitHub:
   This will reach out to GitHub and pull the latest store-type definition
   ```shell
   # K8STLSSecr
   kfutil store-types create K8STLSSecr
   ```

   ##### Offline creation using integration-manifest file:
   If required, it is possible to create store types from the [integration-manifest.json](./integration-manifest.json) included in this repo.
   You would first download the [integration-manifest.json](./integration-manifest.json) and then run the following command
   in your offline environment.
   ```shell
   kfutil store-types create --from-file integration-manifest.json
   ```
   </details>


#### Manual Creation
Below are instructions on how to create the K8STLSSecr store type manually in
the Keyfactor Command Portal
   <details><summary>Click to expand manual K8STLSSecr details</summary>

   Create a store type called `K8STLSSecr` with the attributes in the tables below:

   ##### Basic Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Name | K8STLSSecr | Display name for the store type (may be customized) |
   | Short Name | K8STLSSecr | Short display name for the store type |
   | Capability | K8STLSSecr | Store type name orchestrator will register with. Check the box to allow entry of value |
   | Supports Add | ✅ Checked | Check the box. Indicates that the Store Type supports Management Add |
   | Supports Remove | ✅ Checked | Check the box. Indicates that the Store Type supports Management Remove |
   | Supports Discovery | ✅ Checked | Check the box. Indicates that the Store Type supports Discovery |
   | Supports Reenrollment | 🔲 Unchecked |  Indicates that the Store Type supports Reenrollment |
   | Supports Create | ✅ Checked | Check the box. Indicates that the Store Type supports store creation |
   | Needs Server | ✅ Checked | Determines if a target server name is required when creating store |
   | Blueprint Allowed | 🔲 Unchecked | Determines if store type may be included in an Orchestrator blueprint |
   | Uses PowerShell | 🔲 Unchecked | Determines if underlying implementation is PowerShell |
   | Requires Store Password | 🔲 Unchecked | Enables users to optionally specify a store password when defining a Certificate Store. |
   | Supports Entry Password | 🔲 Unchecked | Determines if an individual entry within a store can have a password. |

   The Basic tab should look like this:

   ![K8STLSSecr Basic Tab](docsource/images/K8STLSSecr-basic-store-type-dialog.png)

   ##### Advanced Tab
   | Attribute | Value | Description |
   | --------- | ----- | ----- |
   | Supports Custom Alias | Forbidden | Determines if an individual entry within a store can have a custom Alias. |
   | Private Key Handling | Optional | This determines if Keyfactor can send the private key associated with a certificate to the store. Required because IIS certificates without private keys would be invalid. |
   | PFX Password Style | Default | 'Default' - PFX password is randomly generated, 'Custom' - PFX password may be specified when the enrollment job is created (Requires the Allow Custom Password application setting to be enabled.) |

   The Advanced tab should look like this:

   ![K8STLSSecr Advanced Tab](docsource/images/K8STLSSecr-advanced-store-type-dialog.png)

   > For Keyfactor **Command versions 24.4 and later**, a Certificate Format dropdown is available with PFX and PEM options. Ensure that **PFX** is selected, as this determines the format of new and renewed certificates sent to the Orchestrator during a Management job. Currently, all Keyfactor-supported Orchestrator extensions support only PFX.

   ##### Custom Fields Tab
   Custom fields operate at the certificate store level and are used to control how the orchestrator connects to the remote target server containing the certificate store to be managed. The following custom fields should be added to the store type:

   | Name | Display Name | Description | Type | Default Value/Options | Required |
   | ---- | ------------ | ---- | --------------------- | -------- | ----------- |
   | KubeNamespace | KubeNamespace | The K8S namespace to use to manage the K8S secret object. | String | None | 🔲 Unchecked |
   | KubeSecretName | KubeSecretName | The name of the K8S secret object. | String | None | 🔲 Unchecked |
   | KubeSecretType | KubeSecretType | This defaults to and must be `tls_secret` | String | tls_secret | ✅ Checked |
   | IncludeCertChain | Include Certificate Chain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. | Bool | true | 🔲 Unchecked |
   | SeparateChain | Separate Chain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. | Bool | false | 🔲 Unchecked |
   | ServerUsername | Server Username | This should be no value or `kubeconfig` | Secret | None | 🔲 Unchecked |
   | ServerPassword | Server Password | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json | Secret | None | 🔲 Unchecked |

   The Custom Fields tab should look like this:

   ![K8STLSSecr Custom Fields Tab](docsource/images/K8STLSSecr-custom-fields-store-type-dialog.png)


   ###### KubeNamespace
   The K8S namespace to use to manage the K8S secret object.

   ![K8STLSSecr Custom Field - KubeNamespace](docsource/images/K8STLSSecr-custom-field-KubeNamespace-dialog.png)
   ![K8STLSSecr Custom Field - KubeNamespace](docsource/images/K8STLSSecr-custom-field-KubeNamespace-validation-options-dialog.png)



   ###### KubeSecretName
   The name of the K8S secret object.

   ![K8STLSSecr Custom Field - KubeSecretName](docsource/images/K8STLSSecr-custom-field-KubeSecretName-dialog.png)
   ![K8STLSSecr Custom Field - KubeSecretName](docsource/images/K8STLSSecr-custom-field-KubeSecretName-validation-options-dialog.png)



   ###### KubeSecretType
   This defaults to and must be `tls_secret`

   ![K8STLSSecr Custom Field - KubeSecretType](docsource/images/K8STLSSecr-custom-field-KubeSecretType-dialog.png)
   ![K8STLSSecr Custom Field - KubeSecretType](docsource/images/K8STLSSecr-custom-field-KubeSecretType-validation-options-dialog.png)



   ###### Include Certificate Chain
   Will default to `true` if not set. If set to `false` only the leaf cert will be deployed.

   ![K8STLSSecr Custom Field - IncludeCertChain](docsource/images/K8STLSSecr-custom-field-IncludeCertChain-dialog.png)
   ![K8STLSSecr Custom Field - IncludeCertChain](docsource/images/K8STLSSecr-custom-field-IncludeCertChain-validation-options-dialog.png)



   ###### Separate Chain
   Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets.

   ![K8STLSSecr Custom Field - SeparateChain](docsource/images/K8STLSSecr-custom-field-SeparateChain-dialog.png)
   ![K8STLSSecr Custom Field - SeparateChain](docsource/images/K8STLSSecr-custom-field-SeparateChain-validation-options-dialog.png)



   ###### Server Username
   This should be no value or `kubeconfig`


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.




   ###### Server Password
   The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json


   > [!IMPORTANT]
   > This field is created by the `Needs Server` on the Basic tab, do not create this field manually.






   </details>
</details>


## Installation

1. **Download the latest Kubernetes Universal Orchestrator extension from GitHub.**

    Navigate to the [Kubernetes Universal Orchestrator extension GitHub version page](https://github.com/Keyfactor/k8s-orchestrator/releases/latest). Refer to the compatibility matrix below to determine the asset should be downloaded. Then, click the corresponding asset to download the zip archive.

   | Universal Orchestrator Version | Latest .NET version installed on the Universal Orchestrator server | `rollForward` condition in `Orchestrator.runtimeconfig.json` | `k8s-orchestrator` .NET version to download |
   | --------- | ----------- | ----------- | ----------- |
   | Between `11.0.0` and `11.5.1` (inclusive) | `net8.0` | `LatestMajor` | `net8.0` |
   | `11.6` _and_ newer | `net8.0` | | `net8.0` | 

    Unzip the archive containing extension assemblies to a known location.

    > **Note** If you don't see an asset with a corresponding .NET version, you should always assume that it was compiled for `net8.0`.

2. **Locate the Universal Orchestrator extensions directory.**

    * **Default on Windows** - `C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions`
    * **Default on Linux** - `/opt/keyfactor/orchestrator/extensions`

3. **Create a new directory for the Kubernetes Universal Orchestrator extension inside the extensions directory.**

    Create a new directory called `k8s-orchestrator`.
    > The directory name does not need to match any names used elsewhere; it just has to be unique within the extensions directory.

4. **Copy the contents of the downloaded and unzipped assemblies from __step 2__ to the `k8s-orchestrator` directory.**

5. **Restart the Universal Orchestrator service.**

    Refer to [Starting/Restarting the Universal Orchestrator service](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/StarttheService.htm).


6. **(optional) PAM Integration**

    The Kubernetes Universal Orchestrator extension is compatible with all supported Keyfactor PAM extensions to resolve PAM-eligible secrets. PAM extensions running on Universal Orchestrators enable secure retrieval of secrets from a connected PAM provider.

    To configure a PAM provider, [reference the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam) to select an extension and follow the associated instructions to install it on the Universal Orchestrator (remote).


> The above installation steps can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions).



## Defining Certificate Stores

The Kubernetes Universal Orchestrator extension implements 7 Certificate Store Types, each of which implements different functionality. Refer to the individual instructions below for each Certificate Store Type that you deemed necessary for your use case from the installation section.

<details><summary>K8SCert (K8SCert)</summary>


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8SCert" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SCert` certificates. Specifically, one with the `K8SCert` capability. |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |
   | KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | KubeSecretName | The name of the K8S secret object. |
   | KubeSecretType | This defaults to and must be `csr` |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8SCert certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8SCert --outpath K8SCert.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8SCert" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SCert` certificates. Specifically, one with the `K8SCert` capability. |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |
   | Properties.KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | Properties.KubeSecretName | The name of the K8S secret object. |
   | Properties.KubeSecretType | This defaults to and must be `csr` |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8SCert --file K8SCert.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

<details><summary>K8SCluster (K8SCluster)</summary>

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SCluster` store types, they must
have specific keys in the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns
- `<cluster_name>`

### Alias Patterns
- `<namespace_name>/secrets/<tls|opaque>/<secret_name>`


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8SCluster" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SCluster` certificates. Specifically, one with the `K8SCluster` capability. |
   | IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8SCluster certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8SCluster --outpath K8SCluster.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8SCluster" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SCluster` certificates. Specifically, one with the `K8SCluster` capability. |
   | Properties.IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | Properties.SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8SCluster --file K8SCluster.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

<details><summary>K8SJKS (K8SJKS)</summary>

In order for certificates of type `Opaque` to be inventoried as `K8SJKS` store types, they must have specific keys in
the Kubernetes secret.
- Valid Keys: `*.jks`

### Storepath Patterns
- `<namespace_name>/<secret_name>`
- `<namespace_name>/secrets/<secret_name>`
- `<cluster_name>/<namespace_name>/secrets/<secret_name>`

### Alias Patterns
- `<k8s_secret_field_name>/<keystore_alias>`

Example: `test.jks/load_balancer` where `test.jks` is the field name on the `Opaque` secret and `load_balancer` is
the certificate alias in the `jks` data store.


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8SJKS" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Store Password | Password to use when reading/writing to store |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SJKS` certificates. Specifically, one with the `K8SJKS` capability. |
   | KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | KubeSecretName | The name of the K8S secret object. |
   | KubeSecretType | This defaults to and must be `jks` |
   | CertificateDataFieldName | The field name to use when looking for certificate data in the K8S secret. |
   | PasswordFieldName | The field name to use when looking for the JKS keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`. |
   | PasswordIsK8SSecret | Indicates whether the password to the JKS keystore is stored in a separate K8S secret. |
   | IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | StorePasswordPath | The path to the K8S secret object to use as the password to the JKS keystore. Example: `<namespace>/<secret_name>` |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8SJKS certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8SJKS --outpath K8SJKS.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8SJKS" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Store Password | Password to use when reading/writing to store |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SJKS` certificates. Specifically, one with the `K8SJKS` capability. |
   | Properties.KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | Properties.KubeSecretName | The name of the K8S secret object. |
   | Properties.KubeSecretType | This defaults to and must be `jks` |
   | Properties.CertificateDataFieldName | The field name to use when looking for certificate data in the K8S secret. |
   | Properties.PasswordFieldName | The field name to use when looking for the JKS keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`. |
   | Properties.PasswordIsK8SSecret | Indicates whether the password to the JKS keystore is stored in a separate K8S secret. |
   | Properties.IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | Properties.StorePasswordPath | The path to the K8S secret object to use as the password to the JKS keystore. Example: `<namespace>/<secret_name>` |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8SJKS --file K8SJKS.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |
   | StorePassword | Password to use when reading/writing to store |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

<details><summary>K8SNS (K8SNS)</summary>

In order for certificates of type `Opaque` and/or `kubernetes.io/tls` to be inventoried in `K8SNS` store types, they must 
have specific keys in the Kubernetes secret.
- Required keys: `tls.crt` or `ca.crt`
- Additional keys: `tls.key`

### Storepath Patterns
- `<namespace_name>`
- `<cluster_name>/<namespace_name>`

### Alias Patterns
- `secrets/<tls|opaque>/<secret_name>`


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8SNS" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SNS` certificates. Specifically, one with the `K8SNS` capability. |
   | KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8SNS certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8SNS --outpath K8SNS.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8SNS" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SNS` certificates. Specifically, one with the `K8SNS` capability. |
   | Properties.KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | Properties.IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | Properties.SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8SNS --file K8SNS.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

<details><summary>K8SPKCS12 (K8SPKCS12)</summary>

In order for certificates of type `Opaque` to be inventoried as `K8SPKCS12` store types, they must have specific keys in
the Kubernetes secret.
- Valid Keys: `*.pfx`, `*.pkcs12`, `*.p12`

### Storepath Patterns
- `<namespace_name>/<secret_name>`
- `<namespace_name>/secrets/<secret_name>`
- `<cluster_name>/<namespace_name>/secrets/<secret_name>`

### Alias Patterns
- `<k8s_secret_field_name>/<keystore_alias>`

Example: `test.pkcs12/load_balancer` where `test.pkcs12` is the field name on the `Opaque` secret and `load_balancer` is
the certificate alias in the `pkcs12` data store.


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8SPKCS12" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Store Password | Password to use when reading/writing to store |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SPKCS12` certificates. Specifically, one with the `K8SPKCS12` capability. |
   | IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | CertificateDataFieldName |  |
   | PasswordFieldName | The field name to use when looking for the PKCS12 keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`. |
   | PasswordIsK8SSecret | Indicates whether the password to the PKCS12 keystore is stored in a separate K8S secret object. |
   | KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | KubeSecretName | The name of the K8S secret object. |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |
   | KubeSecretType | This defaults to and must be `pkcs12` |
   | StorePasswordPath | The path to the K8S secret object to use as the password to the PFX/PKCS12 data. Example: `<namespace>/<secret_name>` |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8SPKCS12 certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8SPKCS12 --outpath K8SPKCS12.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8SPKCS12" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Store Password | Password to use when reading/writing to store |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SPKCS12` certificates. Specifically, one with the `K8SPKCS12` capability. |
   | Properties.IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | Properties.CertificateDataFieldName |  |
   | Properties.PasswordFieldName | The field name to use when looking for the PKCS12 keystore password in the K8S secret. This is either the field name to look at on the same secret, or if `PasswordIsK8SSecret` is set to `true`, the field name to look at on the secret specified in `StorePasswordPath`. |
   | Properties.PasswordIsK8SSecret | Indicates whether the password to the PKCS12 keystore is stored in a separate K8S secret object. |
   | Properties.KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | Properties.KubeSecretName | The name of the K8S secret object. |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |
   | Properties.KubeSecretType | This defaults to and must be `pkcs12` |
   | Properties.StorePasswordPath | The path to the K8S secret object to use as the password to the PFX/PKCS12 data. Example: `<namespace>/<secret_name>` |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8SPKCS12 --file K8SPKCS12.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |
   | StorePassword | Password to use when reading/writing to store |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

<details><summary>K8SSecret (K8SSecret)</summary>

In order for certificates of type `Opaque` to be inventoried as `K8SSecret` store types, they must have specific keys in 
the Kubernetes secret.  
- Required keys: `tls.crt` or `ca.crt` 
- Additional keys: `tls.key`


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8SSecret" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SSecret` certificates. Specifically, one with the `K8SSecret` capability. |
   | KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | KubeSecretName | The name of the K8S secret object. |
   | KubeSecretType | This defaults to and must be `secret` |
   | IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8SSecret certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8SSecret --outpath K8SSecret.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8SSecret" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8SSecret` certificates. Specifically, one with the `K8SSecret` capability. |
   | Properties.KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | Properties.KubeSecretName | The name of the K8S secret object. |
   | Properties.KubeSecretType | This defaults to and must be `secret` |
   | Properties.IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | Properties.SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8SSecret --file K8SSecret.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

<details><summary>K8STLSSecr (K8STLSSecr)</summary>

In order for certificates of type `kubernetes.io/tls` to be inventoried, they must have specific keys in
the Kubernetes secret.
- Required keys: `tls.crt` and `tls.key`
- Optional keys: `ca.crt`


### Store Creation

#### Manually with the Command UI

<details><summary>Click to expand details</summary>

1. **Navigate to the _Certificate Stores_ page in Keyfactor Command.**

    Log into Keyfactor Command, toggle the _Locations_ dropdown, and click _Certificate Stores_.

2. **Add a Certificate Store.**

    Click the Add button to add a new Certificate Store. Use the table below to populate the **Attributes** in the **Add** form.

   | Attribute | Description                                             |
   | --------- |---------------------------------------------------------|
   | Category | Select "K8STLSSecr" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8STLSSecr` certificates. Specifically, one with the `K8STLSSecr` capability. |
   | KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | KubeSecretName | The name of the K8S secret object. |
   | KubeSecretType | This defaults to and must be `tls_secret` |
   | IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

</details>



#### Using kfutil CLI

<details><summary>Click to expand details</summary>

1. **Generate a CSV template for the K8STLSSecr certificate store**

    ```shell
    kfutil stores import generate-template --store-type-name K8STLSSecr --outpath K8STLSSecr.csv
    ```
2. **Populate the generated CSV file**

    Open the CSV file, and reference the table below to populate parameters for each **Attribute**.

   | Attribute | Description |
   | --------- | ----------- |
   | Category | Select "K8STLSSecr" or the customized certificate store name from the previous step. |
   | Container | Optional container to associate certificate store with. |
   | Client Machine | This can be anything useful, recommend using the k8s cluster name or identifier. |
   | Store Path |  |
   | Orchestrator | Select an approved orchestrator capable of managing `K8STLSSecr` certificates. Specifically, one with the `K8STLSSecr` capability. |
   | Properties.KubeNamespace | The K8S namespace to use to manage the K8S secret object. |
   | Properties.KubeSecretName | The name of the K8S secret object. |
   | Properties.KubeSecretType | This defaults to and must be `tls_secret` |
   | Properties.IncludeCertChain | Will default to `true` if not set. If set to `false` only the leaf cert will be deployed. |
   | Properties.SeparateChain | Will default to `false` if not set. Set this to `true` if you want to deploy certificate chain to the `ca.crt` field for Opaque and tls secrets. |
   | Properties.ServerUsername | This should be no value or `kubeconfig` |
   | Properties.ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

3. **Import the CSV file to create the certificate stores**

    ```shell
    kfutil stores import csv --store-type-name K8STLSSecr --file K8STLSSecr.csv
    ```

</details>


#### PAM Provider Eligible Fields
<details><summary>Attributes eligible for retrieval by a PAM Provider on the Universal Orchestrator</summary>

If a PAM provider was installed _on the Universal Orchestrator_ in the [Installation](#Installation) section, the following parameters can be configured for retrieval _on the Universal Orchestrator_.

   | Attribute | Description |
   | --------- | ----------- |
   | ServerUsername | This should be no value or `kubeconfig` |
   | ServerPassword | The credentials to use to connect to the K8S cluster API. This needs to be in `kubeconfig` format. Example: https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#example-service-account-json |

Please refer to the **Universal Orchestrator (remote)** usage section ([PAM providers on the Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam)) for your selected PAM provider for instructions on how to load attributes orchestrator-side.
> Any secret can be rendered by a PAM provider _installed on the Keyfactor Command server_. The above parameters are specific to attributes that can be fetched by an installed PAM provider running on the Universal Orchestrator server itself.

</details>


> The content in this section can be supplemented by the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Certificate%20Stores.htm?Highlight=certificate%20store).


</details>

## Discovering Certificate Stores with the Discovery Job
**NOTE:** To use discovery jobs, you must have the store type created in Keyfactor Command and the `needs_server` 
checkbox *MUST* be checked, if you do not select `needs_server` you will not be able to provide credentials to the 
discovery job and it will fail.

The Kubernetes Orchestrator Extension supports certificate discovery jobs.  This allows you to populate the certificate stores with existing certificates.  To run a discovery job, follow these steps:
1. Click on the "Locations > Certificate Stores" menu item.
2. Click the "Discover" tab.
3. Click the "Schedule" button.
4. Configure the job based on storetype. **Note** the "Server Username" field must be set to `kubeconfig` and the "Server Password" field is the `kubeconfig` formatted JSON file containing the service account credentials.  See the "Service Account Setup" section earlier in this README for more information on setting up a service account.
   ![discover_schedule_start.png](./docs/screenshots/discovery/discover_schedule_start.png)
   ![discover_schedule_config.png](./docs/screenshots/discovery/discover_schedule_config.png)
   ![discover_server_username.png](./docs/screenshots/discovery/discover_server_username.png)
   ![discover_server_password.png](./docs/screenshots/discovery/discover_server_password.png)
5. Click the "Save" button and wait for the Orchestrator to run the job. This may take some time depending on the number of certificates in the store and the Orchestrator's check-in schedule.



<details><summary>K8SJKS</summary>


### K8SJKS Discovery Job

For discovery of `K8SJKS` stores toy can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all 
namespaces. *This cannot be left blank.*
- `File name patterns to match` - comma separated list of K8S secret keys to search for PKCS12 or JKS data. Will use 
the following keys by default: `tls.pfx`,`tls.pkcs12`,`pfx`,`pkcs12`,`tls.jks`,`jks`.
</details>


<details><summary>K8SNS</summary>


### K8SNS Discovery Job

For discovery of K8SNS stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all 
namespaces. *This cannot be left blank.*
</details>


<details><summary>K8SPKCS12</summary>


### K8SPKCS12 Discovery Job

For discovery of `K8SPKCS12` stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*
- `File name patterns to match` - comma separated list of K8S secret keys to search for PKCS12 or PKCS12 data. Will use
  the following keys by default: `tls.pfx`,`tls.pkcs12`,`pfx`,`pkcs12`,`tls.pkcs12`,`pkcs12`.
</details>


<details><summary>K8SSecret</summary>


### K8SSecret Discovery Job

For discovery of K8SNS stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*
</details>


<details><summary>K8STLSSecr</summary>


### K8STLSSecr Discovery Job

For discovery of K8SNS stores you can use the following params to filter the certificates that will be discovered:
- `Directories to search` - comma separated list of namespaces to search for certificates OR `all` to search all
  namespaces. *This cannot be left blank.*
</details>





## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Universal Orchestrator extensions](https://github.com/orgs/Keyfactor/repositories?q=orchestrator).