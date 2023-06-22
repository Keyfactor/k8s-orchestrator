# Kubernetes Orchestrator Extension

The Kubernetes Orchestrator allows for the remote management of certificate stores defined in a Kubernetes cluster. The following types of Kubernetes resources are supported:
   - Secrets - Kubernetes secrets of type `kubernetes.io/tls` or `Opaque` 
    - Certificates - Kubernetes certificates of type `certificates.k8s.io/v1`

#### Integration status: Pilot - Ready for use in test environments. Not for use in production.


## About the Keyfactor Universal Orchestrator Extension

This repository contains a Universal Orchestrator Extension which is a plugin to the Keyfactor Universal Orchestrator. Within the Keyfactor Platform, Orchestrators are used to manage “certificate stores” &mdash; collections of certificates and roots of trust that are found within and used by various applications.

The Universal Orchestrator is part of the Keyfactor software distribution and is available via the Keyfactor customer portal. For general instructions on installing Extensions, see the “Keyfactor Command Orchestrator Installation and Configuration Guide” section of the Keyfactor documentation. For configuration details of this specific Extension see below in this readme.

The Universal Orchestrator is the successor to the Windows Orchestrator. This Orchestrator Extension plugin only works with the Universal Orchestrator and does not work with the Windows Orchestrator.




## Support for Kubernetes Orchestrator Extension

Kubernetes Orchestrator Extension is open source and there is **no SLA** for this tool/library/client. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.



---




## Keyfactor Version Supported

The minimum version of the Keyfactor Universal Orchestrator Framework needed to run this version of the extension is 10.1

## Platform Specific Notes

The Keyfactor Universal Orchestrator may be installed on either Windows or Linux based platforms. The certificate operations supported by a capability may vary based what platform the capability is installed on. The table below indicates what capabilities are supported based on which platform the encompassing Universal Orchestrator is running.
| Operation | Win | Linux |
|-----|-----|------|
|Supports Management Add|&check; |&check; |
|Supports Management Remove|&check; |&check; |
|Supports Create Store|&check; |&check; |
|Supports Discovery|&check; |&check; |
|Supports Renrollment|  |  |
|Supports Inventory|&check; |&check; |


## PAM Integration

This orchestrator extension has the ability to connect to a variety of supported PAM providers to allow for the retrieval of various client hosted secrets right from the orchestrator server itself.  This eliminates the need to set up the PAM integration on Keyfactor Command which may be in an environment that the client does not want to have access to their PAM provider.

The secrets that this orchestrator extension supports for use with a PAM Provider are:

| Name           | Description                                                                                                                                                                                                                                                                                                                 |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ServerUsername | Must be set to `kubeconfig` if used. If you do not set it to `kubeconfig` the `ServerPassword` will be ignored.                                                                                                                                                                                                             |
| ServerPassword | Must be set if `ServerUsername` is provided. The service account credentials for the Universal Orchestrator to use. Must be in `kubeconfig` format. For more information review [Kubernetes service account](https://github.com/Keyfactor/kubernetes-orchestrator/blob/main/scripts/kubernetes/README.md) docs and scripts. |
  

It is not necessary to use a PAM Provider for all of the secrets available above. If a PAM Provider should not be used, simply enter in the actual value to be used, as normal.

If a PAM Provider will be used for one of the fields above, start by referencing the [Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam). The GitHub repo for the PAM Provider to be used contains important information such as the format of the `json` needed. What follows is an example but does not reflect the `json` values for all PAM Providers as they have different "instance" and "initialization" parameter names and values.

<details><summary>General PAM Provider Configuration</summary>
<p>



### Example PAM Provider Setup

To use a PAM Provider to resolve a field, in this example the __Server Password__ will be resolved by the `Hashicorp-Vault` provider, first install the PAM Provider extension from the [Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam) on the Universal Orchestrator.

Next, complete configuration of the PAM Provider on the UO by editing the `manifest.json` of the __PAM Provider__ (e.g. located at extensions/Hashicorp-Vault/manifest.json). The "initialization" parameters need to be entered here:

~~~ json
  "Keyfactor:PAMProviders:Hashicorp-Vault:InitializationInfo": {
    "Host": "http://127.0.0.1:8200",
    "Path": "v1/secret/data",
    "Token": "xxxxxx"
  }
~~~

After these values are entered, the Orchestrator needs to be restarted to pick up the configuration. Now the PAM Provider can be used on other Orchestrator Extensions.

### Use the PAM Provider
With the PAM Provider configured as an extenion on the UO, a `json` object can be passed instead of an actual value to resolve the field with a PAM Provider. Consult the [Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam) for the specific format of the `json` object.

To have the __Server Password__ field resolved by the `Hashicorp-Vault` provider, the corresponding `json` object from the `Hashicorp-Vault` extension needs to be copied and filed in with the correct information:

~~~ json
{"Secret":"my-kv-secret","Key":"myServerPassword"}
~~~

This text would be entered in as the value for the __Server Password__, instead of entering in the actual password. The Orchestrator will attempt to use the PAM Provider to retrieve the __Server Password__. If PAM should not be used, just directly enter in the value for the field.
</p>
</details> 




---


## Table of Contents
- [Kubernetes Orchestrator Extension](#kubernetes-orchestrator-extension)
    * [About the Keyfactor Universal Orchestrator Capability](#about-the-keyfactor-universal-orchestrator-capability)
    * [Support for Kubernetes Orchestrator Extension](#support-for-kubernetes-orchestrator-extension)
    * [Keyfactor Version Supported](#keyfactor-version-supported)
    * [Platform Specific Notes](#platform-specific-notes)
    * [PAM Integration](#pam-integration)
        + [Example PAM Provider Setup](#example-pam-provider-setup)
        + [Use the PAM Provider](#use-the-pam-provider)
    * [Table of Contents](#table-of-contents)
    * [Keyfactor Version Supported](#keyfactor-version-supported-1)
    * [Platform Specific Notes](#platform-specific-notes-1)
    * [PAM Integration](#pam-integration-1)
    * [Overview](#overview)
        + [K8SCert](#k8scert)
        + [K8SSecret](#k8ssecret)
        + [K8STLSSecret](#k8stlssecret)
    * [Versioning](#versioning)
    * [Security Considerations](#security-considerations)
        + [Service Account Setup](#service-account-setup)
    * [Kubernetes Orchestrator Extension Installation](#kubernetes-orchestrator-extension-installation)
    * [Certificate Store Types](#certificate-store-types)
        + [Configuration Information](#configuration-information)
            - [Store Path](#note-about-storepath)
            - [Common Values](#common-values)
                * [UI Basic Tab](#ui-basic-tab)
                * [UI Advanced Tab](#ui-advanced-tab)
                * [Custom Fields Tab](#custom-fields-tab)
                * [Kube Secret Types](#kube-secret-types)
                * [Entry Parameters Tab:](#entry-parameters-tab-)
        + [K8SSecret Store Type](#k8ssecret-store-type)
            - [kfutil Create K8SSecret Store Type](#kfutil-create-k8ssecret-store-type)
            - [UI Configuration](#ui-configuration)
                * [UI Basic Tab](#ui-basic-tab-1)
                * [UI Advanced Tab](#ui-advanced-tab-1)
                * [UI Custom Fields Tab](#ui-custom-fields-tab)
                * [UI Entry Parameters Tab:](#ui-entry-parameters-tab-)
        + [K8STLSSecr Store Type](#k8stlssecr-store-type)
            - [kfutil Create K8STLSSecr Store Type](#kfutil-create-k8stlssecr-store-type)
            - [UI Configuration](#ui-configuration-1)
                * [UI Basic Tab](#ui-basic-tab-2)
                * [UI Advanced Tab](#ui-advanced-tab-2)
                * [UI Custom Fields Tab](#ui-custom-fields-tab-1)
                * [UI Entry Parameters Tab:](#ui-entry-parameters-tab--1)
        + [K8SCert Store Type](#k8scert-store-type)
            - [UI Configuration](#ui-configuration-2)
                * [UI Basic Tab](#ui-basic-tab-3)
                * [UI Advanced Tab](#ui-advanced-tab-3)
                * [UI Custom Fields Tab](#ui-custom-fields-tab-2)
                * [UI Entry Parameters Tab:](#ui-entry-parameters-tab--2)
    * [Creating Certificate Stores and Scheduling Discovery Jobs](#creating-certificate-stores-and-scheduling-discovery-jobs)
    * [Certificate Discovery](#certificate-discovery)
    * [Certificate Management](#certificate-management)
    * [Development](#development)
    * [License](#license)

## Keyfactor Version Supported

The minimum version of the Keyfactor Universal Orchestrator Framework needed to run this version of the extension is 10.1

| Keyfactor Version | Universal Orchestrator Framework Version   | Supported    |
|-------------------|--------------------------------------------|--------------|
| 10.1.1            | 10.1                                       | &check;      |
| 10.0.0            | 10.1                                       | &check;      |
| 9.10.1            | Not supported on KF 9.X.X                  | x            |
| 9.5.0             | Not supported on KF 9.X.X                  | x            |

## Platform Specific Notes

The Keyfactor Universal Orchestrator may be installed on either Windows or Linux based platforms.
The certificate operations supported by a capability may vary based what platform the capability is installed on.
See the store type specific sections below for more details on specific cababilities based on Kubernetes resource type.

## PAM Integration

This orchestrator extension has the ability to connect to a variety of supported PAM providers to
allow for the retrieval of various client hosted secrets right from the orchestrator server itself.
This eliminates the need to set up the PAM integration on Keyfactor Command which may be in an
environment that the client does not want to have access to their PAM provider.

The secrets that this orchestrator extension supports for use with a PAM Provider are:

| Name           | Description                                                                                                                                                         |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ServerPassword | This is a raw JSON file that contains service account credentials to interact with the Kubernetes APIs. See the service account setup guide for permission details. |
| ServerUsername | This is a static value that must be set to `kubeconfig`.                                                                                                            |


It is not necessary to implement all of the secrets available to be managed by a PAM provider.  
For each value that you want managed by a PAM provider, simply enter the key value inside your
specific PAM provider that will hold this value into the corresponding field when setting up
the certificate store, discovery job, or API call.

Setting up a PAM provider for use involves adding an additional section to the manifest.json
file for this extension as well as setting up the PAM provider you will be using.  Each of
these steps is specific to the PAM provider you will use and are documented in the specific
GitHub repo for that provider.  For a list of Keyfactor supported PAM providers, please
reference the [Keyfactor Integration Catalog](https://keyfactor.github.io/integrations-catalog/content/pam).

---

<!-- add integration specific information below -->
## Overview
The Kubernetes Orchestrator Extension is an integration that can remotely manage certificate
resources in a Kubernetes cluster.  The certificate store types that can be managed in the
current version are:
- K8SCert - Kubernetes certificates of type `certificates.k8s.io/v1`
- K8SSecret - Kubernetes secrets of type `Opaque`
- K8STLSSecret - Kubernetes secrets of type `kubernetes.io/tls`

This orchestrator extension makes use of the Kubernetes API by using a service account 
to communicate remotely with certificate stores. The service account must have the correct permissions
in order to perform the desired operations.  For more information on the required permissions, see the
[service account setup guide](#service-account-setup).

### K8SCert
The K8SCert store type is used to manage Kubernetes certificates of type `certificates.k8s.io/v1`. 
To provision these certs use the [k8s-csr-signer](https://github.com/Keyfactor/k8s-csr-signer) 
documentation for more information.

### K8SSecret
The K8SSecret store type is used to manage Kubernetes secrets of type `Opaque`.  These secrets can have any 
arbitrary fields, but except for the `tls.crt` and `tls.key` fields, these are reserved for the `kubernetes.io/tls` 
secret type.    
**NOTE**: The orchestrator will only manage the fields named `certificates` and `private_keys` in the
secret.  Any other fields will be ignored.

### K8STLSSecret
The K8STLSSecret store type is used to manage Kubernetes secrets of type `kubernetes.io/tls`.  These secrets
must have the `tls.crt` and `tls.key` fields and may only contain a single key and single certificate.

## Versioning

The version number of a the Kubernetes Orchestrator Extension can be verified by right clicking on the
`Kyefactor.Orchestrators.K8S.dll` file in the `<path>/<to>/<orchstrator install>/Extensions/Kubernetes` installation folder,
selecting Properties, and then clicking on the Details tab.

## Security Considerations
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

## Kubernetes Orchestrator Extension Installation
1. Create the certificate store types you wish to manage.  Please refer to the individual sections
   devoted to each supported store type under "Certificate Store Types" later in this README.
2. Stop the Keyfactor Universal Orchestrator Service for the orchestrator you plan to install this
   extension to run on.
3. In the Keyfactor Orchestrator installation folder (by convention usually
   C:\Program Files\Keyfactor\Keyfactor Orchestrator), find the "Extensions" folder. Underneath that,
   create a new folder named "Kubernetes". You may choose to use a different name if you wish.
4. Download the latest version of the Kubernetes orchestrator extension from
   [GitHub](https://github.com/Keyfactor/kubernetes-orchestrator).  Click on the "Latest" release
   link on the right hand side of the main page and download the first zip file.
5. Copy the contents of the download installation zip file to the folder created in Step 3.
6. (Optional) If you decide to create one or more certificate store types with short names different
   than the suggested values (please see the individual certificate store type sections in "Certificate
   Store Types" later in this README for more information regarding certificate store types), edit the
   manifest.json file in the folder you created in step 3, and modify each "ShortName" in each
   "Certstores.{ShortName}.{Operation}" line with the ShortName you used to create the respective
   certificate store type.  If you created it with the suggested values, this step can be skipped.
7. Modify the config.json file (See the "Configuration File Setup" section later in this README)
8. Start the Keyfactor Universal Orchestrator Service.
9. Create the certificate store types you wish to manage.  Please refer to the individual sections
   devoted to each supported store type under [Certificate Store Types](#certificate-store-types) later in this README.
10. (Optional) Run certificate discovery jobs to populate the certificate stores with existing
   certificates.  See the [Certificate Store Discovery](#certificate-store-discovery) section later in this README for more
   information.

## Certificate Store Types

When setting up the certificate store types you wish the Kubernetes Orchestrator Extension to
manage, there are some common settings that will be the same for all supported types.
To create a new Certificate Store Type in Keyfactor Command, first click on settings
`(the gear icon on the top right) => Certificate Store Types => Add`.  Alternatively,
there are cURL scripts for all of the currently implemented certificate store types
in the Certificate Store Type cURL Scripts folder in this repo if you wish to automate
the creation of the desired store types.

### Configuration Information
Below is a table of the common values that should be used for all certificate store types.

#### Note about StorePath
A Keyfactor Command certificate store `StorePath` for the K8S orchestrator extension can follow the following formats:

| Pattern                                       | Description                                                                                                                                    |
|-----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `secretName`                                  | The name of the secret to use. This assumes `KubeNamespace` is defined or `default` and will be the `secret` or `cert` name on k8s.            |
| `namespace/secretName`                        | If `KubeNamespace` or `KubeSecretName` are not set, then the path will be split by `/` and the values will be parsed according to the pattern. |
| `clusterName/namespace/secretName`            | Same as above, clusterName is purely informational                                                                                             |
| `clusterName/namespace/secretType/secretName` | Considered a `full` path, this is what discovery will return as `StorePath`                                                                    |

#### Common Values
##### UI Basic Tab
| Field Name              | Required | Description                                                                                                                                                        | Value                  |
|-------------------------|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------|
| Name                    | &check;  | The display name you wish to use for the new Certificate Store Type.                                                                                               | Depends on store type. |
| ShortName               | &check;  | The short name you wish to use for the new Certificate Store Type.                                                                                                 | Depends on store type. |
| Custom Capability       | &check;  | Whether or not the certificate store type supports custom capabilities.                                                                                            | Checked [x]            |
| Supported Job Types     | &check;  | The job types supported by the certificate store type.                                                                                                             | Depends on store type. |
| Needs Server            | &check;  | Must be set to true or checked. NOTE: If using this `ServerUsername` must be equal to `kubeconfig` and `ServerPassword` will be the kubeconfig file in JSON format | Checked [x]            |
| Blueprint Allowed       |          | Checked if you wish to make use of blueprinting.  Please refer to the Keyfactor Command Reference Guide for more details on this feature.                          | Unchecked [ ]          |
| Uses PowerShell         |          | Whether or not the certificate store type uses PowerShell.                                                                                                         | Unchecked [ ]          |
| Requires Store Password |          | Whether or not the certificate store type requires a password.                                                                                                     | Unchecked [ ]          |
| Supports Entry Password |          | Whether or not the certificate store type supports entry passwords.                                                                                                | Unchecked [ ]          |

##### UI Advanced Tab
| Field Name            | Required | Description                                                                                                                                | Value                  |
|-----------------------|----------|--------------------------------------------------------------------------------------------------------------------------------------------|------------------------|
| Store Path Type       |          | The type of path the certificate store type uses.                                                                                          | Freeform               |
| Supports Custom Alias |          | Whether or not the certificate store type supports custom aliases.                                                                         | Depends on store type. |
| Private Key Handling  |          | Whether or not the certificate store type supports private key handling.                                                                   | Depends on store type. |
| PFX Password Style    |          | The password style used by the certificate store type.                                                                                     | Default                |

##### Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value | Description                                                                                                 |
|----------------|----------------------|--------|----------|---------------|-------------------------------------------------------------------------------------------------------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`     | The Kubernetes namespace the store will reside. This will override the value parsed from `storepath`.       |
| KubeSecretName | Kube Secret Name     | String |          | none          | This field overrides `storepath` value. The Kubernetes secret or certificate resource name.                 |
| KubeSecretType | Kube Secret Type     | String | &check;  | none          | Must be one of the following `secret`, `secret_tls` or `cert`. See [kube-secret-types](#kube-secret-types). |

##### Kube Secret Types
- `secret` - A generic secret of type `Opaque`. Must contain a key of one of the following values: [ `cert`, `certficate`, `certs`,`certificates` ] to be inventoried.
- `tls_secret` - A secret of type `kubernetes.io/tls`. Must contain the following keys: [ `tls.crt`, `tls.key` ] to be inventoried.
- `cert` - A certificate `certificates.k8s.io/v1` resource. Must contain the following keys: [ `csr`, `cert` ] to be inventoried.

##### Entry Parameters Tab:
- See specific certificate store type instructions below

### K8SSecret Store Type

#### kfutil Create K8SSecret Store Type

The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.
kfuti
```bash
kfutil login
kfutil store-types create --name K8SSecret
```

#### UI Configuration

##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | `K8SSecret`                               |
| ShortName               | &check;  | `K8SSecret`                               |
| Custom Capability       | &check;  | Checked [x] + `K8SSecret`                 |
| Supported Job Types     | &check;  | Inventory, Add, Remove, Create, Discovery |
| Needs Server            | &check;  | Checked [x]                               |
| Blueprint Allowed       |          | Unchecked [ ]                             |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                             |
| Supports Entry Password |          | Unchecked [ ]                             |

**NOTE:** If using PAM, `server_username` must be equal to `kubeconfig` and `server_password` will be the kubeconfig file in JSON format.

![k8ssecret_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8ssecret_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value     |
|-----------------------|----------|-----------|
| Store Path Type       |          | Freeform  |
| Supports Custom Alias |          | Forbidden |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8ssecret_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8ssecret_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`     |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `secret`      |

![k8ssecret_custom_fields.png](docs%2Fscreenshots%2Fstore_types%2Fk8ssecret_custom_fields.png)

##### UI Entry Parameters Tab:
Empty

### K8STLSSecr Store Type

#### kfutil Create K8STLSSecr Store Type

The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```bash
kfutil login
kfutil store-types create --name K8STLSSecr
```

#### UI Configuration

##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | `K8STLSSecr`                              |
| ShortName               | &check;  | `K8STLSSecr`                              |
| Custom Capability       | &check;  | Checked [x] + `K8STLSSecr`                |
| Supported Job Types     | &check;  | Inventory, Add, Remove, Create, Discovery |
| Needs Server            | &check;  | Checked [x]                               |
| Blueprint Allowed       |          | Unchecked [ ]                             |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                             |
| Supports Entry Password |          | Unchecked [ ]                             |

![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8sstlssecr_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value     |
|-----------------------|----------|-----------|
| Store Path Type       |          | Freeform  |
| Supports Custom Alias |          | Forbidden |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8sstlssecr_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`     |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`  |

![k8sstlssecr_custom_fields.png](docs%2Fscreenshots%2Fstore_types%2Fk8sstlssecr_custom_fields.png)

##### UI Entry Parameters Tab:
Empty

### K8SCert Store Type

The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```bash
kfutil login
kfutil store-types create --name K8SCert
```

#### UI Configuration

##### UI Basic Tab
| Field Name              | Required | Value                    |
|-------------------------|----------|--------------------------|
| Name                    | &check;  | `K8SCert`                |
| ShortName               | &check;  | `K8SCert`                |
| Custom Capability       | &check;  | Checked [x] + `K8SCert`  |
| Supported Job Types     | &check;  | Inventory, Discovery     |
| Needs Server            | &check;  | Checked [x]              |
| Blueprint Allowed       |          | Unchecked [ ]            |
| Uses PowerShell         |          | Unchecked [ ]            |
| Requires Store Password |          | Unchecked [ ]            |
| Supports Entry Password |          | Unchecked [ ]            |

![k8scert_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8scert_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value      |
|-----------------------|----------|------------|
| Store Path Type       |          | Freeform   |
| Supports Custom Alias |          | Forbidden  |
| Private Key Handling  |          | Forbidden  |
| PFX Password Style    |          | Default    |

![k8scert_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8scert_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`     |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `cert`        |

![k8scert_custom_fields.png](docs%2Fscreenshots%2Fstore_types%2Fk8scert_custom_fields.png)

##### UI Entry Parameters Tab:
Empty

## Creating Certificate Stores and Scheduling Discovery Jobs

Please refer to the Keyfactor Command Reference Guide for information on creating
certificate stores and scheduling Discovery jobs in Keyfactor Command.

## Certificate Discovery
**NOTE:** To use disovery jobs, you must have the story type created in Keyfactor Command and the `needs_server` checkbox MUST be checked.
Otherwise you will not be able to provide credentials to the discovery job.

The Kubernetes Orchestrator Extension supports certificate discovery jobs.  This allows you to populate the certificate stores with existing certificates.  To run a discovery job, follow these steps:
1. Click on the "Locations > Certificate Stores" menu item.
2. Click the "Discover" tab.
3. Click the "Schedule" button.
4. Configure the job based on storetype. **Note** the "Server Username" field must be set to `kubeconfig` and the "Server Password" field is the `kubeconfig` formatted JSON file containing the service account credentials.  See the "Service Account Setup" section earlier in this README for more information on setting up a service account.
   ![discover_schedule_start.png](docs%2Fscreenshots%2Fdiscovery%2Fdiscover_schedule_start.png)
   ![discover_schedule_config.png](docs%2Fscreenshots%2Fdiscovery%2Fdiscover_schedule_config.png)
   ![discover_server_username.png](docs%2Fscreenshots%2Fdiscovery%2Fdiscover_server_username.png)
   ![discover_server_password.png](docs%2Fscreenshots%2Fdiscovery%2Fdiscover_server_password.png)
5. Click the "Save" button and wait for the Orchestrator to run the job. This may take some time depending on the number of certificates in the store and the Orchestrator's check-in schedule.

## Certificate Inventory
In order for certificates to be inventoried by the Keyfactor k8s-orchestrator, they must have specific keys and values in the Kubernetes Secret.  The following table shows the required keys and values for each type of certificate store.

| Store Type | Valid Secret Keys                                                                             |
|------------|-----------------------------------------------------------------------------------------------|
| K8STLSSecr | `tls.crt`,`tls.key`                                                                           |
| K8SSecret  | `tls.crt`,`tls.crts`, `cert`, `certs`, `certificate`, `certificates`, `crt`, `crts`, `ca.crt` |
| K8SCert    | `cert`, `csr`                                                                                 |

## Certificate Management
Management add/remove/create operations will attempt to write back to the Kubernetes Secret. 
The following table shows the keys that the orchestrator will write back to the Kubernetes Secret for 
each type of certificate store.

| Store Type | Managed Secret Keys            |
|------------|--------------------------------|
| K8STLSSecr | `tls.crt`,`tls.key`            |
| K8SSecret  | `certificates`, `private_keys` |
| K8SCert    | Management not supported.      |


## Development

[See the development guide](Development.md)

## License
[Apache](https://apache.org/licenses/LICENSE-2.0)


