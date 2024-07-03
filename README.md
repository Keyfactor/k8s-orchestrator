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

The Kubernetes Universal Orchestrator extension is designed to facilitate the remote management of cryptographic certificates within a Kubernetes cluster. Kubernetes employs certificates for various purposes such as securing communication channels between components (e.g., kube-apiserver, kubelet, etcd), authenticating users and services, and ensuring the integrity of the system.

### Certificate Store Types

This extension provides support for several types of Certificate Stores, each adapted to different Kubernetes resources and use cases:

**K8SCert**: Manages Kubernetes certificates of type `certificates.k8s.io/v1`. These certificates are typically used for Kubernetes admission and webhook servers. For provisioning, refer to the [k8s-csr-signer](https://github.com/Keyfactor/k8s-csr-signer) documentation.

**K8SSecret**: Handles Kubernetes secrets of type `Opaque`. These secrets can store arbitrary data but are primarily used to manage certificate and private key pairs. The orchestrator focuses on fields named `certificates` and `private_keys`.

**K8STLSSecret**: Manages Kubernetes secrets of type `kubernetes.io/tls`. These secrets specifically store SSL/TLS certificates and their corresponding private keys. They must include `tls.crt` and `tls.key` fields.

**K8SCluster**: This type allows managing a cluster’s secrets of types `Opaque` and `kubernetes.io/tls` across all Kubernetes namespaces. It acts as a container that encompasses `K8SSecret` and `K8STLSSecret` stores.

**K8SNS**: Manages all secrets of type `Opaque` and `kubernetes.io/tls` within a specific namespace. Similar to `K8SCluster`, it acts as a container but is limited to a specific namespace.

**K8SJKS**: Works with Kubernetes secrets of type `Opaque` that contain one or more Java Keystore (JKS) files. Each keystore within the secret requires unique credentials and is managed individually.

**K8SPKCS12**: Manages Kubernetes secrets of type `Opaque` that contain PKCS12 files. Like `K8SJKS`, these cannot be managed at cluster or namespace levels due to needing unique credentials.

In summary, the Kubernetes Universal Orchestrator extension offers a versatile approach to managing certificates and keys within a Kubernetes cluster, ensuring secure communication and authentication across components and services.

## Compatibility

This integration is compatible with Keyfactor Universal Orchestrator version 10.1 and later.

## Support
The Kubernetes Universal Orchestrator extension is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 
 
> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Installation
Before installing the Kubernetes Universal Orchestrator extension, it's recommended to install [kfutil](https://github.com/Keyfactor/kfutil). Kfutil is a command-line tool that simplifies the process of creating store types, installing extensions, and instantiating certificate stores in Keyfactor Command.

The Kubernetes Universal Orchestrator extension implements 7 Certificate Store Types. Depending on your use case, you may elect to install one, or all of these Certificate Store Types. An overview for each type is linked below:
* [K8SCert](docs/k8scert.md)
* [K8SCluster](docs/k8scluster.md)
* [K8SJKS](docs/k8sjks.md)
* [K8SNS](docs/k8sns.md)
* [K8SPKCS12](docs/k8spkcs12.md)
* [K8SSecret](docs/k8ssecret.md)
* [K8STLSSecr](docs/k8stlssecr.md)

<details><summary>K8SCert</summary>


1. Follow the [requirements section](docs/k8scert.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8SCert
        kfutil store-types create K8SCert
        ```

    * **Manually**:
        * [K8SCert](docs/k8scert.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8SCert](docs/k8scert.md#certificate-store-configuration)


</details>

<details><summary>K8SCluster</summary>


1. Follow the [requirements section](docs/k8scluster.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8SCluster
        kfutil store-types create K8SCluster
        ```

    * **Manually**:
        * [K8SCluster](docs/k8scluster.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8SCluster](docs/k8scluster.md#certificate-store-configuration)


</details>

<details><summary>K8SJKS</summary>


1. Follow the [requirements section](docs/k8sjks.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8SJKS
        kfutil store-types create K8SJKS
        ```

    * **Manually**:
        * [K8SJKS](docs/k8sjks.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8SJKS](docs/k8sjks.md#certificate-store-configuration)


</details>

<details><summary>K8SNS</summary>


1. Follow the [requirements section](docs/k8sns.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8SNS
        kfutil store-types create K8SNS
        ```

    * **Manually**:
        * [K8SNS](docs/k8sns.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8SNS](docs/k8sns.md#certificate-store-configuration)


</details>

<details><summary>K8SPKCS12</summary>


1. Follow the [requirements section](docs/k8spkcs12.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8SPKCS12
        kfutil store-types create K8SPKCS12
        ```

    * **Manually**:
        * [K8SPKCS12](docs/k8spkcs12.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8SPKCS12](docs/k8spkcs12.md#certificate-store-configuration)


</details>

<details><summary>K8SSecret</summary>


1. Follow the [requirements section](docs/k8ssecret.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8SSecret
        kfutil store-types create K8SSecret
        ```

    * **Manually**:
        * [K8SSecret](docs/k8ssecret.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8SSecret](docs/k8ssecret.md#certificate-store-configuration)


</details>

<details><summary>K8STLSSecr</summary>


1. Follow the [requirements section](docs/k8stlssecr.md#requirements) to configure a Service Account and grant necessary API permissions.

    <details><summary>Requirements</summary>

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



    </details>

2. Create Certificate Store Types for the Kubernetes Orchestrator extension. 

    * **Using kfutil**:

        ```shell
        # K8STLSSecr
        kfutil store-types create K8STLSSecr
        ```

    * **Manually**:
        * [K8STLSSecr](docs/k8stlssecr.md#certificate-store-type-configuration)

3. Install the Kubernetes Universal Orchestrator extension.
    
    * **Using kfutil**: On the server that that hosts the Universal Orchestrator, run the following command:

        ```shell
        # Windows Server
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "C:\Program Files\Keyfactor\Keyfactor Orchestrator\extensions"

        # Linux
        kfutil orchestrator extension -e k8s-orchestrator@latest --out "/opt/keyfactor/orchestrator/extensions"
        ```

    * **Manually**: Follow the [official Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/InstallingAgents/NetCoreOrchestrator/CustomExtensions.htm?Highlight=extensions) to install the latest [Kubernetes Universal Orchestrator extension](https://github.com/Keyfactor/k8s-orchestrator/releases/latest).

4. Create new certificate stores in Keyfactor Command for the Sample Universal Orchestrator extension.

    * [K8STLSSecr](docs/k8stlssecr.md#certificate-store-configuration)


</details>


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Universal Orchestrator extensions](https://github.com/orgs/Keyfactor/repositories?q=orchestrator).