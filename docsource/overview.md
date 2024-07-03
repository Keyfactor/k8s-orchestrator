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

