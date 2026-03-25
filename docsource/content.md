## Overview

The Kubernetes Orchestrator allows for the remote management of certificate stores defined in a Kubernetes cluster.
The following types of Kubernetes resources are supported: Kubernetes secrets of type `kubernetes.io/tls` or `Opaque`, and
Kubernetes certificates of type `certificates.k8s.io/v1`.

The certificate store types that can be managed in the current version are:
- `K8SCert` - Kubernetes certificates of type `certificates.k8s.io/v1`
- `K8SSecret` - Kubernetes secrets of type `Opaque`
- `K8STLSSecr` - Kubernetes secrets of type `kubernetes.io/tls`
- `K8SCluster` - This allows for a single store to manage a Kubernetes cluster's secrets of type `Opaque` and `kubernetes.io/tls`.
  This can be thought of as a container of `K8SSecret` and `K8STLSSecr` stores across all Kubernetes namespaces.
- `K8SNS` - This allows for a single store to manage a Kubernetes namespace's secrets of type `Opaque` and `kubernetes.io/tls`.
  This can be thought of as a container of `K8SSecret` and `K8STLSSecr` stores for a single Kubernetes namespace.
- `K8SJKS` - Kubernetes secrets of type `Opaque` that contain one or more Java Keystore(s). These cannot be managed at the
  cluster or namespace level as they should all require unique credentials.
- `K8SPKCS12` - Kubernetes secrets of type `Opaque` that contain one or more PKCS12(s). These cannot be managed at the
  cluster or namespace level as they should all require unique credentials.

This orchestrator extension makes use of the Kubernetes API by using a service account
to communicate remotely with certificate stores. The service account must have the correct permissions
in order to perform the desired operations.  For more information on the required permissions, see the
[service account setup guide](#service-account-setup).

## Supported Key Types

The Kubernetes Orchestrator Extension supports certificates with the following key algorithms across all store types:

| Key Type | Sizes/Curves | Supported |
|----------|--------------|-----------|
| RSA | 1024, 2048, 4096, 8192 bit | Yes |
| ECDSA | P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1) | Yes |
| DSA | 1024, 2048 bit | Yes |
| Ed25519 | - | Yes |
| Ed448 | - | Yes |

**Note:** DSA 2048-bit keys use FIPS 186-3/4 compliant generation with SHA-256. Edwards curve keys (Ed25519/Ed448) are fully supported for all store types including JKS and PKCS12.

## Requirements

### Kubernetes API Access

This orchestrator extension makes use of the Kubernetes API by using a service account
to communicate remotely with certificate stores. The service account must exist and have the appropriate permissions.
The service account token can be provided to the extension in one of two ways:
- As a raw JSON file that contains the service account credentials
- As a base64 encoded string that contains the service account credentials

#### Service Account Setup

To set up a service account user on your Kubernetes cluster to be used by the Kubernetes Orchestrator Extension. For full 
information on the required permissions, see the [service account setup guide](./scripts/kubernetes/README.md).

## Terraform Modules

Reusable Terraform modules are available for all store types using the [Keyfactor Terraform Provider](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest). See the [terraform/](./terraform/) directory for modules, examples, and documentation.

## Discovery

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

