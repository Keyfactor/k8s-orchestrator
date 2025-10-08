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

## Discovery

**NOTE:** To use discovery jobs, you must have the story type created in Keyfactor Command and the `needs_server` 
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

