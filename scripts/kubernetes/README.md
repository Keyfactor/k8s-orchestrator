# Keyfactor Kubernetes Orchestrator Service Account Definition

This document describes the Kubernetes Service Account definition for the Keyfactor Kubernetes Orchestrator Extension to fully function. 
Please note that this is only an example, you may need to modify the script and service account definition to suit your environment.

## Table of Contents
- [Keyfactor Kubernetes Orchestrator Service Account Definition](#keyfactor-kubernetes-orchestrator-service-account-definition)
    * [Pre-requisites](#pre-requisites)
    * [Quickstart](#quickstart)
    * [Manual Steps](#manual-steps)
        + [kubernetes-service-account.yml](#kubernetes-service-accountyml)
        + [create_service_account.sh](#create-service-accountsh)
        + [get_service_account_creds.sh](#get-service-account-credssh)
        
## Pre-requisites
- Kubernetes cluster with RBAC enabled
- Kubernetes permissions to create a service account, read its' token, cluster role and a cluster role binding:
  - `rbac.authorization.k8s.io/v1/ClusterRole`
  - `ServiceAccount`
  - `ConfigMap`
  - `rbac.authorization.k8s.io/v1/ClusterRoleBinding`
  - `secret/$SA_TOKEN`
- `kubectl` installed and configured to connect to the Kubernetes cluster
- `jq` installed

## Quickstart
Assuming you've got `kubectl` configured to connect to your Kubernetes cluster and `jq` installed, you can run the following command to create the service account, role and role binding.

**NOTE**: If you have more than one cluster, you may need to change the index of the array in the script above to match the cluster you want to use. Assumes index is 0
```bash
bash <(curl -s https://raw.githubusercontent.com/Keyfactor/kubernetes-orchestrator/main/scripts/kubernetes/create_service_account.sh)
```
**NOTE**: If you have more than one cluster, you may need to change the index of the array in the script above to match the cluster you want to use. Assumes index is 0

## Manual Steps
If you prefer to manually create and/or modify the service account, role and role binding, you can follow the steps below.

```bash
git clone https://github.com/Keyfactor/kubernetes-orchestrator.git
cd kubernetes-orchestrator/scripts/kubernetes
vim kubernetes-service-account.yml
vim create_service_account.sh
./create_service_account.sh
```

### kubernetes-service-account.yml
This file contains the service account definition. You can modify the service account name and namespace to suit your environment.

### create_service_account.sh
This script will create the service account, role and role binding. You can modify the service account name and namespace to suit your environment.  
**NOTE**: The script, by default will run using the `kubernetes-service-account.yml` from GitHub. If you've modified the file, you can run the script with the `-f` option to use the local file.

### get_service_account_creds.sh
To use an existing service account, you can run `get_service_account_creds.sh`. This script will get the service account token and CA certificate and 
create a `kubeconfig` file. 

**NOTE**: You must have `kubectl` installed and configured to connect to the Kubernetes cluster with permissions to read the service account token and 
CA certificate.

## Example Service Account JSON
[example_kubeconfig.json](example_kubeconfig.json)
```json
{
  "kind": "Config",
  "apiVersion": "v1",
  "preferences": {},
  "clusters": [
    {
      "name": "my-cluster",
      "cluster": {
        "server": "https://my.cluster.domain:443",
        "certificate-authority-data": "<base64 encoded cluster CA certificate>"
      }
    }
  ],
  "users": [
    {
      "name": "keyfactor-orchestrator-sa",
      "user": {
        "token": "<base64 encoded token for k8s service account>"
      }
    }
  ],
  "contexts": [
    {
      "name": "keyfactor-orchestrator-sa-context",
      "context": {
        "cluster": "my-cluster",
        "user": "keyfactor-orchestrator-sa",
        "namespace": "default"
      }
    }
  ],
  "current-context": "keyfactor-orchestrator-sa-context"
}
```