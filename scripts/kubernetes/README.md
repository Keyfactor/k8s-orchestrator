# Keyfactor Kubernetes Orchestrator Service Account Definition

This document describes the Kubernetes Service Account definition for the Keyfactor Kubernetes Orchestrator Extension to fully function. 
Please note that this is only an example and you may need to modify the script and service account definition to suit your environment.

## Table of Contents
- [Keyfactor Kubernetes Orchestrator Service Account Definition](#keyfactor-kubernetes-orchestrator-service-account-definition)
    * [Pre-requisites](#pre-requisites)
    * [Quickstart](#quickstart)
    * [Manual Steps](#manual-steps)
        + [kubernetes-service-account.yml](#kubernetes-service-accountyml)
        + [create_service_account.sh](#create-service-accountsh)
        
## Pre-requisites
- Kubernetes cluster with RBAC enabled
- Permissions to create a service account, role and role binding
- `kubectl` installed and configured to connect to the Kubernetes cluster
- `jq` installed

## Quickstart
Assuming you've got `kubectl` configured to connect to your Kubernetes cluster and `jq` installed, you can run the following command to create the service account, role and role binding.
```bash
bash <(curl -s https://raw.githubusercontent.com/Keyfactor/kubernetes-orchestrator/main/scripts/kubernetes/create_service_account.sh)
```

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