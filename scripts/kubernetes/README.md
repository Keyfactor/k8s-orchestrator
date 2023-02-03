# Keyfactor Kubernetes Orchestrator Service Account Definition

This document describes the Kubernetes Service Account definition for the Keyfactor Kubernetes Orchestrator to fully function. 
Please note that this is only an example and you may need to modify the script and service account definition to suit your environment.

## Pre-requisites
- Kubernetes cluster with RBAC enabled
- Permissions to create a service account, role and role binding
- `kubectl` installed and configured to connect to the Kubernetes cluster
- `jq` installed

## Quickstart
```bash
bash <(curl -s https://raw.githubusercontent.com/Keyfactor/kubernetes-orchestrator/main/scripts/kubernetes/create_service_account.sh)
```


## Create Service Account
The following script will create a service account, role and role binding for the Keyfactor Kubernetes Orchestrator.
```bash

```