# Terraform Modules for Kubernetes Orchestrator Extension

Reusable Terraform modules for managing Keyfactor Command certificate stores backed by Kubernetes resources. Each module corresponds to one of the 7 supported store types in the [Kubernetes Orchestrator Extension](../README.md).

## Modules

| Module | Store Type | Description |
|--------|-----------|-------------|
| [k8s-cert](./modules/k8s-cert/) | `K8SCert` | Certificate Signing Requests (read-only) |
| [k8s-tls](./modules/k8s-tls/) | `K8STLSSecr` | TLS secrets (`kubernetes.io/tls`) |
| [k8s-secret](./modules/k8s-secret/) | `K8SSecret` | Opaque secrets (PEM format) |
| [k8s-cluster](./modules/k8s-cluster/) | `K8SCluster` | Cluster-wide secret management |
| [k8s-ns](./modules/k8s-ns/) | `K8SNS` | Namespace-level secret management |
| [k8s-jks](./modules/k8s-jks/) | `K8SJKS` | Java Keystores in Opaque secrets |
| [k8s-pkcs12](./modules/k8s-pkcs12/) | `K8SPKCS12` | PKCS12/PFX files in Opaque secrets |

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 1.5
- [Keyfactor Terraform Provider](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest) >= 2.1.11
- A running Keyfactor Command instance with the Kubernetes Orchestrator Extension installed
- A registered Universal Orchestrator agent
- A kubeconfig JSON file with service account credentials (see [service account setup](../scripts/kubernetes/README.md))

## Quick Start

```hcl
terraform {
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.1.11"
    }
  }
}

provider "keyfactor" {}

# Look up the orchestrator agent
data "keyfactor_agent" "k8s" {
  agent_identifier = "my-orchestrator"
}

# Create a TLS secret store and deploy a certificate
module "tls_store" {
  source = "./modules/k8s-tls"

  client_machine   = data.keyfactor_agent.k8s.client_machine
  agent_identifier = data.keyfactor_agent.k8s.agent_identifier
  store_path       = "my-cluster/default/my-tls-secret"
  kubeconfig_path  = "./kubeconfig.json"

  certificate_ids = [
    keyfactor_certificate.my_cert.certificate_id,
  ]
}
```

## Examples

| Example | Description |
|---------|-------------|
| [k8s-tls-basic](./examples/k8s-tls-basic/) | Basic TLS secret store with certificate deployment |
| [k8s-jks-buddy-password](./examples/k8s-jks-buddy-password/) | JKS store using a separate K8S secret for the password |
| [complete](./examples/complete/) | All 7 store types configured together |

## Authentication

All modules require a kubeconfig JSON file containing Kubernetes service account credentials. The `kubeconfig_path` variable should point to this file. The file is read at plan/apply time using Terraform's `file()` function.

See the [service account setup guide](../scripts/kubernetes/README.md) for instructions on creating the required credentials.

## Store Type Selection Guide

| Use Case | Recommended Module |
|----------|-------------------|
| Manage a single TLS secret | [k8s-tls](./modules/k8s-tls/) |
| Manage a single Opaque secret with PEM certs | [k8s-secret](./modules/k8s-secret/) |
| Manage a JKS keystore in a secret | [k8s-jks](./modules/k8s-jks/) |
| Manage a PKCS12/PFX file in a secret | [k8s-pkcs12](./modules/k8s-pkcs12/) |
| Inventory all secrets in a namespace | [k8s-ns](./modules/k8s-ns/) |
| Inventory all secrets across all namespaces | [k8s-cluster](./modules/k8s-cluster/) |
| Inventory Kubernetes CSRs | [k8s-cert](./modules/k8s-cert/) |
