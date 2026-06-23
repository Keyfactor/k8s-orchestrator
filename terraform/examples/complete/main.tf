terraform {
  required_version = ">= 1.5"
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.1.11"
    }
  }
}

provider "keyfactor" {}

# ------------------------------------------------------------------------------
# VARIABLES
# ------------------------------------------------------------------------------

variable "orchestrator_name" {
  description = "The client machine name of the Universal Orchestrator."
  type        = string
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig JSON file."
  type        = string
}

variable "cluster_name" {
  description = "The Kubernetes cluster name."
  type        = string
  default     = "my-cluster"
}

variable "namespace" {
  description = "The Kubernetes namespace."
  type        = string
  default     = "default"
}

variable "jks_password" {
  description = "Password for the JKS keystore."
  type        = string
  sensitive   = true
}

variable "pkcs12_password" {
  description = "Password for the PKCS12 keystore."
  type        = string
  sensitive   = true
}

variable "certificate_authority" {
  description = "The certificate authority to use for enrollment."
  type        = string
  default     = "DC-CA\\CA1"
}

variable "certificate_template" {
  description = "The certificate template to use for enrollment."
  type        = string
  default     = "WebServer"
}

# ------------------------------------------------------------------------------
# ORCHESTRATOR
# ------------------------------------------------------------------------------

data "keyfactor_agent" "k8s" {
  agent_identifier = var.orchestrator_name
}

locals {
  client_machine   = data.keyfactor_agent.k8s.client_machine
  agent_identifier = data.keyfactor_agent.k8s.agent_identifier
}

# ------------------------------------------------------------------------------
# CERTIFICATES
# ------------------------------------------------------------------------------

resource "keyfactor_certificate" "web" {
  common_name           = "web.example.com"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Example Corp"
  dns_sans              = ["web.example.com"]
  certificate_authority = var.certificate_authority
  certificate_template  = var.certificate_template
}

resource "keyfactor_certificate" "api" {
  common_name           = "api.example.com"
  country               = "US"
  state                 = "Ohio"
  locality              = "Cleveland"
  organization          = "Example Corp"
  dns_sans              = ["api.example.com"]
  certificate_authority = var.certificate_authority
  certificate_template  = var.certificate_template
}

# ------------------------------------------------------------------------------
# K8SCert - Certificate Signing Requests (read-only inventory)
# ------------------------------------------------------------------------------

module "cert_store" {
  source = "../../modules/k8s-cert"

  client_machine   = local.client_machine
  agent_identifier = local.agent_identifier
  store_path       = var.cluster_name
  kubeconfig_path  = var.kubeconfig_path
}

# ------------------------------------------------------------------------------
# K8STLSSecr - TLS Secret
# ------------------------------------------------------------------------------

module "tls_store" {
  source = "../../modules/k8s-tls"

  client_machine   = local.client_machine
  agent_identifier = local.agent_identifier
  store_path       = "${var.cluster_name}/${var.namespace}/web-tls"
  kubeconfig_path  = var.kubeconfig_path

  certificate_ids = [
    keyfactor_certificate.web.certificate_id,
  ]
}

# ------------------------------------------------------------------------------
# K8SSecret - Opaque Secret
# ------------------------------------------------------------------------------

module "secret_store" {
  source = "../../modules/k8s-secret"

  client_machine   = local.client_machine
  agent_identifier = local.agent_identifier
  store_path       = "${var.cluster_name}/${var.namespace}/api-certs"
  kubeconfig_path  = var.kubeconfig_path
  separate_chain   = true

  certificate_ids = [
    keyfactor_certificate.api.certificate_id,
  ]
}

# ------------------------------------------------------------------------------
# K8SCluster - Cluster-wide inventory
# ------------------------------------------------------------------------------

module "cluster_store" {
  source = "../../modules/k8s-cluster"

  client_machine   = local.client_machine
  agent_identifier = local.agent_identifier
  store_path       = var.cluster_name
  kubeconfig_path  = var.kubeconfig_path
}

# ------------------------------------------------------------------------------
# K8SNS - Namespace-level inventory
# ------------------------------------------------------------------------------

module "ns_store" {
  source = "../../modules/k8s-ns"

  client_machine   = local.client_machine
  agent_identifier = local.agent_identifier
  store_path       = "${var.cluster_name}/namespace/${var.namespace}"
  kubeconfig_path  = var.kubeconfig_path
  kube_namespace   = var.namespace
}

# ------------------------------------------------------------------------------
# K8SJKS - Java Keystore
# ------------------------------------------------------------------------------

module "jks_store" {
  source = "../../modules/k8s-jks"

  client_machine              = local.client_machine
  agent_identifier            = local.agent_identifier
  store_path                  = "${var.cluster_name}/${var.namespace}/app-keystore"
  kubeconfig_path             = var.kubeconfig_path
  store_password              = var.jks_password
  certificate_data_field_name = "app.jks"

  certificate_ids = [
    keyfactor_certificate.web.certificate_id,
  ]
}

# ------------------------------------------------------------------------------
# K8SPKCS12 - PKCS12 Keystore
# ------------------------------------------------------------------------------

module "pkcs12_store" {
  source = "../../modules/k8s-pkcs12"

  client_machine              = local.client_machine
  agent_identifier            = local.agent_identifier
  store_path                  = "${var.cluster_name}/${var.namespace}/app-pfx"
  kubeconfig_path             = var.kubeconfig_path
  store_password              = var.pkcs12_password
  certificate_data_field_name = "app.pfx"

  certificate_ids = [
    keyfactor_certificate.api.certificate_id,
  ]
}

# ------------------------------------------------------------------------------
# OUTPUTS
# ------------------------------------------------------------------------------

output "store_ids" {
  description = "Map of store type to store ID."
  value = {
    K8SCert    = module.cert_store.store_id
    K8STLSSecr = module.tls_store.store_id
    K8SSecret  = module.secret_store.store_id
    K8SCluster = module.cluster_store.store_id
    K8SNS      = module.ns_store.store_id
    K8SJKS     = module.jks_store.store_id
    K8SPKCS12  = module.pkcs12_store.store_id
  }
}
