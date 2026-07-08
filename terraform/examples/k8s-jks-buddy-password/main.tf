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

# Look up the orchestrator agent
data "keyfactor_agent" "k8s" {
  agent_identifier = var.orchestrator_name
}

# Enroll a certificate
resource "keyfactor_certificate" "app" {
  common_name          = "app.example.com"
  country              = "US"
  state                = "Ohio"
  locality             = "Cleveland"
  organization         = "Example Corp"
  dns_sans             = ["app.example.com"]
  certificate_authority = "DC-CA\\CA1"
  certificate_template  = "WebServer"
}

# JKS store with password stored in a separate K8S secret
# The password secret (e.g., "default/jks-passwords") must already exist
# in the cluster with a field named "keystore-password".
module "jks_store" {
  source = "../../modules/k8s-jks"

  client_machine   = data.keyfactor_agent.k8s.client_machine
  agent_identifier = data.keyfactor_agent.k8s.agent_identifier
  store_path       = "${var.cluster_name}/${var.namespace}/app-keystore"
  kubeconfig_path  = var.kubeconfig_path

  # Buddy password: password is in a separate K8S secret
  store_password_k8s_secret_path = "${var.namespace}/jks-passwords"
  password_field_name            = "keystore-password"

  # Custom field name for the JKS data
  certificate_data_field_name = "app.jks"

  certificate_ids = [
    keyfactor_certificate.app.certificate_id,
  ]
}

output "store_id" {
  value = module.jks_store.store_id
}

output "password_is_k8s_secret" {
  value = module.jks_store.password_is_k8s_secret
}
