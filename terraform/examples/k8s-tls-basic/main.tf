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
  description = "The Kubernetes namespace for the TLS secret."
  type        = string
  default     = "default"
}

# Look up the orchestrator agent
data "keyfactor_agent" "k8s" {
  agent_identifier = var.orchestrator_name
}

# Enroll a certificate
resource "keyfactor_certificate" "web" {
  common_name          = "web.example.com"
  country              = "US"
  state                = "Ohio"
  locality             = "Cleveland"
  organization         = "Example Corp"
  dns_sans             = ["web.example.com", "www.example.com"]
  certificate_authority = "DC-CA\\CA1"
  certificate_template  = "WebServer"
}

# Create a TLS secret store and deploy the certificate
module "tls_store" {
  source = "../../modules/k8s-tls"

  client_machine   = data.keyfactor_agent.k8s.client_machine
  agent_identifier = data.keyfactor_agent.k8s.agent_identifier
  store_path       = "${var.cluster_name}/${var.namespace}/web-tls"
  kubeconfig_path  = var.kubeconfig_path

  certificate_ids = [
    keyfactor_certificate.web.certificate_id,
  ]
}

output "store_id" {
  value = module.tls_store.store_id
}
