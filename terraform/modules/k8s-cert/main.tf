terraform {
  required_version = ">= 1.5"
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.1.11"
    }
  }
}

resource "keyfactor_certificate_store" "this" {
  client_machine     = var.client_machine
  store_path         = var.store_path
  agent_identifier   = var.agent_identifier
  store_type         = "K8SCert"
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_path)
  server_use_ssl     = var.server_use_ssl
  inventory_schedule = var.inventory_schedule

  properties = {
    KubeSecretName = var.kube_secret_name
  }
}
