terraform {
  required_version = ">= 1.5"
  required_providers {
    keyfactor = {
      source  = "keyfactor-pub/keyfactor"
      version = ">= 2.1.11"
    }
  }
}

locals {
  properties = merge(
    {
      KubeSecretType   = "secret"
      IncludeCertChain = tostring(var.include_cert_chain)
      SeparateChain    = tostring(var.separate_chain)
    },
    var.kube_namespace != null ? { KubeNamespace = var.kube_namespace } : {},
    var.kube_secret_name != null ? { KubeSecretName = var.kube_secret_name } : {},
  )
}

resource "keyfactor_certificate_store" "this" {
  client_machine     = var.client_machine
  store_path         = var.store_path
  agent_identifier   = var.agent_identifier
  store_type         = "K8SSecret"
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_path)
  server_use_ssl     = var.server_use_ssl
  inventory_schedule = var.inventory_schedule
  properties         = local.properties
}

resource "keyfactor_certificate_deployment" "this" {
  for_each             = toset(var.certificate_ids)
  certificate_id       = each.value
  certificate_store_id = keyfactor_certificate_store.this.id
}
