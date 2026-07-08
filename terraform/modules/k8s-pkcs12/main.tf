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
  password_is_k8s_secret = var.store_password_k8s_secret_path != null

  properties = merge(
    {
      KubeSecretType           = "pkcs12"
      IncludeCertChain         = tostring(var.include_cert_chain)
      CertificateDataFieldName = var.certificate_data_field_name
      PasswordFieldName        = var.password_field_name
      PasswordIsK8SSecret      = tostring(local.password_is_k8s_secret)
    },
    var.kube_namespace != null ? { KubeNamespace = var.kube_namespace } : {},
    var.kube_secret_name != null ? { KubeSecretName = var.kube_secret_name } : {},
    local.password_is_k8s_secret ? { StorePasswordPath = var.store_password_k8s_secret_path } : {},
  )
}

resource "keyfactor_certificate_store" "this" {
  client_machine     = var.client_machine
  store_path         = var.store_path
  agent_identifier   = var.agent_identifier
  store_type         = "K8SPKCS12"
  store_password     = local.password_is_k8s_secret ? null : var.store_password
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
