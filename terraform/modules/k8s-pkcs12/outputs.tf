output "store_id" {
  description = "The ID of the created certificate store."
  value       = keyfactor_certificate_store.this.id
}

output "store_path" {
  description = "The store path of the certificate store."
  value       = keyfactor_certificate_store.this.store_path
}

output "store_type" {
  description = "The store type (always K8SPKCS12)."
  value       = "K8SPKCS12"
}

output "password_is_k8s_secret" {
  description = "Whether the keystore password is stored in a separate K8S secret."
  value       = local.password_is_k8s_secret
}

output "deployment_ids" {
  description = "Map of certificate ID to deployment resource ID."
  value       = { for k, v in keyfactor_certificate_deployment.this : k => v.id }
}
