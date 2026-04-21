output "store_id" {
  description = "The ID of the created certificate store."
  value       = keyfactor_certificate_store.this.id
}

output "store_path" {
  description = "The store path of the certificate store."
  value       = keyfactor_certificate_store.this.store_path
}

output "store_type" {
  description = "The store type (always K8SNS)."
  value       = "K8SNS"
}

output "deployment_ids" {
  description = "Map of certificate ID to deployment resource ID."
  value       = { for k, v in keyfactor_certificate_deployment.this : k => v.id }
}
