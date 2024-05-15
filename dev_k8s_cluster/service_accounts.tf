resource "kubernetes_service_account" "admin_user" {
  metadata {
    name = "admin-user"
    namespace = data.kubernetes_namespace.dashboard.metadata.0.name
  }
}

resource "kubernetes_secret" "admin_user_token" {
  metadata {
    name      = kubernetes_service_account.admin_user.metadata.0.name
    namespace = kubernetes_service_account.admin_user.metadata.0.namespace
    annotations = {
      "kubernetes.io/service-account.name" = kubernetes_service_account.admin_user.metadata.0.name
    }
  }

  type                           = "kubernetes.io/service-account-token"
  wait_for_service_account_token = true
}

output "admin_user_token" {
  value = kubernetes_secret.admin_user_token.data.token
  sensitive = true
}