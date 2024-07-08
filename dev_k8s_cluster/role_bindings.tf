resource "kubernetes_cluster_role_binding" "example" {
  metadata {
    name = kubernetes_service_account.admin_user.metadata.0.name
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.admin_user.metadata.0.name
    namespace = kubernetes_service_account.admin_user.metadata.0.namespace
  }
}