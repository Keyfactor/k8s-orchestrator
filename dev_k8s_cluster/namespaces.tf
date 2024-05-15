resource "kubernetes_namespace" "keyfactor_command" {
  metadata {
    name = "keyfactor-command"
  }
}

resource "kubernetes_namespace" "test" {
  metadata {
    name = "test"
  }
}

data "kubernetes_namespace" "dashboard" {
  metadata {
    name = "kubernetes-dashboard"
  }
}
