terraform {
  required_version = ">= 1.5"
  required_providers {
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = ">=2.30"
    }
  }
}

provider "kubernetes" {
  config_path    = "~/.kube/config"
  config_context = "docker-desktop"
}

