terraform {
  required_version = ">= 1.5"
  required_providers {
    keyfactor = {
      source = "keyfactor-pub/keyfactor"
      version = ">=2.1.11"
    }
  }
}

provider "keyfactor" {
  
}

