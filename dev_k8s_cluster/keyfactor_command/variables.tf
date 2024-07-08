variable "kfc_ca_domain" {
  type        = string
  description = "The default CA domain to use for the certificate"
  default = "Keyfactor"
}

variable "kfc_ca_name" {
    type        = string
    description = "The name of the certificate authority to use for the Keyfactor Command certificate enrollments."
    default = "CommandCA"
}

variable "client_machine_name" {
  type        = string
  description = "Name of the client machine name of the Keyfactor Command Universal Orchestrator to use."
}

variable "kubeconfig_file" {
  type        = string
  description = "Path to the kubeconfig file"
  default = "~/.kube/config"
}

variable "kube_namespace" {
    type        = string
    description = "Kubernetes namespace to store the certificate in"
    default = "default"
}

variable "webserver_template" {
  type        = string
  description = "The webserver template to use in certificate generation"
  default     = "2YearTestWebServer"
}

variable "default_cert_ca" {
  type        = string
  description = "The default certificate authority to use in certificate generation"
  default     = "CommandCA1"
}

variable "default_ca_domain" {
  type        = string
  description = "The default certificate authority domain to use in certificate generation"
  default     = "DC-CA.Command.local"
}

variable "kube_cluster_name" {
  type        = string
  description = "The name of the Kubernetes cluster to use"
  default     = "dev-cluster"
}

variable "kube_tlssecr_name" {
  type        = string
  description = "The name of the Kubernetes TLS secret for the Keyfactor Command `k8s-orchestrator` extension to manage"
  default = "kfc-k8stlssecr-deployment"
}