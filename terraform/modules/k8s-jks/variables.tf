# ------------------------------------------------------------------------------
# REQUIRED VARIABLES
# ------------------------------------------------------------------------------

variable "client_machine" {
  description = "The client machine name of the Keyfactor Command Universal Orchestrator."
  type        = string
}

variable "agent_identifier" {
  description = "The orchestrator agent GUID or client machine name."
  type        = string
}

variable "store_path" {
  description = "The store path for the certificate store. Format: '<cluster>/<namespace>/<secret-name>'."
  type        = string
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file containing service account credentials in JSON format."
  type        = string
}

# ------------------------------------------------------------------------------
# STORE PASSWORD
#
# JKS keystores require a password. Provide EITHER:
#   - store_password: the password directly (stored as Keyfactor store password)
#   - store_password_k8s_secret_path + password_field_name: reference to a K8S
#     secret containing the password
# ------------------------------------------------------------------------------

variable "store_password" {
  description = "The password for the JKS keystore. Required unless store_password_k8s_secret_path is set."
  type        = string
  default     = null
  sensitive   = true
}

variable "store_password_k8s_secret_path" {
  description = "Path to a Kubernetes secret containing the keystore password. Format: '<namespace>/<secret-name>'. When set, PasswordIsK8SSecret is automatically enabled."
  type        = string
  default     = null
}

variable "password_field_name" {
  description = "The field name in the K8S secret that contains the keystore password. Used both for inline passwords (same secret) and separate password secrets."
  type        = string
  default     = "password"
}

# ------------------------------------------------------------------------------
# OPTIONAL VARIABLES
# ------------------------------------------------------------------------------

variable "kube_namespace" {
  description = "The Kubernetes namespace containing the secret. Overrides the namespace parsed from store_path."
  type        = string
  default     = null
}

variable "kube_secret_name" {
  description = "The name of the Kubernetes secret containing the JKS data. Overrides the secret name parsed from store_path."
  type        = string
  default     = null
}

variable "certificate_data_field_name" {
  description = "The field name in the K8S secret that contains the JKS keystore data."
  type        = string
  default     = null
}

variable "include_cert_chain" {
  description = "Whether to include the full certificate chain when deploying. If false, only the leaf certificate is deployed."
  type        = bool
  default     = true
}

variable "server_use_ssl" {
  description = "Whether to use SSL when connecting to the Kubernetes API server."
  type        = bool
  default     = true
}

variable "inventory_schedule" {
  description = "How often to run inventory jobs. Examples: '1d' (daily), '12h' (every 12 hours), '30m' (every 30 minutes)."
  type        = string
  default     = "1d"
}

variable "certificate_ids" {
  description = "List of Keyfactor Command certificate IDs to deploy to this store."
  type        = list(string)
  default     = []
}
