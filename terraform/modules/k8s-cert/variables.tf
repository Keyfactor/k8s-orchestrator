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
  description = "The store path for the certificate store. For K8SCert this is typically the cluster name or identifier."
  type        = string
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file containing service account credentials in JSON format."
  type        = string
}

# ------------------------------------------------------------------------------
# OPTIONAL VARIABLES
# ------------------------------------------------------------------------------

variable "kube_secret_name" {
  description = "The name of a specific CSR to inventory. Leave empty or set to '*' to inventory ALL issued CSRs in the cluster."
  type        = string
  default     = ""
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
