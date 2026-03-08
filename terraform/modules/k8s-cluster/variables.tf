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
  description = "The store path for the certificate store. For K8SCluster this represents the entire cluster."
  type        = string
}

variable "kubeconfig_path" {
  description = "Path to the kubeconfig file containing service account credentials in JSON format."
  type        = string
}

# ------------------------------------------------------------------------------
# OPTIONAL VARIABLES
# ------------------------------------------------------------------------------

variable "include_cert_chain" {
  description = "Whether to include the full certificate chain when deploying. If false, only the leaf certificate is deployed."
  type        = bool
  default     = true
}

variable "separate_chain" {
  description = "Whether to store the certificate chain separately in the 'ca.crt' field."
  type        = bool
  default     = false
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
