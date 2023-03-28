# Repo related variables
variable "repo_path" {
  description = "The path to the repository"
  type        = string
  default     = "keyfactor/k8s-orchestrator"
}

variable "required_approval_count" {
  description = "The number of approvers required to approve a PR"
  type        = number
  default     = 1
}

variable "release_dismissal_restrictions" {
  type = list(string)
  default = []
  description = "The list of actor Names/IDs with dismissal access. If not empty, restrict_dismissals is ignored. Actor names must either begin with a '/' for users or the organization name followed by a '/' for teams."
}

variable "release_bypassers" {
  type = list(string)
  default = []
  description = "The list of actor Names/IDs that are allowed to bypass pull request requirements. Actor names must either begin with a '/' for users or the organization name followed by a '/' for teams."
  
}
variable "release_push_restrictions" {
    type = list(string)
    default = []
    description = "The list of actor Names/IDs that may push to the branch. Actor names must either begin with a '/' for users or the organization name followed by a '/' for teams."
}

# Actions Related Variables
variable "command_domain" {
  description = "The domain to use for testing. The domain must exist in Keyfactor Command."
  type        = string
  default     = "command"
}

variable "command_hostname" {
  description = "The hostname of the Keyfactor Command instance to run tests against."
  type        = string
}

variable "test_username" {
  description = "The username to use for testing. The user must exist in Keyfactor Command and have the appropriate permissions."
  type        = string
}

variable "test_user_password" {
  description = "The password to user account for testing."
  type        = string
  sensitive   = true
}

variable "test_cert_id" {
  description = "The Keyfactor Command ID of a certificate to use for testing. Note: the certificate must exist."
  type        = string
  default     = "1"
}

variable "test_cert_password" {
  description = "The password to use when creating test certificate(s)."
  type        = string
  default     = "cert_changeme@!!"
  sensitive   = true
}

variable "test_store_password" {
  description = "The password to use when creating test certificate store(s)."
  type        = string
  default     = "store_changeme@!!"
  sensitive   = true
}

variable "test_security_role_name" {
  type        = string
  description = "Name of role to create for tests. Note: the role must NOT exist in Keyfactor."
}

variable "test_security_identity_accountname" {
  type        = string
  description = "Name of identity to create for tests. Note: the account must exist in AD, and the identity must NOT exist in Keyfactor."
  default     = "acc-tests-terraformer"
}

variable "test_security_identity_role1" {
  type        = string
  description = "Name of role to bind to test identity. Note: the role must exist in Keyfactor."
}

variable "test_security_identity_role2" {
  type        = string
  description = "Name of additional role to bind to test identity. Note: the role must exist in Keyfactor."
}

variable "test_certificate_store_id" {
  type        = string
  description = "ID of certificate store to test cert deployments. Note: the store must exist in Keyfactor."
}

variable "test_certificate_store_client_machine" {
  type        = string
  description = "Name of orchestrator to test cert deployments. Note: the agent must exist and be approved in Keyfactor."
}

variable "test_certificate_store_orchestrator_agent_id" {
  type        = string
  description = "ID of orchestrator agent to test cert deployments. Note: the agent must exist and be approved in Keyfactor."
}

variable "test_certificate_store_container_id1" {
  type        = string
  description = "ID of certificate store container to test cert deployments. Note: the container must exist in Keyfactor and be compatible with the store type."
}

variable "test_certificate_store_container_id2" {
  type        = string
  description = "ID of certificate store container to test cert deployments. Note: the container must exist in Keyfactor and be compatible with the store type."
}

variable "test_template_role_binding_role_name" {
  type        = string
  description = "Name of an existing role to use for testing. Note: the role must exist in Keyfactor."
}

variable "test_template_role_binding_template_name1" {
  type        = string
  description = "Name of an existing template to use for template role binding. Note: the template must exist in Keyfactor."
}

variable "test_template_role_binding_template_name2" {
  type        = string
  description = "Name of an existing template to use for template role binding. Note: the template must exist in Keyfactor."
}

variable "test_template_role_binding_template_name3" {
  type        = string
  description = "Name of an existing template to use for template role binding. Note: the template must exist in Keyfactor."
}

variable "test_certificate_ca_domain" {
  type        = string
  description = "Domain of an existing CA to use for testing. Note: the domain must exist in Keyfactor."
}
variable "test_certificate_ca_name" {
  type        = string
  description = "Name of an existing CA to use for testing. Note: the CA must exist in Keyfactor and have the template specified in `test_cert_template_name` var. "

}
variable "test_deploy_cert_storeid1" {
  type        = string
  description = "ID of certificate store to test cert deployments. Note: the store must exist in Keyfactor."
}
variable "test_deploy_cert_storeid2" {
  type        = string
  description = "ID of certificate store to test cert deployments. Note: the store must exist in Keyfactor."
}

variable "test_certificate_template_name" {
  type        = string
  description = "Name of an existing template to use for testing. Note: the template must exist in Keyfactor, be usable by the CA specificed in `test_certificate_ca_name` and the user specified in `test_username`. "
}