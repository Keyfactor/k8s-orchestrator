## Actions Variables
#resource "github_actions_variable" "test_hostname" {
#  repository    = var.repo_path
#  variable_name = "TEST_HOSTNAME"
#  value         = var.command_hostname
#}

resource "github_actions_secret" "test_cert_id" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_CERTIFICATE_ID"
  plaintext_value = var.test_cert_id
}

#resource "github_actions_secret" "test_cert_password" {
#  repository      = data.github_repository.repo.name
#  secret_name     = "TEST_CERTIFICATE_PASSWORD"
#  plaintext_value = var.test_cert_password
#}


resource "github_actions_secret" "test_cert_template_name" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_CERTIFICATE_TEMPLATE_NAME"
  plaintext_value = var.test_certificate_template_name
}

resource "github_actions_secret" "test_certificate_ca_domain" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_CERTIFICATE_CA_DOMAIN"
  plaintext_value = var.test_certificate_ca_domain
}

resource "github_actions_secret" "test_certificate_ca_name" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_CERTIFICATE_CA_NAME"
  plaintext_value = var.test_certificate_ca_name
}

## Cert Deploy Test Variables

resource "github_actions_secret" "test_deploy_cert_storeid1" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_DEPLOY_CERT_STOREID1"
  plaintext_value = var.test_deploy_cert_storeid1
}


resource "github_actions_secret" "test_deploy_cert_storeid2" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_DEPLOY_CERT_STOREID2"
  plaintext_value = var.test_deploy_cert_storeid2
}

## Cert Store Test Variables
//KEYFACTOR_CERTIFICATE_STORE_ID: "ef0b8005-63bf-42e8-aa3f-23bc94dcf611"
//          KEYFACTOR_CERTIFICATE_STORE_CLIENT_MACHINE: "myorchestrator01"
//          KEYFACTOR_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID: "c2b2084f-3d89-4ded-bb8b-b4e0e74d2b59"
//          KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID1: "2"
//          KEYFACTOR_CERTIFICATE_STORE_CONTAINER_ID2: "2"
resource "github_actions_secret" "test_certificate_store_id" {
  repository  = data.github_repository.repo.name
  secret_name = "TEST_CERTIFICATE_STORE_ID"
  plaintext_value = var.test_certificate_store_id
}

resource "github_actions_secret" "test_certificate_store_client_machine" {
  repository  = data.github_repository.repo.name
  secret_name = "TEST_CERTIFICATE_STORE_CLIENT_MACHINE"
  plaintext_value = var.test_certificate_store_client_machine
}

resource "github_actions_secret" "test_certificate_store_orchestrator_agent_id" {
  repository  = data.github_repository.repo.name
  secret_name = "TEST_CERTIFICATE_STORE_ORCHESTRATOR_AGENT_ID"
  plaintext_value = var.test_certificate_store_orchestrator_agent_id
}

resource "github_actions_secret" "test_certificate_store_container_id1" {
  repository  = data.github_repository.repo.name
  secret_name = "TEST_CERTIFICATE_STORE_CONTAINER_ID1"
  plaintext_value = var.test_certificate_store_container_id1
}

#resource "github_actions_secret" "test_certificate_store_password" {
#  repository  = data.github_repository.repo.name
#  secret_name = "TEST_CERTIFICATE_STORE_PASS"
#  plaintext_value = var.test_store_password
#}

resource "github_actions_secret" "test_certificate_store_container_id2" {
  repository  = data.github_repository.repo.name
  secret_name = "TEST_CERTIFICATE_STORE_CONTAINER_ID2"
  plaintext_value = var.test_certificate_store_container_id2
}

# Role Test Variables
resource "github_actions_secret" "test_security_role_name" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_SECURITY_ROLE_NAME"
  plaintext_value = var.test_security_role_name
}

resource "github_actions_secret" "test_security_identity_accountname" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_SECURITY_IDENTITY_ACCOUNTNAME"
  plaintext_value = var.test_security_identity_accountname
}

resource "github_actions_secret" "test_security_identity_role1" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_SECURITY_IDENTITY_ROLE1"
  plaintext_value = var.test_security_identity_role1
}

resource "github_actions_secret" "test_security_identity_role2" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_SECURITY_IDENTITY_ROLE2"
  plaintext_value = var.test_security_identity_role2
}

resource "github_actions_secret" "test_template_role_binding_role_name" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_TEMPLATE_ROLE_BINDING_ROLE_NAME"
  plaintext_value = var.test_template_role_binding_role_name
}


resource "github_actions_secret" "test_template_role_binding_template_name1" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME1"
  plaintext_value = var.test_template_role_binding_template_name1
}


resource "github_actions_secret" "test_template_role_binding_template_name2" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME2"
  plaintext_value = var.test_template_role_binding_template_name2
}


resource "github_actions_secret" "test_template_role_binding_template_name3" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_TEMPLATE_ROLE_BINDING_TEMPLATE_NAME3"
  plaintext_value = var.test_template_role_binding_template_name3
}







