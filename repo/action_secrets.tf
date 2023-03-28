# Actions Secrets
resource "github_actions_secret" "test_hostname" {
  repository      = data.github_repository.repo.name
  secret_name     = "KEYFACTOR_HOSTNAME"
  plaintext_value = var.command_hostname
}

resource "github_actions_secret" "test_domain" {
  repository      = data.github_repository.repo.name
  secret_name     = "KEYFACTOR_DOMAIN"
  plaintext_value = var.command_domain
}

resource "github_actions_secret" "test_username" {
  repository      = data.github_repository.repo.name
  secret_name     = "KEYFACTOR_USERNAME"
  plaintext_value = var.test_username
}

resource "github_actions_secret" "test_user_password" {
  repository      = data.github_repository.repo.name
  secret_name     = "KEYFACTOR_PASSWORD"
  plaintext_value = var.test_user_password
}

resource "github_actions_secret" "test_cert_password" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_CERTIFICATE_PASSWORD"
  plaintext_value = var.test_cert_password
}

resource "github_actions_secret" "test_store_password" {
  repository      = data.github_repository.repo.name
  secret_name     = "TEST_CERTIFICATE_STORE_PASS"
  plaintext_value = var.test_store_password
}
