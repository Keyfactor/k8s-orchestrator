resource "github_actions_secret" "test_" {
  repository       = "example_repository"
  secret_name      = "example_secret_name"
  plaintext_value  = var.keyfactor_hostname
}

#resource "github_actions_secret" "example_secret" {
#  repository       = "example_repository"
#  secret_name      = "example_secret_name"
#  encrypted_value  = var.some_encrypted_secret_string
#}