data "github_repository" "repo" {
  full_name = var.repo_path
}

#data "github_actions_public_key" "repo" {
#  repository = data.github_repository.repo.name
#}