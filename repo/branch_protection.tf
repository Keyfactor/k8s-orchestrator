resource "github_branch_protection" "main" {
  repository_id = data.github_repository.repo.id
  # also accepts repository name
  # repository_id  = github_repository.example.name

  pattern          = "main"
  enforce_admins   = true
  allows_deletions = false
  allows_force_pushes = false
  

#  required_status_checks {
#    strict   = false
#    contexts = ["ci/travis"]
#  }
  
  
  required_pull_request_reviews {
    dismiss_stale_reviews  = true
    restrict_dismissals    = true
    required_approving_review_count = 1
    dismissal_restrictions = [
        #data.github_user.example.node_id,
        #"/exampleuser",
        #"exampleorganization/exampleteam",
        # limited to a list of one type of restriction (user, team, app)
        # github_team.example.node_id
    ]
    pull_request_bypassers = [
        #        data.github_user.example.node_id,
        #        "/exampleuser",
        #        "exampleorganization/exampleteam",
        # limited to a list of one type of restriction (user, team, app)
        # github_team.example.node_id
    ]
    require_last_push_approval = true # Require that The most recent push must be approved by someone other than the last pusher.
  }

  push_restrictions = [
        #    data.github_user.example.node_id,
        #    "/exampleuser",
        #    "exampleorganization/exampleteam",
        # limited to a list of one type of restriction (user, team, app)
        # github_team.example.node_id
  ]

}


resource "github_branch_protection" "releases" {
  repository_id = data.github_repository.repo.id
  
  pattern          = "release-*"
  enforce_admins   = true
  allows_deletions = false
  allows_force_pushes = false


    required_status_checks {
      strict   = true # Require branches to be up to date before merging.
      #contexts = ["ci/travis"]
    }


  required_pull_request_reviews {
    dismiss_stale_reviews  = true
    restrict_dismissals    = true
    required_approving_review_count = 1
    dismissal_restrictions = var.release_dismissal_restrictions
    pull_request_bypassers = var.release_bypassers
    require_last_push_approval = true # Require that The most recent push must be approved by someone other than the last pusher.
  }

  push_restrictions = var.release_push_restrictions

}