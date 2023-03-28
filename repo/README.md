# Repo secrets manager

This repo is used to manage secrets for the Keyfactor K8S Orchestrator extension to use in unit tests.

## Initial setup
Run the bootstrap script to create terraform state storage backend.
```bash
./bootstrap.sh
```

## Quick start
```bash
./get_env.sh # This configures your Azure and GitHub credentials, it also pulls the .auto.tfvars file from Azure Key Vault
terraform init
terraform workspace list
terraform workspace select command_10_11
terraform plan
terraform apply --auto-approve
```

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_github"></a> [github](#requirement\_github) | >=5.18.3 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_github"></a> [github](#provider\_github) | 5.18.3 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [github_actions_secret.test_cert_id](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_cert_password](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_cert_template_name](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_ca_domain](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_ca_name](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_store_client_machine](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_store_container_id1](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_store_container_id2](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_store_id](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_store_orchestrator_agent_id](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_certificate_store_password](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_deploy_cert_storeid1](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_deploy_cert_storeid2](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_domain](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_hostname](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_security_identity_accountname](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_security_identity_role1](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_security_identity_role2](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_security_role_name](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_store_password](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_template_role_binding_role_name](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_template_role_binding_template_name1](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_template_role_binding_template_name2](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_template_role_binding_template_name3](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_user_password](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_secret.test_username](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_secret) | resource |
| [github_actions_public_key.terraform_provider_keyfactor](https://registry.terraform.io/providers/integrations/github/latest/docs/data-sources/actions_public_key) | data source |
| [github_repository.terraform_provider_keyfactor](https://registry.terraform.io/providers/integrations/github/latest/docs/data-sources/repository) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_command_domain"></a> [command\_domain](#input\_command\_domain) | The domain to use for testing. The domain must exist in Keyfactor Command. | `string` | `"command"` | no |
| <a name="input_command_hostname"></a> [command\_hostname](#input\_command\_hostname) | The hostname of the Keyfactor Command instance to run tests against. | `string` | n/a | yes |
| <a name="input_repo_path"></a> [repo\_path](#input\_repo\_path) | The path to the repository | `string` | `"keyfactor-pub/terraform-provider-keyfactor"` | no |
| <a name="input_test_cert_id"></a> [test\_cert\_id](#input\_test\_cert\_id) | The Keyfactor Command ID of a certificate to use for testing. Note: the certificate must exist. | `string` | `"1"` | no |
| <a name="input_test_cert_password"></a> [test\_cert\_password](#input\_test\_cert\_password) | The password to use when creating test certificate(s). | `string` | `"cert_changeme@!!"` | no |
| <a name="input_test_cert_template_name"></a> [test\_cert\_template\_name](#input\_test\_cert\_template\_name) | n/a | `string` | `""` | no |
| <a name="input_test_certificate_ca_domain"></a> [test\_certificate\_ca\_domain](#input\_test\_certificate\_ca\_domain) | Domain of an existing CA to use for testing. Note: the domain must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_certificate_ca_name"></a> [test\_certificate\_ca\_name](#input\_test\_certificate\_ca\_name) | Name of an existing CA to use for testing. Note: the CA must exist in Keyfactor and have the template specified in `test_cert_template_name` var. | `string` | n/a | yes |
| <a name="input_test_certificate_store_client_machine"></a> [test\_certificate\_store\_client\_machine](#input\_test\_certificate\_store\_client\_machine) | Name of orchestrator to test cert deployments. Note: the agent must exist and be approved in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_certificate_store_container_id1"></a> [test\_certificate\_store\_container\_id1](#input\_test\_certificate\_store\_container\_id1) | ID of certificate store container to test cert deployments. Note: the container must exist in Keyfactor and be compatible with the store type. | `string` | n/a | yes |
| <a name="input_test_certificate_store_container_id2"></a> [test\_certificate\_store\_container\_id2](#input\_test\_certificate\_store\_container\_id2) | ID of certificate store container to test cert deployments. Note: the container must exist in Keyfactor and be compatible with the store type. | `string` | n/a | yes |
| <a name="input_test_certificate_store_id"></a> [test\_certificate\_store\_id](#input\_test\_certificate\_store\_id) | ID of certificate store to test cert deployments. Note: the store must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_certificate_store_orchestrator_agent_id"></a> [test\_certificate\_store\_orchestrator\_agent\_id](#input\_test\_certificate\_store\_orchestrator\_agent\_id) | ID of orchestrator agent to test cert deployments. Note: the agent must exist and be approved in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_certificate_template_name"></a> [test\_certificate\_template\_name](#input\_test\_certificate\_template\_name) | Name of an existing template to use for testing. Note: the template must exist in Keyfactor, be usable by the CA specificed in `test_certificate_ca_name` and the user specified in `test_username`. | `string` | n/a | yes |
| <a name="input_test_deploy_cert_storeid1"></a> [test\_deploy\_cert\_storeid1](#input\_test\_deploy\_cert\_storeid1) | ID of certificate store to test cert deployments. Note: the store must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_deploy_cert_storeid2"></a> [test\_deploy\_cert\_storeid2](#input\_test\_deploy\_cert\_storeid2) | ID of certificate store to test cert deployments. Note: the store must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_security_identity_accountname"></a> [test\_security\_identity\_accountname](#input\_test\_security\_identity\_accountname) | Name of identity to create for tests. Note: the account must exist in AD, and the identity must NOT exist in Keyfactor. | `string` | `"acc-tests-terraformer"` | no |
| <a name="input_test_security_identity_role1"></a> [test\_security\_identity\_role1](#input\_test\_security\_identity\_role1) | Name of role to bind to test identity. Note: the role must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_security_identity_role2"></a> [test\_security\_identity\_role2](#input\_test\_security\_identity\_role2) | Name of additional role to bind to test identity. Note: the role must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_security_role_name"></a> [test\_security\_role\_name](#input\_test\_security\_role\_name) | Name of role to create for tests. Note: the role must NOT exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_store_password"></a> [test\_store\_password](#input\_test\_store\_password) | The password to use when creating test certificate store(s). | `string` | `"store_changeme@!!"` | no |
| <a name="input_test_template_role_binding_role_name"></a> [test\_template\_role\_binding\_role\_name](#input\_test\_template\_role\_binding\_role\_name) | Name of an existing role to use for testing. Note: the role must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_template_role_binding_template_name1"></a> [test\_template\_role\_binding\_template\_name1](#input\_test\_template\_role\_binding\_template\_name1) | Name of an existing template to use for template role binding. Note: the template must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_template_role_binding_template_name2"></a> [test\_template\_role\_binding\_template\_name2](#input\_test\_template\_role\_binding\_template\_name2) | Name of an existing template to use for template role binding. Note: the template must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_template_role_binding_template_name3"></a> [test\_template\_role\_binding\_template\_name3](#input\_test\_template\_role\_binding\_template\_name3) | Name of an existing template to use for template role binding. Note: the template must exist in Keyfactor. | `string` | n/a | yes |
| <a name="input_test_user_password"></a> [test\_user\_password](#input\_test\_user\_password) | The password to user account for testing. | `string` | n/a | yes |
| <a name="input_test_username"></a> [test\_username](#input\_test\_username) | The username to use for testing. The user must exist in Keyfactor Command and have the appropriate permissions. | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END_TF_DOCS -->