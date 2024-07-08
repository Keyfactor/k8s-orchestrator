# Keyfactor Command K8S Orchestrator Demo
This repo contains Terraform code to demonstrate the use of the Keyfactor Command K8S Orchestrator extension to manage 
certificates in a Kubernetes cluster.

## Prerequisites
- [Keyfactor Command](https://www.keyfactor.com/products/command/) 10.0 or later
- [Keyfactor Command Universal Orchestrator](https://software.keyfactor.com/Core-OnPrem/v10.5/Content/InstallingAgents/Introduction.htm)
- [Keyfactor Command K8S Universal Orchestrator Extension](https://github.com/Keyfactor/k8s-orchestrator?tab=readme-ov-file#kubernetes-orchestrator-extension-installation)
- [Kubernetes Cluster Credentials](https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes)
- [Terraform](https://www.terraform.io/downloads.html) 1.0 or later

## Usage
1. Clone the repository
2. Update the `terraform.tfvars` file with the appropriate values
3. Run `terraform init`
4. Run `terraform apply`
5. Run `terraform destroy` to remove the resources

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_keyfactor"></a> [keyfactor](#requirement\_keyfactor) | >=2.1.11 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_keyfactor"></a> [keyfactor](#provider\_keyfactor) | 2.1.11 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [keyfactor_certificate.pfx_enrollment_01](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate) | resource |
| [keyfactor_certificate_deployment.k8stlssecr](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_deployment) | resource |
| [keyfactor_certificate_store.tls_store](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/resources/certificate_store) | resource |
| [keyfactor_agent.k8s](https://registry.terraform.io/providers/keyfactor-pub/keyfactor/latest/docs/data-sources/agent) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_client_machine_name"></a> [client\_machine\_name](#input\_client\_machine\_name) | Name of the client machine name of the Keyfactor Command Universal Orchestrator to use. | `string` | n/a | yes |
| <a name="input_default_ca_domain"></a> [default\_ca\_domain](#input\_default\_ca\_domain) | The default certificate authority domain to use in certificate generation | `string` | `"DC-CA.Command.local"` | no |
| <a name="input_default_cert_ca"></a> [default\_cert\_ca](#input\_default\_cert\_ca) | The default certificate authority to use in certificate generation | `string` | `"CommandCA1"` | no |
| <a name="input_kfc_ca_domain"></a> [kfc\_ca\_domain](#input\_kfc\_ca\_domain) | The default CA domain to use for the certificate | `string` | `"Keyfactor"` | no |
| <a name="input_kfc_ca_name"></a> [kfc\_ca\_name](#input\_kfc\_ca\_name) | The name of the certificate authority to use for the Keyfactor Command certificate enrollments. | `string` | `"CommandCA"` | no |
| <a name="input_kube_cluster_name"></a> [kube\_cluster\_name](#input\_kube\_cluster\_name) | The name of the Kubernetes cluster to use | `string` | `"dev-cluster"` | no |
| <a name="input_kube_namespace"></a> [kube\_namespace](#input\_kube\_namespace) | Kubernetes namespace to store the certificate in | `string` | `"default"` | no |
| <a name="input_kube_tlssecr_name"></a> [kube\_tlssecr\_name](#input\_kube\_tlssecr\_name) | The name of the Kubernetes TLS secret for the Keyfactor Command `k8s-orchestrator` extension to manage | `string` | `"kfc-k8stlssecr-deployment"` | no |
| <a name="input_kubeconfig_file"></a> [kubeconfig\_file](#input\_kubeconfig\_file) | Path to the kubeconfig file | `string` | `"~/.kube/config"` | no |
| <a name="input_webserver_template"></a> [webserver\_template](#input\_webserver\_template) | The webserver template to use in certificate generation | `string` | `"2YearTestWebServer"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->