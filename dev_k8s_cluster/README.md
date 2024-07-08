# Docker Desktop Kubernetes Cluster
This is a quick guide on how to setup a Kubernetes cluster using Docker Desktop that can be used for development purposes,
and testing the Keyfactor Command Kubernetes Universal Orchestrator extension.

## Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- [helm](https://helm.sh/docs/intro/install/)
- [terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)

## Kubernetes Setup
1. Enable Kubernetes in Docker Desktop
    - Open Docker Desktop
    - Click on the Docker icon in the system tray
    - Click on `Settings`
    - Click on `Kubernetes`
    - Check the box for `Enable Kubernetes`
    - Click `Apply & Restart`
2. Configure kubectl to use the Docker Desktop Kubernetes cluster
    - Run the following command in a terminal
    ```shell
    kubectl config use-context docker-desktop
    ```
3. Run the `setup_dashboard.sh` script to install the Kubernetes dashboard
    ```shell
    ./setup_dashboard.sh
    ```
4. Run the terraform code to create the necessary resources
    ```shell
    terraform init
    terraform apply
    ```
Now the cluster is ready to be used for development and testing purposes.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_kubernetes"></a> [kubernetes](#requirement\_kubernetes) | >=2.30 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_kubernetes"></a> [kubernetes](#provider\_kubernetes) | 2.30.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [kubernetes_cluster_role_binding.example](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/cluster_role_binding) | resource |
| [kubernetes_namespace.keyfactor_command](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/namespace) | resource |
| [kubernetes_namespace.test](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/namespace) | resource |
| [kubernetes_secret.admin_user_token](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/secret) | resource |
| [kubernetes_service_account.admin_user](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/service_account) | resource |
| [kubernetes_namespace.dashboard](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/data-sources/namespace) | data source |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_admin_user_token"></a> [admin\_user\_token](#output\_admin\_user\_token) | n/a |
<!-- END_TF_DOCS -->