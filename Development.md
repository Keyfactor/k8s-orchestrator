# Developer Guide

This document describes how to build and test the KubeTest project.

- [Developer Guide](#developer-guide)
    * [Prerequisites](#prerequisites)
    * [Testing Environment Variables](#testing-environment-variables)
    * [Running tests](#running-tests)
        + [Inventory](#inventory)
            - [bash](#bash)
            - [powershell](#powershell)
            - [Output](#output)
        + [Management Add](#management-add)
            - [bash](#bash-1)
            - [powershell](#powershell-1)
            - [Output](#output-1)
        + [Management Remove](#management-remove)
            - [bash](#bash-2)
            - [powershell](#powershell-2)
            - [Output](#output-2)
        + [Example Failed Test](#example-failed-test)

## Prerequisites

## Testing Environment Variables

| Name                  | Description                                                                                      | Default   | Example                                                                                                                                             |
|-----------------------|--------------------------------------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `KEYFACTOR_HOSTNAME`  | The hostname of the Keyfactor Command server.                                                    |           | `my.kfcommand.kfdelivery.com`                                                                                                                       |
| `KEYFACTOR_USERNAME`  | The username of the Keyfactor user.                                                              |           | `k8s-orch-sa`                                                                                                                                       |
| `KEYFACTOR_PASSWORD`  | The password of the Keyfactor user.                                                              |           | `<k8s-orch-sa's Command password>`                                                                                                                  |
| `TEST_KUBECONFIG`     | A full unescaped `kubeconfig` in JSON format. Can also be base64 encoded. Must be a single line! |           | [See Docs](https://github.com/Keyfactor/k8s-orchestrator/tree/main/scripts/kubernetes#keyfactor-kubernetes-orchestrator-service-account-definition) |
| `TEST_KUBE_NAMESPACE` | The namespace to use for testing.                                                                | `default` | `keyfactor`                                                                                                                                         |
| `TEST_MANUAL`         | If set to `true`, the tests will not be run automatically and prompt for user input.             | `false`   | `true`                                                                                                                                              |
| `TEST_CERT_MGMT_TYPE` | The orchestrator job type. Must be on of the following: `['inv','add','rem']`                    |           | `inv`                                                                                                                                               |
| `TEST_ORCH_OPERATION` | The orchestrator operation. Can be either `inventory` or `management`                            |           | `inventory`                                                                                                                                         |

## Running tests

### Inventory
#### bash
```bash
dotnet build
export KEYFACTOR_HOSTNAME=my.keyfactor.kfdelivery.com
export KEYFACTOR_DOMAIN=command
export KEYFACTOR_USERNAME=k8s-agent-sa
export KEYFACTOR_PASSWORD=mykeyfactorcommandpassword
export TEST_KUBECONFIG={"kind":"Config","apiVersion":"v1","preferences":{},"clusters":[...]...} # This needs to be a full kubeconfig file. Can also be passed base64 encoded.
export TEST_KUBE_NAMESPACE=default
export TEST_MANUAL=false
export TEST_CERT_MGMT_TYPE=inv
export TEST_ORCH_OPERATION=inv
./KubeTest/bin/Debug/netcoreapp3.1/KubeTest.exe
```
#### powershell
```powershell
dotnet build
# Set environment variables
$env:KEYFACTOR_HOSTNAME="my.keyfactor.kfdelivery.com"
$env:KEYFACTOR_DOMAIN="command"
$env:KEYFACTOR_USERNAME="k8s-agent-sa"
$env:KEYFACTOR_PASSWORD="mykeyfactorcommandpassword"
$env:TEST_KUBECONFIG={"kind":"Config","apiVersion":"v1","preferences":{},"clusters":[...]...} # This needs to be the full kubeconfig file. Can also be passed base64 encoded.
$env:TEST_KUBE_NAMESPACE="default"
$env:TEST_MANUAL="false"
$env:TEST_CERT_MGMT_TYPE="inv"
$env:TEST_ORCH_OPERATION="inv"
./KubeTest/bin/Debug/netcoreapp3.1/KubeTest.exe
```

#### Output
```text
------------------------------------------------------------------------------------------------------------------------
|Test Name                                                  |Result                                                     |
------------------------------------------------------------------------------------------------------------------------
|Kube Inventory - TLS Secret - tls-secret-01 - SUCCESS      |Failure - Kubernetes tls_secret 'tls-secret-01' was not ...|
|Kube Inventory - Opaque Secret - opaque-secret-01 - FAIL   |Success                                                    |
|Kube Inventory - Opaque Secret - opaque-secret-00 - SUCCESS|Success                                                    |
|Kube Inventory - Opaque Secret - opaque-secret-01 - SUCCESS|Success                                                    |
|Kube Inventory - Certificate - cert-01 - SUCCESS           |Success Kubernetes cert 'cert-01' was not found in names...|
------------------------------------------------------------------------------------------------------------------------
All tests passed.

```

### Management Add
#### bash
```bash
dotnet build
export KEYFACTOR_HOSTNAME=my.keyfactor.kfdelivery.com
export KEYFACTOR_DOMAIN=command
export KEYFACTOR_USERNAME=k8s-agent-sa
export KEYFACTOR_PASSWORD=mykeyfactorcommandpassword
export TEST_KUBECONFIG={"kind":"Config","apiVersion":"v1","preferences":{},"clusters":[...]...} # This needs to be a full kubeconfig file. Can also be passed base64 encoded.
export TEST_KUBE_NAMESPACE=default
export TEST_MANUAL=false
export TEST_CERT_MGMT_TYPE=add
export TEST_ORCH_OPERATION=management
./KubeTest/bin/Debug/netcoreapp3.1/KubeTest.exe
```
#### powershell
```powershell
dotnet build
# Set environment variables
$env:KEYFACTOR_HOSTNAME="my.keyfactor.kfdelivery.com"
$env:KEYFACTOR_DOMAIN="command"
$env:KEYFACTOR_USERNAME="k8s-agent-sa"
$env:KEYFACTOR_PASSWORD="mykeyfactorcommandpassword"
$env:TEST_KUBECONFIG={"kind":"Config","apiVersion":"v1","preferences":{},"clusters":[...]...} # This needs to be the full kubeconfig file. Can also be passed base64 encoded.
$env:TEST_KUBE_NAMESPACE="default"
$env:TEST_MANUAL="false"
$env:TEST_CERT_MGMT_TYPE="inv"
$env:TEST_ORCH_OPERATION="inv"
./KubeTest/bin/Debug/netcoreapp3.1/KubeTest.exe
```

#### Output
```text
------------------------------------------------------------------------------------------------------------------------
|Test Name                                                  |Result                                                     |
------------------------------------------------------------------------------------------------------------------------
|Add - TLS Secret - tls-secret-01 - SUCCESS                 |Success                                                    |
|Add - TLS Secret - tls-secret-01 - FAIL                    |Success Overwrite is not specified, cannot add multiple ...|
|Add - TLS Secret - tls-secret-01 (overwrite) - SUCCESS     |Success                                                    |
|Add - Opaque Secret - opaque-secret-01 - SUCCESS           |Success                                                    |
|Add - Opaque Secret - opaque-secret-01 - FAIL              |Success The specified network password is not correct.     |
|Add - Opaque Secret - opaque-secret-01 (overwrite) - SUC...|Success                                                    |
|Add - Certificate - cert-01 - FAIL                         |Success ADD operation not supported by Kubernetes CSR type.|
------------------------------------------------------------------------------------------------------------------------
All tests passed.

```

### Management Remove
#### bash
```bash
dotnet build
export KEYFACTOR_HOSTNAME=my.keyfactor.kfdelivery.com
export KEYFACTOR_DOMAIN=command
export KEYFACTOR_USERNAME=k8s-agent-sa
export KEYFACTOR_PASSWORD=mykeyfactorcommandpassword
export TEST_KUBECONFIG={"kind":"Config","apiVersion":"v1","preferences":{},"clusters":[...]...} # This needs to be a full kubeconfig file. Can also be passed base64 encoded.
export TEST_KUBE_NAMESPACE=default
export TEST_MANUAL=false
export TEST_CERT_MGMT_TYPE=remove
export TEST_ORCH_OPERATION=management
./KubeTest/bin/Debug/netcoreapp3.1/KubeTest.exe
```
#### powershell
```powershell
dotnet build
# Set environment variables
$env:KEYFACTOR_HOSTNAME="my.keyfactor.kfdelivery.com"
$env:KEYFACTOR_DOMAIN="command"
$env:KEYFACTOR_USERNAME="k8s-agent-sa"
$env:KEYFACTOR_PASSWORD="mykeyfactorcommandpassword"
$env:TEST_KUBECONFIG={"kind":"Config","apiVersion":"v1","preferences":{},"clusters":[...]...} # This needs to be the full kubeconfig file. Can also be passed base64 encoded.
$env:TEST_KUBE_NAMESPACE="default"
$env:TEST_MANUAL="false"
$env:TEST_CERT_MGMT_TYPE="remove"
$env:TEST_ORCH_OPERATION="inv"
./KubeTest/bin/Debug/netcoreapp3.1/KubeTest.exe
```

#### Output
```text
------------------------------------------------------------------------------------------------------------------------
|Test Name                                                  |Result                                                     |
------------------------------------------------------------------------------------------------------------------------
|Remove - TLS Secret - tls-secrte-01 - FAIL                 |Success Operation returned an invalid status code 'NotFo...|
|Remove - TLS Secret - tls-secret-01 - SUCCESS              |Success                                                    |
|Remove - Opaque Secret - opaque-secrte-01 - FAIL           |Success Operation returned an invalid status code 'NotFo...|
|Remove - Opaque Secret - opaque-secret-01 - SUCCESS        |Success                                                    |
------------------------------------------------------------------------------------------------------------------------
All tests passed.

```

### Example Failed Test
```text
------------------------------------------------------------------------------------------------------------------------
|Test Name                                                  |Result                                                     |
------------------------------------------------------------------------------------------------------------------------
|Remove - TLS Secret - tls-secrte-01 - FAIL                 |Success Operation returned an invalid status code 'NotFo...|
|Remove - TLS Secret - tls-secret-01 - SUCCESS              |Failure - Operation returned an invalid status code 'Not...|
|Remove - Opaque Secret - opaque-secrte-01 - FAIL           |Success Operation returned an invalid status code 'NotFo...|
|Remove - Opaque Secret - opaque-secret-01 - SUCCESS        |Success                                                    |
------------------------------------------------------------------------------------------------------------------------
Some tests failed please check the output above.
```