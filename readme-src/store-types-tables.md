
### K8SCert Store Type
#### kfutil Create K8SCert Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8SCert 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8SCert                          |
| ShortName               | &check;  | K8SCert                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Discovery     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8scert_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Forbidden |
| Private Key Handling  |          | Forbidden  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8scert_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|


### K8SCluster Store Type
#### kfutil Create K8SCluster Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8SCluster 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8SCluster                          |
| ShortName               | &check;  | K8SCluster                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Add,Create,Remove     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8scluster_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Required |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8scluster_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|


### K8SJKS Store Type
#### kfutil Create K8SJKS Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8SJKS 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8SJKS                          |
| ShortName               | &check;  | K8SJKS                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Add,Create,Discovery,Remove     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Checked [x]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8sjks_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Required |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8sjks_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|


### K8SNS Store Type
#### kfutil Create K8SNS Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8SNS 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8SNS                          |
| ShortName               | &check;  | K8SNS                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Add,Create,Discovery,Remove     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8sns_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Required |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8sns_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|


### K8SPKCS12 Store Type
#### kfutil Create K8SPKCS12 Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8SPKCS12 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8SPKCS12                          |
| ShortName               | &check;  | K8SPKCS12                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Add,Create,Discovery,Remove     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Checked [x]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8spkcs12_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Required |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8spkcs12_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|


### K8SSecret Store Type
#### kfutil Create K8SSecret Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8SSecret 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8SSecret                          |
| ShortName               | &check;  | K8SSecret                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Add,Create,Discovery,Remove     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8ssecret_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Forbidden |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8ssecret_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|


### K8STLSSecr Store Type
#### kfutil Create K8STLSSecr Store Type
The following commands can be used with [kfutil](https://github.com/Keyfactor/kfutil). Please refer to the kfutil documentation for more information on how to use the tool to interact w/ Keyfactor Command.

```
bash
kfutil login
kfutil store - types create--name K8STLSSecr 
```

#### UI Configuration
##### UI Basic Tab
| Field Name              | Required | Value                                     |
|-------------------------|----------|-------------------------------------------|
| Name                    | &check;  | K8STLSSecr                          |
| ShortName               | &check;  | K8STLSSecr                          |
| Custom Capability       |          | Unchecked [ ]                             |
| Supported Job Types     | &check;  | Inventory,Add,Create,Discovery,Remove     |
| Needs Server            | &check;  | Checked [x]                         |
| Blueprint Allowed       |          | Unchecked [ ]                       |
| Uses PowerShell         |          | Unchecked [ ]                             |
| Requires Store Password |          | Unchecked [ ]                          |
| Supports Entry Password |          | Unchecked [ ]                         |
      
![k8sstlssecr_basic.png](docs%2Fscreenshots%2Fstore_types%2Fk8stlssecr_basic.png)

##### UI Advanced Tab
| Field Name            | Required | Value                 |
|-----------------------|----------|-----------------------|
| Store Path Type       |          | Freeform      |
| Supports Custom Alias |          | Forbidden |
| Private Key Handling  |          | Optional  |
| PFX Password Style    |          | Default   |

![k8sstlssecr_advanced.png](docs%2Fscreenshots%2Fstore_types%2Fk8stlssecr_advanced.png)

##### UI Custom Fields Tab
| Name           | Display Name         | Type   | Required | Default Value |
|----------------|----------------------|--------|----------|---------------|
| KubeNamespace  | Kube Namespace       | String |          | `default`   |
| KubeSecretName | Kube Secret Name     | String | &check;  |               |
| KubeSecretType | Kube Secret Type     | String | &check;  | `tls_secret`|

