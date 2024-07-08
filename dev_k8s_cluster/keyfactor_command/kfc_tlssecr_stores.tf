data keyfactor_agent "k8s" {
  agent_identifier = var.client_machine_name
}



resource "keyfactor_certificate_store" "tls_store_00" {
  client_machine     = data.keyfactor_agent.k8s.client_machine
  # Orchestrator client name
  store_path         = "${var.kube_cluster_name}/${var.kube_namespace}/${var.kube_tlssecr_name}00"           # Varies based on store type
  agent_identifier   = data.keyfactor_agent.k8s.agent_identifier
  # Orchestrator GUID or Orchestrator ClientMachine
  store_type         = "K8STLSSecr"                          # Must exist in KeyFactor
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_file)
  server_use_ssl     = true
  inventory_schedule = "5m"
  properties         = {
    KubeSecretType   = "tls_secret"
#     KubeNamespace    = var.kube_namespace # this SHOULD take precedence over the store_path
#     KubeSecretName   = var.k8stlssecr_name # this SHOULD take precedence over the store_path
#     KubeSvcCreds = file(var.kubeconfig_file) # todo: invalid property
#     SeparateChain    = true # todo: invalid property
#     IncludeCertChain = true # todo: invalid property
  }
}

resource "keyfactor_certificate_deployment" "k8stlssecr_00" {
  certificate_id       = keyfactor_certificate.pfx_enrollment_00.certificate_id
  certificate_store_id = keyfactor_certificate_store.tls_store_00.id
}



resource "keyfactor_certificate_store" "tls_store_01" {
  client_machine     = data.keyfactor_agent.k8s.client_machine
  # Orchestrator client name
  store_path         = "${var.kube_cluster_name}/${var.kube_namespace}/${var.kube_tlssecr_name}01"           # Varies based on store type
  agent_identifier   = data.keyfactor_agent.k8s.agent_identifier
  # Orchestrator GUID or Orchestrator ClientMachine
  store_type         = "K8STLSSecr"                          # Must exist in KeyFactor
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_file)
  server_use_ssl     = true
  inventory_schedule = "5m"
  properties         = {
    KubeSecretType   = "tls_secret"
    #     KubeNamespace    = var.kube_namespace # this SHOULD take precedence over the store_path
    #     KubeSecretName   = var.k8stlssecr_name # this SHOULD take precedence over the store_path
    #     KubeSvcCreds = file(var.kubeconfig_file) # todo: invalid property
    #     SeparateChain    = true # todo: invalid property
    #     IncludeCertChain = true # todo: invalid property
  }
}

resource "keyfactor_certificate_deployment" "k8stlssecr_01" {
  certificate_id       = keyfactor_certificate.pfx_enrollment_01.certificate_id
  certificate_store_id = keyfactor_certificate_store.tls_store_01.id
}

resource "keyfactor_certificate_store" "tls_store_02" {
  client_machine     = data.keyfactor_agent.k8s.client_machine
  # Orchestrator client name
  store_path         = "${var.kube_cluster_name}/${var.kube_namespace}/${var.kube_tlssecr_name}02"           # Varies based on store type
  agent_identifier   = data.keyfactor_agent.k8s.agent_identifier
  # Orchestrator GUID or Orchestrator ClientMachine
  store_type         = "K8STLSSecr"                          # Must exist in KeyFactor
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_file)
  server_use_ssl     = true
  inventory_schedule = "5m"
  properties         = {
    KubeSecretType   = "tls_secret"
    #     KubeNamespace    = var.kube_namespace # this SHOULD take precedence over the store_path
    #     KubeSecretName   = var.k8stlssecr_name # this SHOULD take precedence over the store_path
    #     KubeSvcCreds = file(var.kubeconfig_file) # todo: invalid property
    #     SeparateChain    = true # todo: invalid property
    #     IncludeCertChain = true # todo: invalid property
  }
}

resource "keyfactor_certificate_deployment" "k8stlssecr_02" {
  certificate_id       = keyfactor_certificate.pfx_enrollment_02.certificate_id
  certificate_store_id = keyfactor_certificate_store.tls_store_02.id
}

resource "keyfactor_certificate_store" "tls_store_03" {
  client_machine     = data.keyfactor_agent.k8s.client_machine
  # Orchestrator client name
  store_path         = "${var.kube_cluster_name}/${var.kube_namespace}/${var.kube_tlssecr_name}03"           # Varies based on store type
  agent_identifier   = data.keyfactor_agent.k8s.agent_identifier
  # Orchestrator GUID or Orchestrator ClientMachine
  store_type         = "K8STLSSecr"                          # Must exist in KeyFactor
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_file)
  server_use_ssl     = true
  inventory_schedule = "5m"
  properties         = {
    KubeSecretType   = "tls_secret"
    #     KubeNamespace    = var.kube_namespace # this SHOULD take precedence over the store_path
    #     KubeSecretName   = var.k8stlssecr_name # this SHOULD take precedence over the store_path
    #     KubeSvcCreds = file(var.kubeconfig_file) # todo: invalid property
    #     SeparateChain    = true # todo: invalid property
    #     IncludeCertChain = true # todo: invalid property
  }
}

resource "keyfactor_certificate_deployment" "k8stlssecr_03" {
  certificate_id       = keyfactor_certificate.pfx_enrollment_03.certificate_id
  certificate_store_id = keyfactor_certificate_store.tls_store_03.id
}

resource "keyfactor_certificate_store" "tls_store_04" {
  client_machine     = data.keyfactor_agent.k8s.client_machine
  # Orchestrator client name
  store_path         = "${var.kube_cluster_name}/${var.kube_namespace}/${var.kube_tlssecr_name}04"           # Varies based on store type
  agent_identifier   = data.keyfactor_agent.k8s.agent_identifier
  # Orchestrator GUID or Orchestrator ClientMachine
  store_type         = "K8STLSSecr"                          # Must exist in KeyFactor
  server_username    = "kubeconfig"
  server_password    = file(var.kubeconfig_file)
  server_use_ssl     = true
  inventory_schedule = "5m"
  properties         = {
    KubeSecretType   = "tls_secret"
    #     KubeNamespace    = var.kube_namespace # this SHOULD take precedence over the store_path
    #     KubeSecretName   = var.k8stlssecr_name # this SHOULD take precedence over the store_path
    #     KubeSvcCreds = file(var.kubeconfig_file) # todo: invalid property
    #     SeparateChain    = true # todo: invalid property
    #     IncludeCertChain = true # todo: invalid property
  }
}

resource "keyfactor_certificate_deployment" "k8stlssecr_04" {
  certificate_id       = keyfactor_certificate.pfx_enrollment_04.certificate_id
  certificate_store_id = keyfactor_certificate_store.tls_store_04.id
}