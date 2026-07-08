#!/usr/bin/env bash
# Prompt for SA_NAME, NAMESPACE, CLUSTER_NAME, CLUSTER_API_SERVER
read -p "Enter the name of the service account: " SA_NAME
read -p "Enter the namespace of the service account: " NAMESPACE
read -p "Enter the name of the cluster: " CLUSTER_NAME
read -p "Enter the API server hostname w/ port of the cluster: " CLUSTER_API_SERVER
### NOTE - If you have more than one cluster, you may need to change the index of the array ###
#read -p "Enter the index of the cluster in your kubeconfig file: " CLUSTER_INDEX
echo "Generating kubeconfig file for service account $SA_NAME in namespace $NAMESPACE on cluster $CLUSTER_NAME at $CLUSTER_API_SERVER"
#echo "CA_CERT: $CA_CERT" #uncomment if you need to debug
#echo "SA_TOKEN: $SA_TOKEN" #uncomment if you need to debug
SA_TOKEN=$(kubectl get secret "$SA_NAME" -n "$NAMESPACE" -o jsonpath='{.data.token}' 2>/dev/null | base64 --decode)
if [ -z "$SA_TOKEN" ]; then
    echo "ERROR: Token secret '$SA_NAME' not found in namespace '$NAMESPACE'."
    echo "Create it by applying kubernetes_svc_account.yaml, then re-run this script."
    exit 1
fi

### NOTE - If you have more than one cluster, you may need to change the index of the array ###
CA_CERT=$(kubectl config view --raw -o json | jq -r '.clusters[0].cluster."certificate-authority-data"')
# Create the kubeconfig file
echo "apiVersion: v1
kind: Config
clusters:
- name: $CLUSTER_NAME
  cluster:
    server: $CLUSTER_API_SERVER
    certificate-authority-data: $CA_CERT
contexts:
- name: $SA_NAME-context
  context:
    cluster: $CLUSTER_NAME
    namespace: $NAMESPACE
    user: $SA_NAME
current-context: $SA_NAME-context
users:
- name: $SA_NAME
  user:
    token: $SA_TOKEN" > kubeconfig
    
kubectl config view --raw -o json --kubeconfig=kubeconfig > "${SA_NAME}-context.json"
echo "${SA_NAME}-context.json has been created. Please copy and paste the content as the 'ServerPassword' value on your certificate store definition."