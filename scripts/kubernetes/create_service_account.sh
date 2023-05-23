#!/usr/bin/env bash
set -e
unset KUBECONFIG
kubectl apply -f ./kubernetes_svc_account.yml

# Define the name of the Kubernetes namespace where the service account resides
NAMESPACE="${K8S_NAMESPACE:-default}"
echo "NAMESPACE: $NAMESPACE"

# Define the name of the service account
SA_NAME="${K8S_SA_NAME:-keyfactor-orchestrator-sa}"
echo "SA_NAME: $SA_NAME"

# Set the cluster name
CLUSTER_NAME="${K8S_CLUSTER_NAME:-kubernetes}"
echo "CLUSTER_NAME: $CLUSTER_NAME"
### NOTE - If you have more than one cluster, you may need to change the index of the array ###
CLUSTER_API_SERVER="${K8S_CLUSTER_API_SERVER:-$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')}" # If you have more than one cluster, you may need to change the index of the array
echo "CLUSTER_API_SERVER: $CLUSTER_API_SERVER"
# Set the service account name

# Get the service account token

SA_TOKEN=$(kubectl get secrets -n $NAMESPACE | grep -i $SA_NAME | awk '{print $1}')
SA_TOKEN=$(kubectl get secret/$SA_TOKEN -n $NAMESPACE -o json | jq -r '.data.token' | base64 --decode)

### NOTE - If you have more than one cluster, you may need to change the index of the array ###
CA_CERT=$(kubectl config view --raw -o json | jq -r '.clusters[0].cluster."certificate-authority-data"')

# Check if the service account token is empty
if [ -z "$SA_TOKEN" ]; then
    echo "Service account token is empty. Please check the service account name and namespace."
    exit 1
fi

echo "Generating kubeconfig file for service account $SA_NAME in namespace $NAMESPACE on cluster $CLUSTER_NAME at $CLUSTER_API_SERVER"
#echo "CA_CERT: $CA_CERT" #uncomment if you need to debug
#echo "SA_TOKEN: $SA_TOKEN" #uncomment if you need to debug
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

# Save only the service account context to a JSON file
kubectl config view --raw -o json --kubeconfig=kubeconfig > "${SA_NAME}-context.json"

# Set the KUBECONFIG environment variable to point to the new kubeconfig file
export KUBECONFIG=$PWD/kubeconfig

# Verify permissions of the service account to list secrets
kubectl get secrets 
kubectl get csr
