#!/usr/bin/env bash
# Prompt for SA_NAME, NAMESPACE, CLUSTER_NAME, CLUSTER_API_SERVER
read -p "Enter the name of the service account: " SA_NAME
read -p "Enter the namespace of the service account: " NAMESPACE
read -p "Enter the name of the cluster: " CLUSTER_NAME
read -p "Enter the API server hostname w/ port of the cluster: " CLUSTER_API_SERVER
echo "Generating kubeconfig file for service account $SA_NAME in namespace $NAMESPACE on cluster $CLUSTER_NAME at $CLUSTER_API_SERVER"
#echo "CA_CERT: $CA_CERT" #uncomment if you need to debug
#echo "SA_TOKEN: $SA_TOKEN" #uncomment if you need to debug
SA_TOKEN=$(kubectl get secrets -n $NAMESPACE | grep -i $SA_NAME | awk '{print $1}')
SA_TOKEN=$(kubectl get secret/$SA_TOKEN -n $NAMESPACE -o json | jq -r '.data.token' | base64 --decode)
CA_CERT=$(kubectl config view --raw -o json | jq -r '.clusters[1].cluster."certificate-authority-data"')
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
echo "${SA_NAME}-context.json has been created. Please copy and paste the content as the 'KubeSvcCreds' value on your certificate store definition."