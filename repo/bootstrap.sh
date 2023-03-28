#!/usr/bin/env bash
export AZ_RESOURCE_GROUP_NAME=integrations-infra
export AZ_STORAGE_ACCOUNT_NAME=orchestratortests
export AZ_STORAGE_CONTAINER_NAME=k8s-orchestrator-tfstate
export AZ_TENANT_ID=csspkioutlook.onmicrosoft.com

# Login to azure
az login --tenant $AZ_TENANT_ID
# Create storage account
az storage account create \
  --resource-group $AZ_RESOURCE_GROUP_NAME \
  --name $AZ_STORAGE_ACCOUNT_NAME \
  --sku Standard_LRS \
  --encryption-services blob

# Create blob container
az storage container create \
  --name $AZ_STORAGE_CONTAINER_NAME \
  --account-name $AZ_STORAGE_ACCOUNT_NAME

ACCOUNT_KEY=$(az storage account keys list --resource-group $AZ_RESOURCE_GROUP_NAME --account-name $AZ_STORAGE_ACCOUNT_NAME --query '[0].value' -o tsv)
export ARM_ACCESS_KEY=$ACCOUNT_KEY