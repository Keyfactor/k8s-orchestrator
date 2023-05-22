#!/usr/bin/env bash

source ~/.kf1022

export KEYFACTOR_API_PATH="${KEYFACTOR_API_PATH:-KeyfactorAPI}"
export KEYFACTOR_HOSTNAME="${KEYFACTOR_HOSTNAME:-$$(cat ~/.keyfactor/command_config.json | jq -r .host)}"

export AGENT_ID="31e00132-a52b-4c96-b6ee-19b31f0fac6e"

export STORE_CLIENT_MACHINE="aaa"

export STORE_PATH_1="k8s-demoakstest3io"
export STORE_PATH_2="k8s-ecdsa-256-vca"
export STORE_PATH_3="lauderdale-switches-edu"
export STORE_PASSWORD_1="WPMYLqG4tHkd"
export STORE_PASSWORD_2="yNmASfGEVjpN"
export STORE_PASSWORD_3="WzSijxyfHC5E"

export STORE_PROPS_1="{\"CertificateDataFieldName\":\"\",\"PasswordFieldName\":\"password\",\"PasswordIsK8SSecret\":\"true\",\"KubeNamespace\":\"default\",\"KubeSecretName\":\"\",\"ServerUseSsl\":\"true\",\"KubeSecretType\":\"pkcs12\",\"StorePassword\":\"\",\"StorePasswordPath\":\"\",\"ServerUsername\":{\"value\":{\"SecretValue\":\"kubeconfig\"}},\"ServerPassword\":{\"value\":{\"SecretValue\":\"abc123\"}}}"


export STORE_1_PAYLOAD
STORE_1_PAYLOAD=$(cat <<EOF
{
  "ClientMachine": "$STORE_CLIENT_MACHINE",
  "Storepath": "$STORE_PATH_1",
  "CreateIfMissing": true,
  "Properties": $STORE_PROPS_1,
  "AgentId": "${AGENT_ID}",
  "AgentAssigned": true,
  "InventorySchedule": {
    "Immediate": true,
  },
  "Password": {
    "SecretValue": "",
  }
}
EOF
)

function createLocalPkcs12() {
  # From locally created p12
  openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
  openssl pkcs12 -export -in cert.pem -inkey key.pem -out certificate.p12
  kubectl create secret generic testp12 --from-file=certificate.p12
}

function createK8SSecret() {
  echo "Creating K8S Secret"
  # From Command enrollments
  kubectl create secret generic "${STORE_PATH_1:-secret1}" --from-file="${STORE_PATH_1:-secret1}.pfx" --from-literal=password="${STORE_PASSWORD_1:-password1}"
  kubectl create secret generic "${STORE_PATH_2:-secret2}" --from-file="${STORE_PATH_2:-secret2}.pfx" --from-literal=password="${STORE_PASSWORD_2:-password2}"
  kubectl create secret generic "${STORE_PATH_3:-secret3}" --from-file="${STORE_PATH_3:-secret3}.pfx" --from-literal=password="${STORE_PASSWORD_3:-password3}"
}

function deleteK8SSecret() {
  echo "Deleting K8S Secret"
  kubectl delete secret "${STORE_PATH_1:-secret1}"
  kubectl delete secret "${STORE_PATH_2:-secret2}"
  kubectl delete secret "${STORE_PATH_3:-secret3}"
}

function createCmdStores(){
  echo "KEYFACTOR_USERNAME: $KEYFACTOR_USERNAME"
#  echo "KEYFACTOR_PASSWORD: $KEYFACTOR_PASSWORD"
  apiUrl=https://"$KEYFACTOR_HOSTNAME"/"$KEYFACTOR_API_PATH/CertificateStores"
  echo "apiUrl: $apiUrl"
  
  curl -X POST \
  --header "Content-Type: application/json" \
  --header 'x-keyfactor-api-version: 1' \
  --header 'x-keyfactor-requested-with: APIClient' \
  --header 'Accept: application/json' \
  -u ${KEYFACTOR_DOMAIN}\\${KEYFACTOR_USERNAME}:${KEYFACTOR_PASSWORD} \
  -d "$STORE_1_PAYLOAD" $apiUrl
}

#createLocalPkcs12
#createK8SSecret
createCmdStores

#read -p "Press enter to delete K8S Secret and Command Stores"
#deleteK8SSecret