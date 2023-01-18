#!/usr/bin/env bash
source .env
export GH_REPO_NAME="Keyfactor/k8s-orchestrator"
export GH_VARIABLES_API="/repos/$GH_REPO_NAME/actions/variables"
export GH_SECRETS_API="/repos/$GH_REPO_NAME/actions/secrets"

function listVars() {
  echo "List variables for repo $GH_REPO_NAME"
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API"    
}

function createVars(){
  echo "Creating or updating variable KEYFACTOR_HOSTNAME with value $KEYFACTOR_HOSTNAME for repo $GH_REPO_NAME" 
  gh api \
    --method POST \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API" \
    -f name='KEYFACTOR_HOSTNAME' \
    -f value="$KEYFACTOR_HOSTNAME" || true
   
  gh api \
    --method PATCH \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API/KEYFACTOR_HOSTNAME" \
    -f name='KEYFACTOR_HOSTNAME' \
    -f value="$KEYFACTOR_HOSTNAME" 
   
  echo "Creating or updating variable KEYFACTOR_DOMAIN with value $KEYFACTOR_HOSTNAME for repo $GH_REPO_NAME" 
  gh api \
    --method POST \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API" \
    -f name='KEYFACTOR_DOMAIN' \
    -f value="$KEYFACTOR_DOMAIN" || true
     
  gh api \
    --method PATCH \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API/KEYFACTOR_DOMAIN" \
    -f name='KEYFACTOR_DOMAIN' \
    -f value="$KEYFACTOR_DOMAIN" 
   
  echo "Creating or updating variable KEYFACTOR_USERNAME with value $KEYFACTOR_USERNAME for repo $GH_REPO_NAME"
  gh api \
    --method POST \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API" \
    -f name='KEYFACTOR_USERNAME' \
    -f value="$KEYFACTOR_USERNAME" || true
    
  gh api \
    --method PATCH \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_VARIABLES_API/KEYFACTOR_USERNAME" \
    -f name='KEYFACTOR_USERNAME' \
    -f value="$KEYFACTOR_USERNAME"
}
    
function getRepoKey(){
  echo "Fetching repo public key"
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "/repos/$GH_REPO_NAME/actions/secrets/public-key" > publicKey.json
    
  export GH_PUBKEY=$(jq -r '.key' publicKey.json)
  echo "Public key: $GH_PUBKEY"
  export GH_PUBKEY_ID="$(jq -r '.key_id' publicKey.json)"
  echo "Key ID: $GH_PUBKEY_ID"  
}

function createOrUpdateSecrets(){
  echo "Write KEYFACTOR_PASSWORD"
  encrypted_value="$KEYFACTOR_PASSWORD_ENCR"
  gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_SECRETS_API/KEYFACTOR_PASSWORD" \
    -f encrypted_value="$encrypted_value" \
   -f key_id="$GH_PUBKEY_ID" 
  
  echo "Write TEST_KUBECONFIG"
  encrypted_value="$TEST_KUBECONFIG_ENCR"
  
  gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_SECRETS_API/TEST_KUBECONFIG" \
    -f encrypted_value="$encrypted_value" \
   -f key_id="$GH_PUBKEY_ID"
   
  
  gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_SECRETS_API/TEST_PAM_MOCK_PASSWORD" \
    -f encrypted_value="$encrypted_value" \
   -f key_id="$GH_PUBKEY_ID"
   
  echo "Write nuget_token"
  encrypted_value="$nuget_token"
  gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_SECRETS_API/TEST_KUBECONFIG" \
    -f encrypted_value="$encrypted_value" \
   -f key_id="$GH_PUBKEY_ID"
  
  echo "List secrets for repo $GH_REPO_NAME"
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$GH_SECRETS_API"  
}

createVars
createOrUpdateSecrets
listVars