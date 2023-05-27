#!/usr/bin/env bash

root_ca_name="K8S Orchestrator Dev Root CA"
intermediate_ca_name="K8S Orchestrator Dev Intermediate CA"
export VAULT_ADDR="http://localhost:8200"
#export VAULT_TOKEN="" # If you have a token, you can set it here
export CN_PREFIX="k8s-"
export CN_SUFFIX="-vca"

# Enable the PKI secrets engine
vault secrets enable pki

# Tune the secrets engine so that certificates are valid for ten years
vault secrets tune -max-lease-ttl=87600h pki

# Generate the root CA
vault write -format=json pki/root/generate/internal \
    common_name="$root_ca_name" \
    ttl=87600h > pki_root_root-ca.json
    
# Tell Vault where to find the root CA for signing
vault write pki/config/urls issuing_certificates="$VAULT_ADDR/v1/pki/ca" crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

# Generate the intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int
vault write -format=json pki_int/intermediate/generate/internal \
    common_name="$intermediate_ca_name" \
    ttl=43800h > pki_int_intermediate_intermediate-ca.json

# Extract CSR from Vault response
jq -r .data.csr pki_int_intermediate_intermediate-ca.json > pki_int_intermediate_intermediate.csr

# Sign the intermediate CA's CSR
vault write -format=json pki/root/sign-intermediate csr=@pki_int_intermediate_intermediate.csr \
    format=pem_bundle ttl="43800h" \
    common_name="$intermediate_ca_name" > pki_int_intermediate_signed-intermediate.json
    
# Extract the intermediate CA certificate from Vault response
jq -r .data.certificate pki_int_intermediate_signed-intermediate.json > pki_int_intermediate_intermediate.cert.pem
    
# Tell Vault where to find the intermediate CA for signing
vault write pki_int/intermediate/set-signed certificate=@pki_int_intermediate_intermediate.cert.pem

# Create a role using an RSA 2048 key
vault write pki_int/roles/rsa-2048 \
    allow_any_name=true \
    max_ttl=72h \
    key_type=rsa \
    key_bits=2048

# Create a role using an RSA 4096 key
vault write pki_int/roles/rsa-4096 \
    allow_any_name=true \
    max_ttl=72h \
    key_type=rsa \
    key_bits=4096

# Create a role using an ECDSA P256 key
vault write pki_int/roles/ecdsa-256 \
    allow_any_name=true \
    max_ttl=72h \
    key_type=ec \
    key_bits=256

# Create a role using an ECDSA P384 key
vault write pki_int/roles/ecdsa-384 \
    allow_any_name=true \
    max_ttl=72h \
    key_type=ec \
    key_bits=384
    
# Create a role using an ECDSA P521 key
vault write pki_int/roles/ecdsa-521 \
    allow_any_name=true \
    max_ttl=72h \
    key_type=ec \
    key_bits=521
    
# Create a role using an Ed25519 key
vault write pki_int/roles/ed25519 \
    allow_any_name=true \
    max_ttl=72h \
    key_type=ed25519 \
    key_bits=0
    
# Issue a certificate from the RSA 2048 role
vault write -format=json pki_int/issue/rsa-2048 common_name="${CN_PREFIX}rsa-2048${CN_SUFFIX}" > rsa-2048.json
# Extract the certificate from Vault response
jq -r .data.certificate rsa-2048.json > rsa-2048.cert.pem
# Extract the private key from Vault response
jq -r .data.private_key rsa-2048.json > rsa-2048.key.pem

# Issue a certificate from the RSA 4096 role
vault write -format=json pki_int/issue/rsa-4096 common_name="${CN_PREFIX}rsa-4096${CN_SUFFIX}" > rsa-4096.json
# Extract the certificate from Vault response
jq -r .data.certificate rsa-4096.json > rsa-4096.cert.pem
# Extract the private key from Vault response
jq -r .data.private_key rsa-4096.json > rsa-4096.key.pem

# Issue a certificate from the ECDSA P256 role
vault write -format=json pki_int/issue/ecdsa-256 common_name="${CN_PREFIX}ecdsa-256${CN_SUFFIX}" > ecdsa-256.json
# Extract the certificate from Vault response
jq -r .data.certificate ecdsa-256.json > ecdsa-256.cert.pem
# Extract the private key from Vault response
jq -r .data.private_key ecdsa-256.json > ecdsa-256.key.pem

# Issue a certificate from the ECDSA P384 role
vault write -format=json pki_int/issue/ecdsa-384 common_name="${CN_PREFIX}ecdsa-384${CN_SUFFIX}" > ecdsa-384.json
# Extract the certificate from Vault response
jq -r .data.certificate ecdsa-384.json > ecdsa-384.cert.pem
# Extract the private key from Vault response
jq -r .data.private_key ecdsa-384.json > ecdsa-384.key.pem

# Issue a certificate from the ECDSA P521 role
vault write -format=json pki_int/issue/ecdsa-521 common_name="${CN_PREFIX}ecdsa-521${CN_SUFFIX}" > ecdsa-521.json
# Extract the certificate from Vault response
jq -r .data.certificate ecdsa-521.json > ecdsa-521.cert.pem
# Extract the private key from Vault response
jq -r .data.private_key ecdsa-521.json > ecdsa-521.key.pem

# Issue a certificate from the Ed25519 role
vault write -format=json pki_int/issue/ed25519 common_name="${CN_PREFIX}ed25519${CN_SUFFIX}" > ed25519.json
# Extract the certificate from Vault response
jq -r .data.certificate ed25519.json > ed25519.cert.pem
# Extract the private key from Vault response
jq -r .data.private_key ed25519.json > ed25519.key.pem

# Write all certs and private keys to kubeneretes secrets
kubectl create secret generic rsa-2048 --from-file=tls.crt=rsa-2048.cert.pem --from-file=tls.key=rsa-2048.key.pem
kubectl create secret generic rsa-4096 --from-file=tls.crt=rsa-4096.cert.pem --from-file=tls.key=rsa-4096.key.pem
kubectl create secret generic ecdsa-256 --from-file=tls.crt=ecdsa-256.cert.pem --from-file=tls.key=ecdsa-256.key.pem
kubectl create secret generic ecdsa-384 --from-file=tls.crt=ecdsa-384.cert.pem --from-file=tls.key=ecdsa-384.key.pem
kubectl create secret generic ecdsa-521 --from-file=tls.crt=ecdsa-521.cert.pem --from-file=tls.key=ecdsa-521.key.pem
kubectl create secret generic ed25519 --from-file=tls.crt=ed25519.cert.pem --from-file=tls.key=ed25519.key.pem

# Write all certs and private keys to kubeneretes tls secrets
kubectl create secret tls tls-rsa-2048 --cert=rsa-2048.cert.pem --key=rsa-2048.key.pem
kubectl create secret tls tls-rsa-4096 --cert=rsa-4096.cert.pem --key=rsa-4096.key.pem
kubectl create secret tls tls-ecdsa-256 --cert=ecdsa-256.cert.pem --key=ecdsa-256.key.pem
kubectl create secret tls tls-ecdsa-384 --cert=ecdsa-384.cert.pem --key=ecdsa-384.key.pem
kubectl create secret tls tls-ecdsa-521 --cert=ecdsa-521.cert.pem --key=ecdsa-521.key.pem
kubectl create secret tls tls-ed25519 --cert=ed25519.cert.pem --key=ed25519.key.pem

# Prompt y/n if you want to delete all generated files then run the following commands
read -p "Do you want to delete all generated files? (y/n) " answer

if [[ $answer =~ ^[Yy]$ ]]; then
    
    echo "Deleting all k8s opa secrets..."
    # Delete all kubernetes secrets
    kubectl delete secret rsa-2048
    kubectl delete secret rsa-4096
    kubectl delete secret ecdsa-256
    kubectl delete secret ecdsa-384
    kubectl delete secret ecdsa-521
    kubectl delete secret ed25519
    
    echo "Deleting all k8s opa tls secrets..."
    # Delete all kubernetes tls secrets
    kubectl delete secret tls-rsa-2048
    kubectl delete secret tls-rsa-4096
    kubectl delete secret tls-ecdsa-256
    kubectl delete secret tls-ecdsa-384
    kubectl delete secret tls-ecdsa-521
    kubectl delete secret tls-ed25519
    
    echo "Deleting all generated files..."
    # Delete all generated files
    rm rsa-2048.cert.pem rsa-2048.key.pem rsa-2048.json
    rm rsa-4096.cert.pem rsa-4096.key.pem rsa-4096.json
    rm ecdsa-256.cert.pem ecdsa-256.key.pem ecdsa-256.json
    rm ecdsa-384.cert.pem ecdsa-384.key.pem ecdsa-384.json
    rm ecdsa-521.cert.pem ecdsa-521.key.pem ecdsa-521.json
    rm ed25519.cert.pem ed25519.key.pem ed25519.json
    
    echo "Completed. All generated files are deleted."
else
    echo "Completed. All generated files are in the current directory $(pwd)."
fi




 