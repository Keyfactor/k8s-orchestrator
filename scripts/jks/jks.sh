#!/usr/bin/env bash

export JKS_ALIAS_NAME=jks-unit-01
export JKS_ALIAS_NAME2=jks-unit-02
export JKS_KEYSTORE_NAME=keystore.jks
export JKS_P12_KEYSTORE_NAME=keystore.p12
export JKS_KEYSTORE_PASSWORD="changeme!"

export OUTPUT_CERT_NAME=certificate.crt
export OUTPUT_KEY_NAME=private.key
export OUTPUT_CSR_NAME=csr.csr
export OUTPUT_P12_NAME=keystore.p12

export VERIFY_CERT_NAME=certificate.pem
export VERIFY_DER_NAME=certificate.der
export VERIFY_KEY_NAME=privatekey.pem

export K8S_SECRET_NAME=jks-unit-01


function generateKeyPair(){
  echo "Generating private and certificate"
  openssl genpkey -algorithm RSA -out $OUTPUT_KEY_NAME
  openssl req -new -key private.key -out $OUTPUT_CSR_NAME -subj "/CN=$JKS_ALIAS_NAME2/OU=Integrations/O=Keyfactor/L=Providence/ST=OH/C=US"
  openssl x509 -req -days 365 -in $OUTPUT_CSR_NAME -signkey $OUTPUT_KEY_NAME -out $OUTPUT_CERT_NAME 
}


function generateJKS(){
  echo "Generating JKS keystore"
  keytool -genkey -alias $JKS_ALIAS_NAME -keyalg RSA -keystore $JKS_P12_KEYSTORE_NAME -storepass $JKS_KEYSTORE_PASSWORD -keypass $JKS_KEYSTORE_PASSWORD -dname "CN=$JKS_ALIAS_NAME, OU=Integrations, O=Keyfactor, L=Providence, ST=OH, C=US"
  keytool -import -alias $JKS_ALIAS_NAME -file $OUTPUT_CERT_NAME -keystore $JKS_P12_KEYSTORE_NAME -storepass $JKS_KEYSTORE_PASSWORD -keypass $JKS_KEYSTORE_PASSWORD -noprompt
  
  keytool -list -v -keystore $JKS_P12_KEYSTORE_NAME -storepass $JKS_KEYSTORE_PASSWORD -keypass $JKS_KEYSTORE_PASSWORD 
}


function generateLegacyJks(){
  echo "Generating Legacy JKS keystore"
  keytool -importkeystore \
    -srckeystore $JKS_P12_KEYSTORE_NAME \
    -destkeystore $JKS_KEYSTORE_NAME \
    -srcstoretype PKCS12 \
    -deststoretype JKS \
    -srcstorepass $JKS_KEYSTORE_PASSWORD \
    -deststorepass $JKS_KEYSTORE_PASSWORD \
    -noprompt
  openssl pkcs12 \
    -in $OUTPUT_P12_NAME \
    -nodes -nocerts \
    -out $OUTPUT_KEY_NAME  \
    -passin pass:$JKS_KEYSTORE_PASSWORD
  openssl pkcs12 \
    -in $OUTPUT_P12_NAME \
    -nokeys \
    -out $OUTPUT_CERT_NAME \
    -passin pass:$JKS_KEYSTORE_PASSWORD
}

function verifyJKSContents(){
  keytool -export -alias $JKS_ALIAS_NAME -file $VERIFY_DER_NAME -keystore $JKS_KEYSTORE_NAME -storepass $JKS_KEYSTORE_PASSWORD -keypass $JKS_KEYSTORE_PASSWORD -noprompt
  openssl x509 -inform DER -in $VERIFY_DER_NAME -out $VERIFY_CERT_NAME 
  
  keytool \
    -importkeystore \
    -srckeystore $JKS_KEYSTORE_NAME \
    -destkeystore $OUTPUT_P12_NAME \
    -srcstoretype JKS \
    -deststoretype PKCS12 \
    -srcstorepass $JKS_KEYSTORE_PASSWORD \
    -deststorepass $JKS_KEYSTORE_PASSWORD \
    -noprompt
  openssl pkcs12 \
    -in $OUTPUT_P12_NAME \
    -nodes -nocerts \
    -out $VERIFY_KEY_NAME  \
    -passin pass:$JKS_KEYSTORE_PASSWORD
  
  cat $VERIFY_CERT_NAME
  # Compare contents of $OUTPUT_CERT_NAME and $VERIFY_CERT_NAME
  # Compare contents of $OUTPUT_KEY_NAME and $VERIFY_KEY_NAME
  #  diff $OUTPUT_CERT_NAME $VERIFY_CERT_NAME \
  #    && echo "Certificate contents match" || echo "Certificate contents do not match"
  #  diff $OUTPUT_KEY_NAME $VERIFY_KEY_NAME \
  #    && echo "Key contents match" || echo "Key contents do not match"
  
}

function writeK8SSecret(){
  echo "Writing K8S secret"
  kubectl create secret generic $K8S_SECRET_NAME \
    --from-file=$JKS_KEYSTORE_NAME \
    --from-literal=password=$JKS_KEYSTORE_PASSWORD
}

function cleanUp(){
  echo "Deleting K8S secret"
  kubectl delete secret $K8S_SECRET_NAME
#  rm $JKS_KEYSTORE_NAME
#  rm $OUTPUT_CERT_NAME
#  rm $OUTPUT_KEY_NAME
#  rm $OUTPUT_CSR_NAME
#  rm $OUTPUT_P12_NAME
#  rm $VERIFY_CERT_NAME
#  rm $VERIFY_DER_NAME
#  rm $VERIFY_KEY_NAME
}


function addAdditionalCert(){
  echo "Creating keypair"
  generateKeyPair
  echo "Adding additional cert"
  keytool -import -alias $JKS_ALIAS_NAME2 -file $OUTPUT_CERT_NAME -keystore $JKS_KEYSTORE_NAME -storepass $JKS_KEYSTORE_PASSWORD -keypass $JKS_KEYSTORE_PASSWORD -noprompt
}

function getK8SJksData(){
#  echo "Getting K8S secret"
  kubectl get secret $K8S_SECRET_NAME --output json | jq -r '.data."keystore.jks"' | base64 -d > fromK8S.jks
  keytool -list -v -keystore fromK8S.jks -storepass $JKS_KEYSTORE_PASSWORD -keypass $JKS_KEYSTORE_PASSWORD
}

cleanUp
#generateKeyPair
generateJKS
generateLegacyJks
addAdditionalCert
#verifyJKSContents
writeK8SSecret
#getK8SJksData


