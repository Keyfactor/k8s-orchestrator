#!/usr/bin/env bash

export JKS_ALIAS_NAME=myalias2
export JKS_KEYSTORE_NAME=keystore.jks
export JKS_KEYSTORE_PASSWORD=changeit

export OUTPUT_CERT_NAME=certificate.crt
export OUTPUT_KEY_NAME=private.key
export OUTPUT_CSR_NAME=csr.csr
export OUTPUT_P12_NAME=keystore.p12

export VERIFY_CERT_NAME=certificate.pem
export VERIFY_DER_NAME=certificate.der
export VERIFY_KEY_NAME=privatekey.pem

export K8S_SECRET_NAME=mysecret


function generateKeyPair(){
  echo "Generating private and certificate"
  openssl genpkey -algorithm RSA -out $OUTPUT_KEY_NAME
  openssl req -new -key private.key -out $OUTPUT_CSR_NAME
  openssl x509 -req -days 365 -in $OUTPUT_CSR_NAME -signkey $OUTPUT_KEY_NAME -out $OUTPUT_CERT_NAME  
}


function generateJKS(){
  echo "Generating JKS keystore"
  keytool -genkey -alias $JKS_ALIAS_NAME -keyalg RSA -keystore $JKS_KEYSTORE_NAME
  keytool -import -alias $JKS_ALIAS_NAME -file $OUTPUT_CERT_NAME -keystore $JKS_KEYSTORE_NAME
  
  keytool -list -v -keystore $JKS_KEYSTORE_NAME  
}


function verifyJKSContents(){
  keytool -export -alias $JKS_ALIAS_NAME -file $VERIFY_DER_NAME -keystore $JKS_KEYSTORE_NAME
  openssl x509 -inform DER -in $VERIFY_DER_NAME -out $VERIFY_CERT_NAME
  
  keytool -importkeystore -srckeystore $JKS_KEYSTORE_NAME -destkeystore $OUTPUT_P12_NAME -srcstoretype JKS -deststoretype PKCS12
  openssl pkcs12 -in $OUTPUT_P12_NAME -nodes -nocerts -out $VERIFY_KEY_NAME  
  
  # Compare contents of $OUTPUT_CERT_NAME and $VERIFY_CERT_NAME
  # Compare contents of $OUTPUT_KEY_NAME and $VERIFY_KEY_NAME
  diff $OUTPUT_CERT_NAME $VERIFY_CERT_NAME && echo "Certificate contents match" || echo "Certificate contents do not match"
  diff $OUTPUT_KEY_NAME $VERIFY_KEY_NAME && echo "Key contents match" || echo "Key contents do not match"
  
}

function writeK8SSecret(){
  echo "Writing K8S secret"
  kubectl create secret generic $K8S_SECRET_NAME --from-file=$JKS_KEYSTORE_NAME --from-literal=password=$JKS_KEYSTORE_PASSWORD
}

function deleteK8SSecret(){
  echo "Deleting K8S secret"
  kubectl delete secret $K8S_SECRET_NAME
}


#generateKeyPair
#generateJKS
#verifyJKSContents
writeK8SSecret
#deleteK8SSecret


