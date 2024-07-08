#!/usr/bin/env bash

function updateFromCommandInstance() {
  kfutil store-types get --name K8SCLUSTER --output-to-integration-manifest
  kfutil store-types get --name K8SNS --output-to-integration-manifest
  kfutil store-types get --name K8SJKS --output-to-integration-manifest
  kfutil store-types get --name K8SPKCS12 --output-to-integration-manifest
  kfutil store-types get --name K8STLSSecr --output-to-integration-manifest
  kfutil store-types get --name K8SSecret --output-to-integration-manifest
  kfutil store-types get --name K8SCert --output-to-integration-manifest  
}

function integrationManifestToFiles(){
  store_types_length=$(jq '.about.orchestrator.store_types | length' integration-manifest.json)
  
  for (( i=0; i<$store_types_length; i++ ))
  do
    short_name=$(jq -r ".about.orchestrator.store_types[$i].ShortName" integration-manifest.json)
    jq ".about.orchestrator.store_types[$i]" integration-manifest.json > "$short_name.json"
  done
}

integrationManifestToFiles