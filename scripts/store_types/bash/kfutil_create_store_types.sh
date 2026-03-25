#!/usr/bin/env bash

# Creates all 7 Kubernetes Orchestrator store types using kfutil.
# kfutil reads store type definitions from the Keyfactor integration catalog.
#
# Prerequisites:
#   - kfutil installed: https://github.com/Keyfactor/kfutil#quickstart
#   - Auth environment variables (see README.md for options)
#
# Auto-generated from integration-manifest.json — do not edit by hand.
# Regenerate with: make store-types-gen-scripts

if ! command -v kfutil &> /dev/null; then
    echo "kfutil could not be found. Please install kfutil"
    echo "See the official docs: https://github.com/Keyfactor/kfutil#quickstart"
    exit 1
fi

if [ -z "$KEYFACTOR_HOSTNAME" ]; then
    echo "KEYFACTOR_HOSTNAME not set — launching kfutil login"
    kfutil login
fi

kfutil store-types create --name "K8SCert"
kfutil store-types create --name "K8SCluster"
kfutil store-types create --name "K8SJKS"
kfutil store-types create --name "K8SNS"
kfutil store-types create --name "K8SPKCS12"
kfutil store-types create --name "K8SSecret"
kfutil store-types create --name "K8STLSSecr"

echo "Done. All store types created."
