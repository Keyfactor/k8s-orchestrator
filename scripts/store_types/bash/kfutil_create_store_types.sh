#!/usr/bin/env bash

#export KEYFACTOR_USERNAME="<your username>"
#export KEYFACTOR_PASSWORD="<your password>"
#export KEYFACTOR_HOSTNAME="<your Keyfactor command hostname>"
#export KEYFACTOR_DOMAIN="<your AD domain name>"

# Check kfutil is installed
if ! command -v kfutil &> /dev/null
then
    echo "kfutil could not be found. Please install kfutil"
    echo "See the official docs: https://github.com/Keyfactor/kfutil#quickstart"
    # Check if kfutil deps are already installed and if they are then provide the command to install kfutil from GitHub.
    if command -v gh &> /dev/null || command -v zip &> /dev/null || command -v unzip &> /dev/null;
    then
        echo "To install kfutil, run the following command:"
        echo "bash <(curl -s https://raw.githubusercontent.com/Keyfactor/kfutil/main/gh-dl-release.sh)"
    fi
fi

# Check environment variables are set
if [ -z "$KEYFACTOR_USERNAME" ] || [ -z "$KEYFACTOR_PASSWORD" ] || [ -z "$KEYFACTOR_HOSTNAME" ] || [ -z "$KEYFACTOR_DOMAIN" ]; then
    echo "Please set the environment variables KEYFACTOR_USERNAME, KEYFACTOR_PASSWORD, KEYFACTOR_HOSTNAME and KEYFACTOR_DOMAIN"
    kfutil login 
fi

kfutil store-types create --name "K8SCert"
kfutil store-types create --name "K8SSecret"
kfutil store-types create --name "K8STLSSecr"