#!/usr/bin/env bash
# Convert YAML to JSON
# Usage: yaml2json.sh <yaml-file>
# Example: yaml2json.sh tests.yaml > tests.json
yq -p yaml -o json "$1"