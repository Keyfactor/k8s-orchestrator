#!/usr/bin/env bash
# Generates a client certificate kubeconfig for the Keyfactor Kubernetes Orchestrator Extension.
#
# This script:
#   1. Applies RBAC (ClusterRole + ClusterRoleBinding) for the orchestrator user
#   2. Generates an RSA private key
#   3. Creates and submits a Kubernetes CertificateSigningRequest
#   4. Approves the CSR (requires cluster-admin)
#   5. Builds a kubeconfig with client-certificate-data / client-key-data
#   6. Verifies connectivity
#
# Requirements:
#   - kubectl configured to connect to the target cluster with cluster-admin permissions
#   - openssl
#   - jq
#   - base64 (standard on Linux/macOS)
#
# Environment variable overrides (all optional):
#   K8S_USER_NAME          - CN for the client certificate and RBAC user  (default: keyfactor-orchestrator)
#   K8S_NAMESPACE          - Namespace for the kubeconfig context          (default: default)
#   K8S_CLUSTER_NAME       - Cluster name written into the kubeconfig      (default: kubernetes)
#   K8S_CLUSTER_API_SERVER - API server URL                                (default: from current kubectl context)
#   K8S_KEY_SIZE           - RSA key size in bits                          (default: 4096)
set -euo pipefail

USER_NAME="${K8S_USER_NAME:-keyfactor-orchestrator}"
NAMESPACE="${K8S_NAMESPACE:-default}"
CLUSTER_NAME="${K8S_CLUSTER_NAME:-kubernetes}"
CLUSTER_API_SERVER="${K8S_CLUSTER_API_SERVER:-$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')}"
KEY_SIZE="${K8S_KEY_SIZE:-4096}"
CSR_K8S_NAME="${USER_NAME}-keyfactor-csr"
OUTPUT_FILE="${USER_NAME}-context.json"

echo "USER_NAME:          $USER_NAME"
echo "NAMESPACE:          $NAMESPACE"
echo "CLUSTER_NAME:       $CLUSTER_NAME"
echo "CLUSTER_API_SERVER: $CLUSTER_API_SERVER"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Apply RBAC
# ---------------------------------------------------------------------------
echo "==> Step 1: Applying RBAC (ClusterRole + ClusterRoleBinding for user '${USER_NAME}')..."
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keyfactor-orchestrator
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: []
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["certificates.k8s.io"]
    resources: ["certificatesigningrequests"]
    resourceNames: []
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: keyfactor-orchestrator-cert-binding
roleRef:
  kind: ClusterRole
  name: keyfactor-orchestrator
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: User
    name: ${USER_NAME}
    apiGroup: rbac.authorization.k8s.io
EOF

# ---------------------------------------------------------------------------
# Step 2: Generate private key
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 2: Generating ${KEY_SIZE}-bit RSA private key..."
openssl genrsa -out "${USER_NAME}.key" "$KEY_SIZE" 2>/dev/null
echo "    Written to ${USER_NAME}.key"

# ---------------------------------------------------------------------------
# Step 3: Generate CSR
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 3: Generating certificate signing request (CN=${USER_NAME}, O=keyfactor)..."
openssl req -new \
  -key "${USER_NAME}.key" \
  -subj "/CN=${USER_NAME}/O=keyfactor" \
  -out "${USER_NAME}.csr"
echo "    Written to ${USER_NAME}.csr"

# ---------------------------------------------------------------------------
# Step 4: Submit CSR to Kubernetes
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 4: Submitting CSR to Kubernetes as '${CSR_K8S_NAME}'..."
kubectl delete csr "$CSR_K8S_NAME" --ignore-not-found=true
kubectl apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${CSR_K8S_NAME}
spec:
  request: $(base64 < "${USER_NAME}.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 31536000
  usages:
    - client auth
EOF

# ---------------------------------------------------------------------------
# Step 5: Approve CSR
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 5: Approving CSR (requires cluster-admin)..."
kubectl certificate approve "$CSR_K8S_NAME"

# ---------------------------------------------------------------------------
# Step 6: Wait for the signed certificate
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 6: Waiting for signed certificate..."
CERT=""
for i in $(seq 1 15); do
  CERT=$(kubectl get csr "$CSR_K8S_NAME" -o jsonpath='{.status.certificate}' 2>/dev/null || true)
  if [ -n "$CERT" ]; then
    echo "    Certificate issued."
    break
  fi
  echo "    Waiting... (attempt $i/15)"
  sleep 2
done

if [ -z "$CERT" ]; then
  echo ""
  echo "ERROR: Certificate was not issued after waiting. Check CSR status with:"
  echo "  kubectl describe csr $CSR_K8S_NAME"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 7: Save certificate and display details
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 7: Saving signed certificate..."
echo "$CERT" | base64 --decode > "${USER_NAME}.crt"
echo "    Written to ${USER_NAME}.crt"
echo ""
openssl x509 -in "${USER_NAME}.crt" -noout -subject -dates
echo ""

# ---------------------------------------------------------------------------
# Step 8: Build kubeconfig
# ---------------------------------------------------------------------------
echo "==> Step 8: Building kubeconfig..."
CA_CERT=$(kubectl config view --raw -o json | jq -r '.clusters[0].cluster."certificate-authority-data"')
CLIENT_CERT_DATA=$(base64 < "${USER_NAME}.crt" | tr -d '\n')
CLIENT_KEY_DATA=$(base64 < "${USER_NAME}.key" | tr -d '\n')

cat > kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- name: ${CLUSTER_NAME}
  cluster:
    server: ${CLUSTER_API_SERVER}
    certificate-authority-data: ${CA_CERT}
contexts:
- name: ${USER_NAME}-context
  context:
    cluster: ${CLUSTER_NAME}
    namespace: ${NAMESPACE}
    user: ${USER_NAME}
current-context: ${USER_NAME}-context
users:
- name: ${USER_NAME}
  user:
    client-certificate-data: ${CLIENT_CERT_DATA}
    client-key-data: ${CLIENT_KEY_DATA}
EOF

kubectl config view --raw -o json --kubeconfig=kubeconfig > "${OUTPUT_FILE}"
echo "    Written to ${OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# Step 9: Verify connectivity
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 9: Verifying connectivity..."
if kubectl get secrets -n "$NAMESPACE" --kubeconfig=kubeconfig > /dev/null 2>&1; then
  echo "    OK — orchestrator user can list secrets in namespace '${NAMESPACE}'."
else
  echo "    WARNING: Could not list secrets in namespace '${NAMESPACE}'."
  echo "    Check RBAC and cluster connectivity before using this kubeconfig."
fi

# ---------------------------------------------------------------------------
# Step 10: Cleanup intermediate files
# ---------------------------------------------------------------------------
echo ""
echo "==> Step 10: Cleaning up..."
rm -f "${USER_NAME}.csr"
echo "    Removed ${USER_NAME}.csr"

echo ""
echo "SECURITY NOTE: ${USER_NAME}.key contains the unencrypted private key."
echo "  The key is also embedded in ${OUTPUT_FILE} as 'client-key-data'."
echo "  Delete ${USER_NAME}.key and ${USER_NAME}.crt once you have confirmed"
echo "  the kubeconfig is working."
echo ""
echo "Done! Copy the contents of ${OUTPUT_FILE} as the 'ServerPassword' value"
echo "in your Keyfactor Command certificate store definition."
