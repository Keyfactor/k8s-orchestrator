# Keyfactor Kubernetes Orchestrator — Service Account Setup

This document describes how to configure Kubernetes credentials for the Keyfactor Kubernetes Orchestrator Extension.

Two authentication methods are supported. Choose the one that best fits your environment:

| | [Option 1: Service Account Token](#option-1-service-account-token) | [Option 2: Client Certificate](#option-2-client-certificate) | [Option 3: In-Cluster / Pod Identity](#option-3-in-cluster--pod-identity) |
|---|---|---|---|
| Credential type | Long-lived bearer token | X.509 client certificate + private key | Projected SA token (auto-rotated) |
| Expiry | None (static) | Defined by cluster CA policy (typically 1 year) | ~1 hour (rotated automatically by kubelet) |
| K8s object required | `kubernetes.io/service-account-token` Secret | None — cluster CA signs the cert directly | None — mounted automatically into the pod |
| Stored in Command | Yes (bearer token) | Yes (cert + key) | No |
| Rotation | Manual | Manual / via Keyfactor | Fully automatic |
| Requires UO in pod | No | No | Yes — manages its own cluster only |
| Setup complexity | Lower | Slightly higher (CSR approval required) | Medium (UO must be deployed as a K8s pod) |

Both methods produce the same output: a `kubeconfig` JSON file that you paste into the **Server Password** field of your Keyfactor Command certificate store definition.

---

## Pre-requisites (both options)

- A Kubernetes cluster with RBAC enabled
- `kubectl` installed and configured to connect to the cluster
- `jq` installed
- Cluster permissions to create ClusterRoles and ClusterRoleBindings

---

## Option 1: Service Account Token

Credentials are a long-lived bearer token stored in a `kubernetes.io/service-account-token` Secret. This Secret must be explicitly created — since Kubernetes v1.22, service accounts no longer receive one automatically.

### Files

| File | Purpose |
|------|---------|
| `kubernetes_svc_account.yaml` | Creates the ServiceAccount, ClusterRole, ClusterRoleBinding, and token Secret |
| `create_service_account.sh` | Applies the YAML and builds the kubeconfig in one step |
| `get_service_account_creds.sh` | Builds the kubeconfig from an existing service account and token Secret |
| `example_kubeconfig.json` | Example output format |

### Quickstart

```bash
bash <(curl -s https://raw.githubusercontent.com/Keyfactor/k8s-orchestrator/main/scripts/kubernetes/create_service_account.sh)
```

> **Note:** If you have more than one cluster in your kubeconfig, you may need to change the cluster array index (default: `0`) in the script.

### Manual steps

```bash
git clone https://github.com/Keyfactor/k8s-orchestrator.git
cd k8s-orchestrator/scripts/kubernetes

# Review and edit if needed, then apply
kubectl apply -f kubernetes_svc_account.yaml

# Build the kubeconfig
./get_service_account_creds.sh
```

`get_service_account_creds.sh` prompts for the service account name, namespace, cluster name, and API server URL, then writes `<sa-name>-context.json`.

### How it works

`kubernetes_svc_account.yaml` creates four resources:

1. A `ServiceAccount` named `keyfactor-orchestrator-sa`
2. A `ClusterRole` named `keyfactor-orchestrator` with the required permissions
3. A `ClusterRoleBinding` that grants the ClusterRole to the ServiceAccount
4. A `kubernetes.io/service-account-token` Secret with an annotation pointing to the ServiceAccount — Kubernetes populates `.data.token` automatically

`get_service_account_creds.sh` reads that token and builds a kubeconfig file.

### Example kubeconfig

[example_kubeconfig.json](example_kubeconfig.json)

```json
{
  "kind": "Config",
  "apiVersion": "v1",
  "clusters": [{ "name": "my-cluster", "cluster": { "server": "https://my.cluster.domain:443", "certificate-authority-data": "<base64 CA cert>" } }],
  "users": [{ "name": "keyfactor-orchestrator-sa", "user": { "token": "<service account bearer token>" } }],
  "contexts": [{ "name": "keyfactor-orchestrator-sa-context", "context": { "cluster": "my-cluster", "user": "keyfactor-orchestrator-sa", "namespace": "default" } }],
  "current-context": "keyfactor-orchestrator-sa-context"
}
```

---

## Option 2: Client Certificate

Credentials are an X.509 client certificate and private key signed by the cluster CA. The certificate CN is used as the Kubernetes user identity for RBAC — no ServiceAccount object is needed.

### Files

| File | Purpose |
|------|---------|
| `kubernetes_svc_account_cert_auth.yaml` | Creates the ClusterRole and ClusterRoleBinding for the certificate user |
| `generate_client_cert_creds.sh` | End-to-end: RBAC, key gen, CSR submission, approval, kubeconfig build |
| `example_kubeconfig_cert.json` | Example output format |

### Additional pre-requisites

- `openssl`
- **Cluster-admin** permissions (required to approve the CertificateSigningRequest)

### Quickstart

```bash
git clone https://github.com/Keyfactor/k8s-orchestrator.git
cd k8s-orchestrator/scripts/kubernetes
chmod +x generate_client_cert_creds.sh
./generate_client_cert_creds.sh
```

The script writes `keyfactor-orchestrator-context.json` on completion. Paste its contents into the **Server Password** field in Keyfactor Command.

### Configuration

All parameters have defaults and can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `K8S_USER_NAME` | `keyfactor-orchestrator` | CN for the client certificate and RBAC subject |
| `K8S_NAMESPACE` | `default` | Namespace written into the kubeconfig context |
| `K8S_CLUSTER_NAME` | `kubernetes` | Cluster name written into the kubeconfig |
| `K8S_CLUSTER_API_SERVER` | *(from current kubectl context)* | API server URL |
| `K8S_KEY_SIZE` | `4096` | RSA key size in bits |

Example with overrides:

```bash
K8S_USER_NAME=kf-orchestrator \
K8S_NAMESPACE=cert-management \
K8S_CLUSTER_NAME=prod-cluster \
./generate_client_cert_creds.sh
```

> **Important:** If you change `K8S_USER_NAME`, the script automatically uses that CN in both the certificate and the RBAC binding. The two must always match — if you later apply `kubernetes_svc_account_cert_auth.yaml` manually, update `subjects[0].name` in that file to match.

### What the script does

1. Applies a `ClusterRole` and `ClusterRoleBinding` binding to the certificate CN as a Kubernetes User
2. Generates an RSA private key (`<user>.key`)
3. Creates a CSR with `CN=<user>` and `O=keyfactor` (`<user>.csr`)
4. Submits the CSR as a `certificates.k8s.io/v1` CertificateSigningRequest resource
5. Approves the CSR (`kubectl certificate approve`)
6. Waits for the cluster CA to issue the signed certificate
7. Builds a kubeconfig with `client-certificate-data` and `client-key-data`
8. Verifies connectivity by listing secrets in the configured namespace
9. Removes the intermediate `.csr` file

> **Certificate validity:** The script requests a 1-year certificate (`expirationSeconds: 31536000`). The actual validity is determined by the cluster's CA policy and may differ. Check expiry with `openssl x509 -in keyfactor-orchestrator.crt -noout -dates`.

> **Security note:** `<user>.key` and `<user>.crt` are written to disk during the process and the private key is also embedded in the output JSON. Delete both files after confirming the kubeconfig works.

### Manual steps (without the script)

If you prefer to run each step yourself:

```bash
# 1. Apply RBAC
kubectl apply -f kubernetes_svc_account_cert_auth.yaml

# 2. Generate private key and CSR
openssl genrsa -out keyfactor-orchestrator.key 4096
openssl req -new -key keyfactor-orchestrator.key \
  -subj "/CN=keyfactor-orchestrator/O=keyfactor" \
  -out keyfactor-orchestrator.csr

# 3. Submit the CSR to Kubernetes
kubectl apply -f - <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: keyfactor-orchestrator-keyfactor-csr
spec:
  request: $(base64 < keyfactor-orchestrator.csr | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 31536000
  usages:
    - client auth
EOF

# 4. Approve the CSR
kubectl certificate approve keyfactor-orchestrator-keyfactor-csr

# 5. Extract the signed certificate
kubectl get csr keyfactor-orchestrator-keyfactor-csr \
  -o jsonpath='{.status.certificate}' | base64 --decode > keyfactor-orchestrator.crt

# 6. Build the kubeconfig (see example_kubeconfig_cert.json for the structure)
#    Embed the base64-encoded cert and key as client-certificate-data and client-key-data
```

### Example kubeconfig

[example_kubeconfig_cert.json](example_kubeconfig_cert.json)

```json
{
  "kind": "Config",
  "apiVersion": "v1",
  "clusters": [{ "name": "my-cluster", "cluster": { "server": "https://my.cluster.domain:443", "certificate-authority-data": "<base64 CA cert>" } }],
  "users": [{ "name": "keyfactor-orchestrator", "user": { "client-certificate-data": "<base64 client cert>", "client-key-data": "<base64 private key>" } }],
  "contexts": [{ "name": "keyfactor-orchestrator-context", "context": { "cluster": "my-cluster", "user": "keyfactor-orchestrator", "namespace": "default" } }],
  "current-context": "keyfactor-orchestrator-context"
}
```

---

## Option 3: In-Cluster / Pod Identity

When the Universal Orchestrator runs as a pod inside the Kubernetes cluster it is managing, it can authenticate using the **projected service account token** that kubelet automatically mounts into the pod. No credentials are stored in Keyfactor Command for this cluster — the token is rotated every hour without any intervention.

> **Scope:** This option manages only the cluster the UO pod runs in. To manage additional clusters from the same UO, provide a kubeconfig in the Server Password field for those store definitions as usual (Options 1 or 2).

### Files

| File | Purpose |
|------|---------|
| `kubernetes_svc_account.yaml` | Creates the ServiceAccount and RBAC (same as Option 1) |
| `keyfactor-orchestrator-deployment.yaml` | Kubernetes `Deployment` manifest for the UO pod |

### How it works

1. Apply `kubernetes_svc_account.yaml` — this creates the `keyfactor-orchestrator-sa` ServiceAccount and grants it the required ClusterRole.
2. Deploy the UO using `keyfactor-orchestrator-deployment.yaml`. The pod runs with `serviceAccountName: keyfactor-orchestrator-sa`.
3. kubelet mounts a short-lived projected token at `/var/run/secrets/kubernetes.io/serviceaccount/token` and rotates it automatically.
4. The plugin detects the `KUBERNETES_SERVICE_HOST` environment variable (set in every pod by Kubernetes) and calls `KubernetesClientConfiguration.InClusterConfig()` when no kubeconfig is provided.
5. In Keyfactor Command, leave **Server Password blank** for certificate stores in this cluster — no kubeconfig needed.

### Setup

```bash
# 1. Create the ServiceAccount and RBAC
kubectl apply -f kubernetes_svc_account.yaml

# 2. Edit keyfactor-orchestrator-deployment.yaml and replace all <PLACEHOLDER> values

# 3. Deploy the orchestrator
kubectl apply -f keyfactor-orchestrator-deployment.yaml

# 4. Verify the pod is running
kubectl get pods -l app=keyfactor-orchestrator

# 5. Check the logs to confirm in-cluster auth was detected
kubectl logs -l app=keyfactor-orchestrator | grep -i "in-cluster"
```

### Configuring certificate stores in Command

For stores in **this cluster** (the one the UO pod runs in):

- **Server Username:** `kubeconfig`
- **Server Password:** *(leave blank — select "No value" in the Command UI)*

For stores in **other clusters**, provide a kubeconfig JSON as normal (Options 1 or 2).

### Notes

- `replicas: 1` is required — the UO is stateful and must not be scaled horizontally.
- The projected token is audience-bound to the kube-apiserver and cannot be used outside the cluster.
- Resource requests/limits in the deployment manifest are starting points — adjust for your workload.
- The `KEYFACTOR_ORCHESTRATOR_NAME` value must match the orchestrator name registered in Keyfactor Command.

---

## Providing credentials to Keyfactor Command

For Options 1 and 2, provide the output JSON file the same way:

- **Server Username:** `kubeconfig`
- **Server Password:** paste the full contents of the `*-context.json` file

For Option 3 (in-cluster), leave **Server Password blank** (select "No value" in the Command UI) for stores in the UO's own cluster.

This applies to both certificate store definitions and discovery job configurations.
