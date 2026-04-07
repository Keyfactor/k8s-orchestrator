# Makefile Reference Guide

This guide documents all available Make targets for the Kubernetes Orchestrator Extension project.

## Quick Reference

| Category | Common Targets |
|----------|---------------|
| **Build** | `make build` |
| **Testing** | `make test-unit`, `make test-integration`, `make test` |
| **Coverage** | `make test-coverage-unit`, `make test-coverage-open` |
| **Debugging** | `make debug-loop`, `make debug-logs` |
| **OAuth** | `make token`, `make token-show` |
| **API** | `make api-list-stores`, `make api-list-certs` |

Run `make help` to see all available targets with descriptions.

---

## General

### `make help`
Display all available targets organized by category with descriptions.

### `make all` (default)
Alias for `make build`.

---

## Development

### `make setup`
Interactive setup wizard that creates environment configuration files:
- Creates `.test.env` with Azure-related environment variables
- Creates `.env` with project configuration

### `make reset`
Removes `.env` and `test.env` files to reset the development environment.

### `make newtest`
Creates a new xUnit test project linked to the main project.

### `make installpackage`
Interactive helper to install a NuGet package into a selected project.

---

## Testing

### Unit Tests

#### `make test-unit`
Run all unit tests (excludes integration tests).
```bash
make test-unit
```

### Integration Tests

Integration tests require:
- A Kubernetes cluster accessible via `~/.kube/config`
- Cluster permissions to create/delete namespaces and secrets

#### `make test-integration`
Run all integration tests on both frameworks (net8.0 and net10.0).
```bash
make test-integration
```

#### `make test-integration-fast`
Run integration tests on net8.0 only (~50% faster).
```bash
make test-integration-fast
```

#### `make test-integration-full`
Run integration tests on all frameworks (explicit target for clarity).

#### `make test-integration-smoke-net10`
Run a subset of Inventory tests on net10.0 only for quick validation.

#### `make test-integration-no-cleanup`
Run integration tests without cleaning up secrets afterward. Useful for manual inspection of created resources.

### Store-Type Specific Tests

Run integration tests for a specific certificate store type:

| Target | Store Type | Description |
|--------|------------|-------------|
| `make test-store-jks` | K8SJKS | Java Keystores |
| `make test-store-pkcs12` | K8SPKCS12 | PKCS12/PFX files |
| `make test-store-secret` | K8SSecret | Opaque secrets |
| `make test-store-tls` | K8STLSSecr | TLS secrets |
| `make test-store-cluster` | K8SCluster | Cluster-wide management |
| `make test-store-ns` | K8SNS | Namespace-level management |
| `make test-store-cert` | K8SCert | Certificate Signing Requests |

#### `make test-store-type STORE=<type>`
Run tests for a specific store type with cleanup:
```bash
make test-store-type STORE=K8SSecret
make test-store-type STORE=K8STLSSecr
```

### Combined/CI Tests

#### `make testall`
Run all tests (unit + integration).

#### `make test-all-with-cleanup`
Run all tests with cluster cleanup before and after.

#### `make test-ci`
CI-optimized test runner:
- On `main` branch: runs full integration tests
- On PR branches: runs fast tests + net10.0 smoke tests

### Utilities

#### `make test`
Interactive single test selection using `fzf`. Select a test from the list to run it with detailed output.

#### `make test-watch`
Run tests in watch mode - automatically re-runs tests when files change.

### Code Coverage

#### `make test-coverage`
Run all tests (unit + integration) with code coverage and generate an HTML report.
```bash
make test-coverage
# Report generated at ./coverage/html/index.html
```

#### `make test-coverage-unit`
Run unit tests only with code coverage (faster, excludes integration tests).
```bash
make test-coverage-unit
# Report generated at ./coverage/unit/html/index.html
```

#### `make test-coverage-summary`
Display coverage summary in the terminal (requires running coverage first).
```bash
make test-coverage-unit
make test-coverage-summary
```

#### `make test-coverage-open`
Open the HTML coverage report in your browser (macOS).
```bash
make test-coverage-open
```

#### `make test-coverage-clean`
Remove all coverage reports and artifacts.
```bash
make test-coverage-clean
```

### Utilities

#### `make test-cluster-setup`
Display instructions for setting up the test Kubernetes cluster, including:
- Current kubectl context
- Available contexts
- Test namespace information

#### `make test-cluster-cleanup`
Clean up all test namespaces and CSRs from the cluster:
- `keyfactor-k8sjks-integration-tests`
- `keyfactor-k8spkcs12-integration-tests`
- `keyfactor-k8ssecret-integration-tests`
- `keyfactor-k8stlssecr-integration-tests`
- `keyfactor-k8scluster-test-ns1`, `keyfactor-k8scluster-test-ns2`
- `keyfactor-k8sns-integration-tests`
- `keyfactor-k8scert-integration-tests`
- `keyfactor-manual-test`

---

## OAuth Token Management

OAuth tokens are cached to `.oauth_token` for 50 minutes (3000 seconds) to reduce authentication requests.

### `make token`
Get an OAuth token. Uses cached token if valid, otherwise fetches a new one.
```bash
make token
# Output: Using cached token (expires in 45 minutes)
# eyJhbGciOiJS...
```

### `make token-refresh`
Force refresh the OAuth token and cache it.

### `make token-show`
Display cached token status without exposing the full token:
```bash
make token-show
# Token status: VALID
# Expires in: 45 minutes
# Token preview: eyJhbGciOiJSUzI1Ni...
```

### `make token-clear`
Clear the cached OAuth token.

### `make token-get`
Get token silently (for use in scripts). Returns just the token string.

---

## Keyfactor Command API

These targets interact with the Keyfactor Command API using cached OAuth tokens.

### `make api-list-stores`
List all certificate stores from Command:
```bash
make api-list-stores
# e523b800-fe18-4e68-b7be-8f2034ffdc16 | k8s-agent | manual-tlssecr
# 27b16153-742c-4b4c-9b2d-02ec9cc90fa5 | k8s-agent | manual-opaque
```

### `make api-list-certs`
List first 20 certificates from Command:
```bash
make api-list-certs
# 43 | meow | F3127840482241A1251498545A598C6D765BA03E | HasKey=true
# 44 | ec-csr | FA3BFCD6966AC297B1A3AA9FA43EB1C55EE1048B | HasKey=false
```

### `make api-get-cert CERT_ID=<id>`
Get detailed certificate information:
```bash
make api-get-cert CERT_ID=43
# {
#   "Id": 43,
#   "Thumbprint": "F3127840482241A1251498545A598C6D765BA03E",
#   "IssuedCN": "meow",
#   "HasPrivateKey": true,
#   "IssuerDN": "CN=Sub-CA",
#   "KeyType": "RSA"
# }
```

### `make api-get-jobs`
List recent orchestrator jobs (last 10):
```bash
make api-get-jobs
# guid-1234 | Management | Completed | 2024-02-25T10:00:00Z
```

---

## Debugging (Container-based Testing)

These targets facilitate debugging the orchestrator extension with a local Keyfactor Command container.

### Configuration Variables

Override these with environment variables or on the command line:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG_ENV_FILE` | `~/.env_ses2541` | Environment file with Keyfactor credentials |
| `DEBUG_CONTAINER_DIR` | `~/Desktop/Container` | Docker compose directory |
| `DEBUG_COMPOSE_FILE` | `docker-compose-ses.yml` | Docker compose file |
| `DEBUG_SERVICE_NAME` | `ses_2541_uo_25_4_oauth` | Container service name |
| `DEBUG_TLS_STORE_ID` | `e523b800-...` | TLS secret store GUID |
| `DEBUG_OPAQUE_STORE_ID` | `27b16153-...` | Opaque secret store GUID |
| `DEBUG_PFX_PASSWORD` | `3ceZRxdQffny` | Default PFX password |
| `DEBUG_CERT_ID` | `44` | Default certificate ID |

### Build & Container Management

#### `make debug-build`
Build the extension and verify the DLL is in the container folder.

#### `make debug-restart`
Restart the orchestrator container (down + up).

#### `make debug-container-id`
Get the current container ID.

### Logs

#### `make debug-logs`
Show last 100 lines of container logs.

#### `make debug-logs-follow`
Follow container logs in real-time (Ctrl+C to stop).

### Scheduling Jobs

#### `make debug-schedule-tls`
Schedule a management job for the TLS secret store using the default certificate.

#### `make debug-schedule-opaque`
Schedule a management job for the Opaque secret store.

#### `make debug-schedule-both`
Schedule jobs for both TLS and Opaque stores.

#### `make debug-schedule-tls-cert CERT_ID=<id> [PFX_PASSWORD=<pwd>]`
Schedule a TLS job with a specific certificate:
```bash
make debug-schedule-tls-cert CERT_ID=43
make debug-schedule-tls-cert CERT_ID=43 PFX_PASSWORD=mypassword
```

### Checking Results

#### `make debug-check-tls-secret`
Check the TLS secret (`manual-tlssecr`) in Kubernetes.

#### `make debug-check-opaque-secret`
Check the Opaque secret (`manual-opaque`) in Kubernetes.

#### `make debug-check-secrets`
Check both TLS and Opaque secrets.

#### `make debug-wait-job`
Wait for jobs to complete (polls logs for completion message).

### Debug Loops (Full Workflows)

These targets run complete debug workflows: build, restart, schedule, wait, check logs and secrets.

#### `make debug-loop`
Full debug loop for TLS store with default certificate.

#### `make debug-loop-both`
Full debug loop for both TLS and Opaque stores.

#### `make debug-loop-cert43`
Full debug loop with certificate 43 (has private key + chain).

#### `make debug-loop-cert44`
Full debug loop with certificate 44 (no private key, DER format).

### Certificate Information

#### `make debug-get-token`
Get OAuth token (alias for `make token-get`).

#### `make debug-get-cert-info CERT_ID=<id>`
Get certificate information from Command:
```bash
make debug-get-cert-info CERT_ID=43
```

---

## Build

### `make build`
Build the entire solution:
```bash
make build
# Builds both net8.0 and net10.0 targets
```

---

## Environment Setup

### Required Files

1. **`.env`** - Project configuration (created by `make setup`)
   ```
   PROJECT_ROOT=/path/to/k8s-orchestrator
   PROJECT_FILE=kubernetes-orchestrator-extension/Keyfactor.Orchestrators.K8S.csproj
   PROJECT_NAME=kubernetes-orchestrator-extension
   ```

2. **`.test.env`** - Test environment variables (created by `make setup`)
   ```bash
   export AZURE_TENANT_ID=...
   export AZURE_CLIENT_SECRET=...
   export AZURE_CLIENT_ID=...
   export AZURE_APP_GATEWAY_RESOURCE_ID=...
   ```

3. **`~/.env_ses2541`** (or custom `DEBUG_ENV_FILE`) - Keyfactor credentials for debugging
   ```bash
   export KEYFACTOR_HOSTNAME=my.keyfactor.kfdelivery.com
   export KEYFACTOR_API_PATH=KeyfactorAPI
   export KEYFACTOR_AUTH_TOKEN_URL=https://login.keyfactor.com/oauth/token
   export KEYFACTOR_AUTH_CLIENT_ID=...
   export KEYFACTOR_AUTH_CLIENT_SECRET=...
   ```

### Files Created by Make Targets

| File | Purpose | Gitignored |
|------|---------|------------|
| `.oauth_token` | Cached OAuth token | Yes |
| `.oauth_token_expiry` | Token expiry timestamp | Yes |
| `.env` | Project configuration | Yes |
| `.test.env` | Test environment variables | Yes |

---

## Kubernetes CSR Management (K8SCert Testing)

These targets help create and manage Kubernetes Certificate Signing Requests for testing the K8SCert store type.

### Creating CSRs

#### `make csr-create [NAME=my-csr] [CN=test-cert]`
Create a single test CSR:
```bash
make csr-create                    # Creates test-csr-<timestamp>
make csr-create NAME=my-test-csr   # Creates my-test-csr
make csr-create NAME=my-csr CN=myapp.example.com
```

#### `make csr-create-approved [NAME=my-csr]`
Create a CSR and immediately approve it:
```bash
make csr-create-approved NAME=my-approved-csr
```

#### `make csr-create-batch [COUNT=10] [APPROVE=true]`
Create multiple test CSRs at once:
```bash
make csr-create-batch              # Creates 10 pending CSRs
make csr-create-batch COUNT=5      # Creates 5 pending CSRs
make csr-create-batch APPROVE=true # Creates 10 approved CSRs
make csr-create-batch COUNT=3 APPROVE=true
```

### Managing CSRs

#### `make csr-approve NAME=my-csr`
Approve a pending CSR:
```bash
make csr-approve NAME=test-csr-123456
```

#### `make csr-deny NAME=my-csr`
Deny a pending CSR:
```bash
make csr-deny NAME=test-csr-123456
```

#### `make csr-delete NAME=my-csr`
Delete a specific CSR:
```bash
make csr-delete NAME=test-csr-123456
```

### Viewing CSRs

#### `make csr-list`
List all CSRs in the cluster.

#### `make csr-list-test`
List only test CSRs (those prefixed with `test-`).

#### `make csr-describe NAME=my-csr`
Show detailed information about a specific CSR.

### Cleanup

#### `make csr-cleanup`
Delete all test CSRs (those prefixed with `test-`).

---

## Common Workflows

### Running Tests for Development
```bash
# Quick unit test check
make test-unit

# Single store type integration test
make test-store-tls

# Full integration test (slower)
make test-integration
```

### Debugging a Certificate Deployment Issue
```bash
# 1. Check token is valid
make token-show

# 2. Get certificate info
make api-get-cert CERT_ID=43

# 3. Run full debug loop
make debug-loop-cert43

# 4. Check logs if something went wrong
make debug-logs
```

### Testing with Fresh Cluster State
```bash
# Clean up any leftover resources
make test-cluster-cleanup

# Run integration tests
make test-integration

# Or run all tests with cleanup
make test-all-with-cleanup
```

### CI/CD Usage
```bash
# Use optimized CI test target
make test-ci

# Or for full validation
make test-all-with-cleanup
```
