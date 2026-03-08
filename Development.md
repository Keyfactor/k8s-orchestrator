# Developer Guide

This document describes how to build and test the Kubernetes Orchestrator Extension.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
  - [Integration Tests](#integration-tests)
  - [Store-Type Specific Tests](#store-type-specific-tests)
  - [Code Coverage](#code-coverage)
- [Architecture](#architecture)
- [Debugging](#debugging)
- [Makefile Reference](#makefile-reference)

## Prerequisites

- .NET 8.0 SDK or later (.NET 10.0 SDK recommended — project targets both `net8.0` and `net10.0`)
- Access to a Kubernetes cluster (for integration tests)
- `kubectl` configured with appropriate context (default: `kf-integrations`)
- `fzf` (optional, for interactive test selection)

## Building

```bash
make build              # Build entire solution
dotnet build -c Release # Build for release
```

## Testing

The project uses xUnit for testing with comprehensive unit and integration test suites (~1337 unit tests, ~200 integration tests).

### Unit Tests

Run unit tests (no Kubernetes cluster required):

```bash
make test-unit
```

### Integration Tests

Integration tests require a Kubernetes cluster. By default, tests use `~/.kube/config` with the `kf-integrations` context.

```bash
make test-integration           # Run all integration tests (net8.0 only, with cleanup)
make test-integration-fast      # Same as above (net8.0 only, ~50% faster than full)
make test-integration-full      # Run on all frameworks (net8.0 + net10.0)
make test-integration-no-cleanup # Leave secrets for manual inspection
make test-all-with-cleanup      # Unit + integration with pre/post cleanup
```

#### CI Testing

```bash
make test-ci                    # Fast on PRs, full on main branch
make test-integration-smoke-net10 # Smoke tests on net10.0 only (Inventory tests)
```

#### Cluster Setup

```bash
make test-cluster-setup         # Display cluster setup instructions and verify connectivity
make test-cluster-cleanup       # Clean up test namespaces and CSRs
make test-setup                 # Full setup: cleanup + create CSRs for K8SCert tests
```

Integration tests create namespaces prefixed with `keyfactor-` and clean them up after completion.

### Store-Type Specific Tests

Run tests for individual store types:

```bash
make test-store-jks       # K8SJKS (Java Keystores)
make test-store-pkcs12    # K8SPKCS12 (PKCS12/PFX files)
make test-store-secret    # K8SSecret (Opaque secrets)
make test-store-tls       # K8STLSSecr (TLS secrets)
make test-store-cluster   # K8SCluster (cluster-wide)
make test-store-ns        # K8SNS (namespace-level)
make test-store-cert      # K8SCert (CSRs)
make test-kubeclient      # KubeCertificateManagerClient (direct client tests)
```

Or run tests for a specific store type with cleanup:

```bash
make test-store-type STORE=K8SJKS
```

### Handler and Base Class Tests

```bash
make test-handlers        # Test secret handlers
make test-base-jobs       # Test base job classes
```

### Other Test Commands

```bash
make testall              # Run all tests (unit + integration)
make test                 # Interactive single test selection (requires fzf)
make test-watch           # Auto-rerun tests on file changes
make test-single FILTER=Inventory_OpaqueSecretWithCertificate  # Run one test by filter
```

### Code Coverage

```bash
make test-coverage              # Run all tests with coverage and generate HTML report
make test-coverage-unit         # Unit tests only with coverage
make test-coverage-open         # Open coverage HTML report in browser (macOS)
make test-coverage-summary      # Show coverage summary in terminal
make test-coverage-clean        # Remove coverage reports
make test-coverage-install      # Install reportgenerator tool
```

#### Coverage Analysis

```bash
make coverage-summary           # Unit coverage summary sorted by uncovered lines
make coverage-summary-all       # Combined (unit+integration) coverage summary
make coverage-uncovered CLASS=CertificateUtilities   # Uncovered lines for a class
make coverage-uncovered-all CLASS=JobBase             # Uncovered lines from combined coverage
```

## Architecture

The extension follows a layered architecture:

```
Jobs/
├── Base/                    # Base job classes
│   ├── K8SJobBase.cs       # Shared infrastructure
│   ├── InventoryBase.cs    # Inventory logic
│   ├── ManagementBase.cs   # Management logic
│   ├── DiscoveryBase.cs    # Discovery logic
│   └── ReenrollmentBase.cs # Reenrollment logic
└── StoreTypes/              # Store-specific implementations
    ├── K8SCert/
    ├── K8SCluster/
    ├── K8SNS/
    ├── K8SJKS/
    ├── K8SPKCS12/
    ├── K8SSecret/
    └── K8STLSSecr/

Handlers/                    # Secret operation handlers
├── ISecretHandler.cs
├── SecretHandlerFactory.cs
├── TlsSecretHandler.cs
├── OpaqueSecretHandler.cs
├── JksSecretHandler.cs
├── Pkcs12SecretHandler.cs
├── ClusterSecretHandler.cs
├── NamespaceSecretHandler.cs
└── CertificateSecretHandler.cs

Services/                    # Business logic
├── StoreConfigurationParser.cs   # Parses job config to StoreConfiguration
├── PasswordResolver.cs           # Resolves passwords from secrets or direct values
├── CertificateChainExtractor.cs  # Certificate chain parsing and extraction
├── KeystoreOperations.cs         # JKS/PKCS12 keystore operations
├── JobCertificateParser.cs       # Certificate format detection and extraction
└── StorePathResolver.cs          # Resolves store paths to namespace/name

Serializers/                 # Store-type serialization
├── K8SJKS/Store.cs          # JKS keystore handling (BouncyCastle)
└── K8SPKCS12/Store.cs       # PKCS12 handling (BouncyCastle)

Clients/                     # Kubernetes API wrapper
├── KubeClient.cs            # Authenticated K8S client wrapper
├── SecretOperations.cs      # Secret CRUD operations
├── CertificateOperations.cs # CSR operations
└── KubeconfigParser.cs      # Kubeconfig JSON parsing
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## Debugging

### Container-based Debugging

For debugging with Keyfactor Command orchestrator containers:

```bash
make debug-build            # Build extension and verify DLL in container folder
make debug-restart          # Restart the orchestrator container
make debug-logs             # Show recent container logs (last 100 lines)
make debug-logs-follow      # Follow container logs in real-time
make debug-container-id     # Get the current container ID
```

#### Scheduling Test Jobs

```bash
make debug-schedule-tls     # Schedule management job for TLS secret store
make debug-schedule-opaque  # Schedule management job for Opaque secret store
make debug-schedule-both    # Schedule both TLS and Opaque jobs
make debug-schedule-tls-cert CERT_ID=43               # Schedule TLS job with specific cert
make debug-schedule-tls-cert CERT_ID=43 PFX_PASSWORD=xxx  # With custom password
```

#### Debug Loops (build + restart + schedule + verify)

```bash
make debug-loop             # Full loop: build, restart, schedule TLS job, wait, check
make debug-loop-both        # Full loop for both TLS and Opaque stores
make debug-loop-cert43      # Loop with cert 43 (has private key + chain)
make debug-loop-cert44      # Loop with cert 44 (no private key, DER format)
```

#### Checking Secrets

```bash
make debug-check-tls-secret    # Check TLS secret in Kubernetes
make debug-check-opaque-secret # Check Opaque secret in Kubernetes
make debug-check-secrets       # Check both secrets
make debug-wait-job            # Wait for jobs to complete (polls logs)
make debug-get-cert-info CERT_ID=43  # Get certificate info from Command
```

### Keystore Inspection

Inspect JKS or PKCS12 keystores stored in Kubernetes secrets:

```bash
make inspect-jks SECRET=my-jks-secret                          # Inspect JKS (default namespace, default password)
make inspect-jks SECRET=my-jks NS=my-namespace INSPECT_PASSWORD=mypass
make inspect-jks-manual SECRET=my-jks                          # Manual inspection (outputs raw commands)
make inspect-pkcs12 SECRET=my-pkcs12-secret
make inspect-pkcs12 SECRET=my-pkcs12 NS=my-namespace INSPECT_PASSWORD=mypass
make inspect-pkcs12-manual SECRET=my-pkcs12
```

### CSR Testing

For K8SCert (Certificate Signing Request) testing:

```bash
make csr-create                  # Create a test CSR
make csr-create NAME=my-csr CN=test-cert  # Create with custom name/CN
make csr-create-approved         # Create and approve a test CSR
make csr-create-with-chain       # Create CSR with certificate chain (root -> intermediate -> leaf)
make csr-create-batch COUNT=10 APPROVE=true  # Create multiple CSRs
make csr-create-batch-with-chain COUNT=3     # Create multiple CSRs with chains
```

```bash
make csr-list               # List all CSRs
make csr-list-test          # List only test CSRs (prefixed with test-)
make csr-describe NAME=my-csr  # Describe a CSR
make csr-approve NAME=my-csr   # Approve a CSR
make csr-deny NAME=my-csr      # Deny a CSR
make csr-delete NAME=my-csr    # Delete a CSR
make csr-cleanup            # Delete all test CSRs
```

### OAuth Token Management

```bash
make token                  # Get OAuth token (uses cache if valid)
make token-refresh          # Force refresh and cache to disk
make token-show             # Show cached token info (without exposing token)
make token-clear            # Clear cached token
make token-get              # Get token silently (for use in scripts)
```

### Keyfactor Command API

```bash
make api-list-stores        # List certificate stores from Command
make api-list-certs         # List certificates (first 20)
make api-get-cert CERT_ID=43  # Get certificate details
make api-get-jobs           # Get recent orchestrator jobs (last 10)
```

## Makefile Reference

Run `make help` to see all available targets with descriptions, organized by category:

| Category | Targets |
|----------|---------|
| **General** | `help` |
| **Development** | `reset`, `setup`, `newtest`, `installpackage` |
| **Testing** | `testall`, `test`, `test-unit`, `test-integration`, `test-integration-fast`, `test-integration-full`, `test-integration-smoke-net10`, `test-ci`, `test-setup`, `test-coverage`, `test-coverage-install`, `test-coverage-unit`, `test-coverage-summary`, `test-coverage-open`, `test-coverage-clean`, `coverage-summary`, `coverage-summary-all`, `coverage-uncovered`, `coverage-uncovered-all`, `test-watch`, `test-single`, `test-store-jks`, `test-store-pkcs12`, `test-store-secret`, `test-store-tls`, `test-store-cluster`, `test-store-ns`, `test-store-cert`, `test-kubeclient`, `test-handlers`, `test-base-jobs`, `test-cluster-setup`, `test-cluster-cleanup`, `test-store-type`, `test-integration-no-cleanup`, `test-all-with-cleanup` |
| **Debugging** | `debug-build`, `debug-container-id`, `debug-restart`, `debug-logs`, `debug-logs-follow`, `debug-get-token`, `debug-schedule-tls`, `debug-schedule-opaque`, `debug-schedule-both`, `debug-check-tls-secret`, `debug-check-opaque-secret`, `debug-check-secrets`, `debug-wait-job`, `debug-loop`, `debug-loop-both`, `debug-schedule-tls-cert`, `debug-loop-cert43`, `debug-loop-cert44`, `debug-get-cert-info`, `inspect-jks`, `inspect-jks-manual`, `inspect-pkcs12`, `inspect-pkcs12-manual` |
| **OAuth** | `token`, `token-refresh`, `token-show`, `token-clear`, `token-get` |
| **Store Types** | `store-types-create`, `store-types-update`, `store-types-split` |
| **Command API** | `api-list-stores`, `api-list-certs`, `api-get-cert`, `api-get-jobs` |
| **CSR Management** | `csr-create`, `csr-create-approved`, `csr-approve`, `csr-deny`, `csr-list`, `csr-list-test`, `csr-describe`, `csr-delete`, `csr-cleanup`, `csr-create-batch`, `csr-create-with-chain`, `csr-create-batch-with-chain` |
| **Build** | `build` |

## Common Issues

### Test Failures

1. **SSL Connection Errors**: Ensure your kubeconfig is valid and the cluster is accessible
2. **Namespace Not Found**: Run `make test-cluster-cleanup` to clean up stale resources
3. **Permission Denied**: Ensure your service account has appropriate RBAC permissions

### Build Issues

1. **Manifest.json file lock**: Run `rm -rf */bin */obj` to clean build artifacts
