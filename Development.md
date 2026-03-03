# Developer Guide

This document describes how to build and test the Kubernetes Orchestrator Extension.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
  - [Integration Tests](#integration-tests)
  - [Store-Type Specific Tests](#store-type-specific-tests)
- [TestConsole (Legacy)](#testconsole-legacy)
- [Architecture](#architecture)

## Prerequisites

- .NET 8.0 SDK or later
- Access to a Kubernetes cluster (for integration tests)
- `kubectl` configured with appropriate context

## Building

```bash
# Build entire solution
dotnet build

# Or using Make
make build

# Build for release
dotnet build -c Release
```

## Testing

The project uses xUnit for testing with comprehensive unit and integration test suites.

### Unit Tests

Run unit tests (no Kubernetes cluster required):

```bash
make test-unit
```

This runs all tests that don't require a live Kubernetes cluster (~740 tests).

### Integration Tests

Integration tests require a Kubernetes cluster. By default, tests use `~/.kube/config`.

```bash
# Run all integration tests
make test-integration

# Run integration tests (faster - single framework)
make test-integration-fast

# Run tests without cleanup (for debugging)
make test-integration-no-cleanup

# Run all tests with pre/post cleanup
make test-all-with-cleanup
```

#### Cluster Setup

```bash
# Check cluster connectivity and context
make test-cluster-setup

# Clean up test resources from previous runs
make test-cluster-cleanup
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

### Interactive Test Selection

Use `fzf` for interactive test selection:

```bash
make test
```

### Code Coverage

```bash
# Run tests with coverage
make test-coverage

# Unit tests with coverage
make test-coverage-unit

# View coverage report
make test-coverage-open
```

## TestConsole (Legacy)

The `TestConsole` application provides manual integration testing against a Keyfactor Command instance.

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `KEYFACTOR_HOSTNAME` | Keyfactor Command hostname | `my.keyfactor.kfdelivery.com` |
| `KEYFACTOR_DOMAIN` | Authentication domain | `command` |
| `KEYFACTOR_USERNAME` | Service account username | `k8s-agent-sa` |
| `KEYFACTOR_PASSWORD` | Service account password | |
| `TEST_KUBECONFIG` | Full kubeconfig JSON (single line or base64) | See scripts/kubernetes/README.md |
| `TEST_KUBE_NAMESPACE` | Target namespace | `default` |
| `TEST_MANUAL` | Enable manual mode | `true`/`false` |
| `TEST_CERT_MGMT_TYPE` | Operation type | `inv`, `add`, `remove` |
| `TEST_ORCH_OPERATION` | Job operation | `inventory`, `management` |

### Running TestConsole

```bash
dotnet build

# Set environment variables
export KEYFACTOR_HOSTNAME=my.keyfactor.kfdelivery.com
export KEYFACTOR_DOMAIN=command
export KEYFACTOR_USERNAME=k8s-agent-sa
export KEYFACTOR_PASSWORD=<password>
export TEST_KUBECONFIG='<kubeconfig-json>'
export TEST_KUBE_NAMESPACE=default
export TEST_MANUAL=false
export TEST_CERT_MGMT_TYPE=inv
export TEST_ORCH_OPERATION=inventory

# Run
./TestConsole/bin/Debug/net8.0/TestConsole
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
Clients/                     # Kubernetes API wrapper
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## Debugging

### Container-based Debugging

For debugging with Keyfactor Command orchestrator containers:

```bash
# Build and verify DLL
make debug-build

# Restart orchestrator container
make debug-restart

# View container logs
make debug-logs
make debug-logs-follow

# Schedule test jobs
make debug-schedule-tls
make debug-schedule-opaque

# Full debug loop
make debug-loop
```

### CSR Testing

For K8SCert (Certificate Signing Request) testing:

```bash
# Create and approve a test CSR
make csr-create-approved

# Create CSR with certificate chain
make csr-create-with-chain

# List and cleanup CSRs
make csr-list
make csr-cleanup
```

## Common Issues

### Test Failures

1. **SSL Connection Errors**: Ensure your kubeconfig is valid and the cluster is accessible
2. **Namespace Not Found**: Run `make test-cluster-cleanup` to clean up stale resources
3. **Permission Denied**: Ensure your service account has appropriate RBAC permissions

### Build Issues

1. **Manifest.json file lock**: Run `rm -rf */bin */obj` to clean build artifacts
