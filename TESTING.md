# Testing Guide

Comprehensive testing guide for the Keyfactor Kubernetes Universal Orchestrator Extension.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
  - [Unit Tests](#unit-tests)
  - [Integration Tests](#integration-tests)
- [Test Coverage](#test-coverage)
- [CI/CD Integration](#cicd-integration)
- [Writing New Tests](#writing-new-tests)
- [Troubleshooting](#troubleshooting)

---

## Overview

The test suite includes **603+ tests** across all 7 Kubernetes Orchestrator store types:

- **457 unit tests** - Fast, isolated tests with no external dependencies
- **146+ integration tests** - End-to-end tests against real Kubernetes clusters

All tests use **xUnit** framework with **Moq** for mocking, **BouncyCastle** for cryptographic operations, and **Keyfactor.PKI** for certificate utilities.

### Test Coverage by Store Type

| Store Type | Unit Tests | Integration Tests | Total |
|------------|-----------|------------------|-------|
| K8SJKS (Java Keystores) | ~80 | 14 | ~94 |
| K8SPKCS12 (PKCS12/PFX) | ~75 | 13 | ~88 |
| K8SCert (CSRs) | ~25 | 7 | ~32 |
| K8SSecret (Opaque PEM) | ~53 | 25 | ~78 |
| K8STLSSecr (TLS Secrets) | ~58 | 25 | ~83 |
| K8SCluster (Cluster-wide) | ~55 | 21 | ~76 |
| K8SNS (Namespace) | ~55 | 27 | ~82 |
| Utilities/CertificateFormat | ~56 | - | ~56 |
| **Total** | **~457** | **~146** | **~603** |

> **Note**: Counts are approximate due to parameterized tests. Run `dotnet test --list-tests` for exact counts.

---

## Quick Start with Makefile

The project includes convenient Makefile targets for all common test operations:

```bash
# Testing
make test-unit              # Run unit tests only
make test-integration       # Run integration tests only
make test-store-jks         # Test specific store type

# Code Coverage
make test-coverage-unit     # Unit tests with coverage report
make test-coverage          # All tests with coverage report
make test-coverage-open     # Open HTML coverage report in browser
make test-coverage-summary  # Show coverage summary in terminal

# Cluster Management
make test-cluster-setup     # Show cluster configuration
make test-cluster-cleanup   # Clean up test resources
```

See [MAKEFILE_GUIDE.md](MAKEFILE_GUIDE.md) for complete documentation of all Makefile targets.

---

## Test Structure

```
kubernetes-orchestrator-extension.Tests/
├── Attributes/
│   └── SkipUnlessAttribute.cs        # Conditional test execution
├── Helpers/
│   └── CertificateTestHelper.cs      # Certificate generation utilities
├── Integration/                       # Integration tests (require K8s)
│   ├── K8SCertStoreIntegrationTests.cs
│   ├── K8SClusterStoreIntegrationTests.cs
│   ├── K8SJKSStoreIntegrationTests.cs
│   ├── K8SNSStoreIntegrationTests.cs
│   ├── K8SPKCS12StoreIntegrationTests.cs
│   ├── K8SSecretStoreIntegrationTests.cs
│   └── K8STLSSecrStoreIntegrationTests.cs
├── Utilities/                         # Utility tests
│   └── CertificateUtilitiesTests.cs
├── K8SCertStoreTests.cs              # Unit tests
├── K8SClusterStoreTests.cs
├── K8SJKSStoreTests.cs
├── K8SNSStoreTests.cs
├── K8SPKCS12StoreTests.cs
├── K8SSecretStoreTests.cs
└── K8STLSSecrStoreTests.cs
```

### Test Naming Convention

All tests follow the pattern: `MethodName_Scenario_ExpectedResult`

Examples:
- `DeserializeRemoteCertificateStore_ValidJks_ReturnsStore`
- `Inventory_NonExistentSecret_ReturnsFailure`
- `PemCertificate_WithWhitespace_StillValid`

---

## Running Tests

### Prerequisites

**For Unit Tests:**
- .NET SDK 8.0 or 10.0
- No external dependencies required

**For Integration Tests:**
- .NET SDK 8.0 or 10.0
- Kubernetes cluster (or kind/minikube)
- Kubeconfig at `~/.kube/config` with context named `kf-integrations`
- Cluster permissions to create/delete namespaces and secrets

---

### Unit Tests

Unit tests run quickly (3-5 minutes) and have no external dependencies.

#### Run All Unit Tests

```bash
# From repository root
dotnet test kubernetes-orchestrator-extension.Tests/Keyfactor.Orchestrators.K8S.Tests.csproj

# Or with detailed output
dotnet test kubernetes-orchestrator-extension.Tests/Keyfactor.Orchestrators.K8S.Tests.csproj \
  --verbosity detailed
```

#### Run Tests for Specific Store Type

```bash
# K8SJKS tests
dotnet test --filter "FullyQualifiedName~K8SJKSStoreTests&FullyQualifiedName!~Integration"

# K8STLSSecr tests
dotnet test --filter "FullyQualifiedName~K8STLSSecrStoreTests&FullyQualifiedName!~Integration"

# All PEM-based store tests (K8SSecret + K8STLSSecr)
dotnet test --filter "FullyQualifiedName~K8SSecret|FullyQualifiedName~K8STLSSecr"
```

#### Run with Code Coverage

**Using Makefile (Recommended):**
```bash
# Run unit tests with coverage (fastest)
make test-coverage-unit

# Run all tests (unit + integration) with coverage
make test-coverage

# View coverage summary in terminal
make test-coverage-summary

# Open HTML report in browser (macOS)
make test-coverage-open

# Clean up coverage reports
make test-coverage-clean
```

**Manual Method:**
```bash
# Install coverage tool (one-time)
dotnet tool install -g dotnet-coverage

# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage" \
  --results-directory ./TestResults

# Generate HTML report
reportgenerator \
  -reports:"./TestResults/**/coverage.cobertura.xml" \
  -targetdir:"./TestResults/CoverageReport" \
  -reporttypes:Html

# View report
open ./TestResults/CoverageReport/index.html  # macOS
xdg-open ./TestResults/CoverageReport/index.html  # Linux
```

#### Run Tests on Specific Framework

```bash
# .NET 8.0 only
dotnet test --framework net8.0

# .NET 10.0 only
dotnet test --framework net10.0
```

---

### Integration Tests

Integration tests create real Kubernetes resources and validate end-to-end functionality.

#### Setup Prerequisites

**Option 1: Use Existing Cluster**

1. Ensure kubeconfig exists at `~/.kube/config`
2. Create or use context named `kf-integrations`:
   ```bash
   kubectl config get-contexts
   kubectl config use-context kf-integrations
   ```
3. Verify permissions:
   ```bash
   kubectl auth can-i create namespaces
   kubectl auth can-i create secrets --all-namespaces
   ```

**Option 2: Create Local Cluster with kind**

```bash
# Install kind (if not installed)
# macOS
brew install kind
# Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# Create cluster
kind create cluster --name kf-integrations --wait 5m

# Verify cluster
kubectl cluster-info --context kind-kf-integrations

# Rename context to match expected name
kubectl config rename-context kind-kf-integrations kf-integrations
```

**Option 3: Use Minikube**

```bash
# Start minikube
minikube start --profile=kf-integrations

# Set context
kubectl config use-context kf-integrations
```

#### Run Integration Tests

```bash
# Enable integration tests
export RUN_INTEGRATION_TESTS=true

# Run all integration tests
dotnet test kubernetes-orchestrator-extension.Tests/Keyfactor.Orchestrators.K8S.Tests.csproj

# Run integration tests for specific store type
dotnet test --filter "FullyQualifiedName~K8SJKSStoreIntegrationTests"

# Run with verbose output
dotnet test --filter "FullyQualifiedName~Integration" --verbosity detailed
```

#### Integration Test Behavior

Each integration test:
1. **Creates** dedicated test namespace (e.g., `keyfactor-k8sjks-integration-tests`)
2. **Executes** test operations (create secrets, run inventory, etc.)
3. **Cleans up** all created resources in `DisposeAsync()`
4. **Never modifies** existing cluster resources outside test namespaces

**Test Namespaces Created:**

Each test namespace includes a framework suffix (`-net8` or `-net10`) to enable parallel execution across .NET frameworks without resource conflicts:

- `keyfactor-k8sjks-integration-tests-net8` / `keyfactor-k8sjks-integration-tests-net10`
- `keyfactor-k8spkcs12-integration-tests-net8` / `keyfactor-k8spkcs12-integration-tests-net10`
- `keyfactor-k8scert-integration-tests-net8` / `keyfactor-k8scert-integration-tests-net10`
- `keyfactor-k8ssecret-integration-tests-net8` / `keyfactor-k8ssecret-integration-tests-net10`
- `keyfactor-k8stlssecr-integration-tests-net8` / `keyfactor-k8stlssecr-integration-tests-net10`
- `keyfactor-k8scluster-test-ns1-net8` / `keyfactor-k8scluster-test-ns1-net10`
- `keyfactor-k8scluster-test-ns2-net8` / `keyfactor-k8scluster-test-ns2-net10`
- `keyfactor-k8sns-integration-tests-net8` / `keyfactor-k8sns-integration-tests-net10`

#### Cleanup After Integration Tests

Normally, tests clean up automatically. If tests are interrupted, manually clean up:

```bash
# Delete all test namespaces
kubectl delete namespace -l managed-by=keyfactor-k8s-orchestrator-tests

# Or delete specific namespace
kubectl delete namespace keyfactor-k8sjks-integration-tests
```

---

## Test Coverage

### Current Coverage Metrics

**Store Type Tests (100% implementation complete):**
- ✅ All 7 store types have comprehensive unit tests
- ✅ All 7 store types have integration tests
- ✅ All 381 unit tests passing (100% success rate)
- ✅ All 120 integration tests passing (100% success rate)

**Test Scenarios Covered:**

#### Key Types (11 variations)
- RSA: 1024, 2048, 4096, 8192 bits
- EC: P-256, P-384, P-521 curves
- DSA: 1024, 2048 bits
- EdDSA: Ed25519, Ed448

#### Password Scenarios (20+)
- Empty password
- Simple password
- Complex password (special characters)
- Very long password (256+ chars)
- Unicode password
- Password with spaces
- Numeric-only password
- Password with newlines (trimmed)

#### Certificate Chains
- Single certificate (self-signed)
- Certificate with intermediate CA
- Full chain (leaf + intermediate + root)
- Separate ca.crt field storage

#### Error Conditions
- Wrong password
- Corrupted keystore data
- Missing secret
- Invalid namespace
- Malformed PEM data
- Empty keystores

#### Create Store If Missing
Tests for the "Create Store If Missing" feature in Keyfactor Command:
- K8SJKS: Creates empty JKS keystore when no certificate data provided
- K8SPKCS12: Creates empty PKCS12 keystore when no certificate data provided
- K8SSecret: Creates empty Opaque secret when no certificate data provided
- K8STLSSecr: Creates empty TLS secret when no certificate data provided
- K8SCluster: Returns success with warning (not supported for aggregate store types)
- K8SNS: Returns success with warning (not supported for aggregate store types)

#### Edge Cases
- Empty secrets
- Whitespace in PEM data
- Very large keystores (100+ certs)
- Special characters in secret names
- Cross-namespace operations (K8SCluster)
- Namespace boundaries (K8SNS)
- KubeSecretType property derivation from Capability (deprecated property support)

---

## CI/CD Integration

### GitHub Actions Workflows

**1. Unit Tests (`unit-tests.yml`)**
- Runs on: Every PR, push to main
- Tests: All 381 unit tests
- Frameworks: .NET 8.0 and 10.0
- Coverage: Uploads code coverage reports
- Duration: ~5 minutes

**2. Integration Tests (`integration-tests.yml`)**
- Runs on: Every PR, push to main
- Tests: All 120 integration tests
- Kubernetes: kind cluster (v1.29)
- Frameworks: .NET 8.0 and 10.0 (parallel with framework-specific namespaces)
- Duration: ~10 minutes

**3. PR Quality Gate (`pr-quality-gate.yml`)**
- Runs on: Every PR
- Includes: Build + basic tests
- Purpose: Fast feedback before detailed testing

### Running Tests Locally Like CI

```bash
# Simulate unit test workflow
dotnet restore
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build \
  --framework net8.0 \
  --collect:"XPlat Code Coverage"

# Simulate integration test workflow (requires kind)
kind create cluster --name kf-integrations
export RUN_INTEGRATION_TESTS=true
dotnet test --configuration Release --no-build --framework net8.0
kind delete cluster --name kf-integrations
```

### Test Result Artifacts

CI workflows upload test results as artifacts:
- **Unit Tests**: Test results + code coverage reports
- **Integration Tests**: Test results + logs

Download artifacts from GitHub Actions run page:
1. Go to Actions tab
2. Select workflow run
3. Scroll to "Artifacts" section
4. Download desired artifact

---

## Writing New Tests

### Unit Test Template

```csharp
using Xunit;
using Keyfactor.Orchestrators.K8S.Tests.Helpers;
using static Keyfactor.Orchestrators.K8S.Tests.Helpers.CertificateTestHelper;

namespace Keyfactor.Orchestrators.K8S.Tests;

public class YourStoreTypeTests
{
    [Fact]
    public void MethodName_Scenario_ExpectedResult()
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test Cert");

        // Act
        var result = YourMethod(certInfo.Certificate);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(expectedValue, result);
    }

    [Theory]
    [InlineData(KeyType.Rsa2048)]
    [InlineData(KeyType.EcP256)]
    public void MethodName_VariousKeyTypes_AllWork(KeyType keyType)
    {
        // Arrange
        var certInfo = CertificateTestHelper.GenerateCertificate(keyType);

        // Act & Assert
        Assert.NotNull(certInfo.Certificate);
    }
}
```

### Integration Test Template

```csharp
using System;
using System.Threading.Tasks;
using Xunit;
using Keyfactor.Orchestrators.K8S.Tests.Attributes;
using k8s;
using k8s.Models;

namespace Keyfactor.Orchestrators.K8S.Tests.Integration;

[Collection("Integration Tests")]
public class YourStoreIntegrationTests : IAsyncLifetime
{
    private Kubernetes _k8sClient;
    private const string TestNamespace = "your-test-namespace";

    public async Task InitializeAsync()
    {
        var runIntegrationTests = Environment.GetEnvironmentVariable("RUN_INTEGRATION_TESTS");
        if (string.IsNullOrEmpty(runIntegrationTests) ||
            !runIntegrationTests.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Initialize K8s client and create test namespace
        var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(
            kubeConfigPath: "~/.kube/config",
            currentContext: "kf-integrations");
        _k8sClient = new Kubernetes(config);

        await CreateNamespaceIfNotExists();
    }

    public async Task DisposeAsync()
    {
        // Clean up resources
        _k8sClient?.Dispose();
    }

    [SkipUnless(EnvironmentVariable = "RUN_INTEGRATION_TESTS")]
    public async Task YourTest_Scenario_ExpectedResult()
    {
        // Arrange
        var secret = new V1Secret { /* ... */ };
        await _k8sClient.CoreV1.CreateNamespacedSecretAsync(secret, TestNamespace);

        // Act
        var result = await YourOperation();

        // Assert
        Assert.Equal(expectedValue, result);
    }
}
```

### Using CertificateTestHelper

```csharp
// Generate certificate with specific key type
var certInfo = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "CN=test.example.com");

// Access components
var certificate = certInfo.Certificate;  // BouncyCastle X509Certificate
var keyPair = certInfo.KeyPair;          // AsymmetricCipherKeyPair
var privateKey = certInfo.KeyPair.Private;
var publicKey = certInfo.KeyPair.Public;

// Generate certificate chain (leaf, intermediate, root)
var chain = CertificateTestHelper.GenerateCertificateChain(KeyType.Rsa2048);
var leafCert = chain[0].Certificate;
var intermediateCert = chain[1].Certificate;
var rootCert = chain[2].Certificate;

// Convert to PEM format
var certPem = CertificateTestHelper.ConvertCertificateToPem(certificate);
var keyPem = CertificateTestHelper.ConvertPrivateKeyToPem(privateKey);

// Generate PKCS12/JKS
var pkcs12Bytes = CertificateTestHelper.GeneratePkcs12(
    certificate, keyPair, password: "test123", alias: "mycert");
var jksBytes = CertificateTestHelper.GenerateJks(
    certificate, keyPair, password: "test123", alias: "mycert");

// Generate corrupted data for negative tests
var corruptedData = CertificateTestHelper.GenerateCorruptedPkcs12();
```

---

## Known Limitations

### IncludeCertChain with Certificates Without Private Keys

When `IncludeCertChain=true` is configured for a certificate store, but the certificate being deployed in Keyfactor Command does **not** have a private key, the certificate chain **cannot** be included.

**Why?**
- Keyfactor Command sends certificates in DER format when they have no private key
- DER format can only contain a single certificate (the leaf certificate)
- Certificate chains require PKCS12 format, which requires a private key

**Symptoms:**
- A warning is logged: "IncludeCertChain is enabled but the certificate was received in DER format..."
- Only the leaf certificate is deployed, regardless of the IncludeCertChain setting

**Solution:**
- Ensure certificates in Keyfactor Command have "Private Key" set if you need the chain included
- Alternatively, use `SeparateChain=true` to manually manage chain certificates

### JKS vs PKCS12 Inventory Behavior

JKS and PKCS12 inventories behave differently for keystores with mixed entry types:

- **JKS Inventory**: Only returns entries with private keys (PrivateKeyEntry). Trusted certificate entries (certificate-only, no private key) are **not** returned.
- **PKCS12 Inventory**: Returns **all** entries including trusted certificate entries.

This is the current implemented behavior and is tested/documented. If you need to manage trusted certificates in JKS stores, you can add them but they won't appear in inventory.

### Invalid Configuration: IncludeCertChain=false with SeparateChain=true

When `SeparateChain=true` but `IncludeCertChain=false`, this is an invalid/conflicting configuration:
- `SeparateChain=true` means "put the chain in ca.crt and leaf in tls.crt"
- `IncludeCertChain=false` means "don't include any chain certificates"

**Behavior:**
- A warning is logged: "Invalid configuration: SeparateChain=true but IncludeCertChain=false..."
- `IncludeCertChain=false` takes precedence - only the leaf certificate is deployed
- `SeparateChain` is effectively ignored

**Recommendation:**
- Use `IncludeCertChain=true,SeparateChain=true` if you want chain in ca.crt
- Use `IncludeCertChain=true,SeparateChain=false` if you want full chain in tls.crt
- Use `IncludeCertChain=false` (any SeparateChain value) if you want leaf only

### KubeSecretType Property Deprecation

The `KubeSecretType` store property is **deprecated** and will be removed in a future release.

**Why?**
- The secret type is now automatically derived from the store's Capability
- This eliminates redundant configuration and potential mismatches

**Behavior:**
- If `KubeSecretType` is provided in store properties, a deprecation warning is logged
- The derived value from Capability takes precedence over the store property value
- Store type definitions have been updated to mark this property as `Required: false`

**Mapping (Capability → Derived KubeSecretType):**
| Capability | Derived Type |
|------------|--------------|
| K8SJKS | jks |
| K8SPKCS12 | pkcs12 |
| K8SSecret | secret |
| K8STLSSecr | tls_secret |
| K8SCluster | cluster |
| K8SNS | namespace |
| K8SCert | certificate |

### Create Store If Missing - Aggregate Store Types

K8SCluster and K8SNS store types do **not** support the "Create Store If Missing" feature.

**Why?**
- K8SCluster and K8SNS are "aggregate" store types that manage multiple secrets
- There is no single "store" to create - they represent all secrets in a cluster/namespace
- The concept of "creating" an empty cluster or namespace doesn't apply

**Behavior:**
- A warning is logged explaining that this operation is not supported
- The job returns **success** with a descriptive message
- No secrets are created or modified

---

## Troubleshooting

### Common Issues

#### 1. Integration Tests Skipped

**Problem**: All integration tests show as "Skipped"

**Solution**:
```bash
# Ensure environment variable is set
export RUN_INTEGRATION_TESTS=true

# Verify it's set
echo $RUN_INTEGRATION_TESTS

# Run tests
dotnet test
```

#### 2. Kubeconfig Not Found

**Problem**: `FileNotFoundException: Kubeconfig not found at ~/.kube/config`

**Solution**:
```bash
# Verify kubeconfig exists
ls -la ~/.kube/config

# Or set KUBECONFIG environment variable
export KUBECONFIG=/path/to/your/kubeconfig

# Verify cluster connectivity
kubectl cluster-info
```

#### 3. Context 'kf-integrations' Not Found

**Problem**: Integration tests fail with context not found

**Solution**:
```bash
# List available contexts
kubectl config get-contexts

# Rename existing context
kubectl config rename-context your-context-name kf-integrations

# Or create new kind cluster with correct name
kind create cluster --name kf-integrations
kubectl config rename-context kind-kf-integrations kf-integrations
```

#### 4. Permission Denied Errors

**Problem**: `forbidden: User "..." cannot create resource "namespaces"`

**Solution**:
```bash
# Check permissions
kubectl auth can-i create namespaces
kubectl auth can-i create secrets --all-namespaces

# For kind/minikube, you have cluster-admin by default
# For remote clusters, ensure service account has required permissions
```

#### 5. Tests Timing Out

**Problem**: Integration tests hang or timeout

**Solution**:
```bash
# Check cluster health
kubectl get nodes
kubectl get pods --all-namespaces

# Increase test timeout (in test project)
dotnet test -- RunConfiguration.TestSessionTimeout=600000  # 10 minutes

# Check for hanging namespaces from previous runs
kubectl get namespaces | grep keyfactor
kubectl delete namespace <stuck-namespace>
```

#### 6. Build Errors

**Problem**: `error MSB3644: The reference assemblies were not found`

**Solution**:
```bash
# Ensure correct .NET SDK versions installed
dotnet --list-sdks

# Install required versions
# .NET 8.0: https://dotnet.microsoft.com/download/dotnet/8.0
# .NET 10.0: https://dotnet.microsoft.com/download/dotnet/10.0

# Clean and rebuild
dotnet clean
dotnet restore
dotnet build
```

#### 7. Coverage Report Not Generated

**Problem**: No coverage data collected

**Solution**:
```bash
# Install required tools
dotnet tool install -g coverlet.console
dotnet tool install -g dotnet-reportgenerator-globaltool

# Run with explicit collector
dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults

# Verify coverage files created
ls -la ./TestResults/**/coverage.cobertura.xml
```

### Debug Mode

Run tests with maximum verbosity for troubleshooting:

```bash
# Diagnostic level logging
dotnet test --verbosity diagnostic --logger "console;verbosity=detailed"

# With specific test
dotnet test --filter "FullyQualifiedName~YourTestName" --verbosity diagnostic
```

### Getting Help

**For test failures:**
1. Check `UNIT_TEST_COMPLETION_SUMMARY.md` for known issues
2. Review test logs with `--verbosity detailed`
3. Verify environment setup matches prerequisites
4. Check GitHub Actions logs for CI failures

**For integration test issues:**
1. Verify cluster connectivity: `kubectl cluster-info`
2. Check test namespace status: `kubectl get namespaces`
3. Review pod logs: `kubectl logs -n <test-namespace> <pod-name>`
4. Enable trace logging in test code for debugging

---

## Best Practices

### Do's ✅

- ✅ Run unit tests before committing
- ✅ Run integration tests before creating PR
- ✅ Use `CertificateTestHelper` for test data generation
- ✅ Follow naming convention: `MethodName_Scenario_ExpectedResult`
- ✅ Clean up resources in integration tests
- ✅ Use `SkipUnless` attribute for integration tests
- ✅ Test both success and failure scenarios
- ✅ Include edge cases in test coverage

### Don'ts ❌

- ❌ Don't check in certificate files (use dynamic generation)
- ❌ Don't hardcode passwords or secrets in tests
- ❌ Don't skip integration tests locally before PR
- ❌ Don't modify cluster resources outside test namespaces
- ❌ Don't use production clusters for integration tests
- ❌ Don't ignore test failures ("I'll fix later")
- ❌ Don't write tests without assertions

---

**Questions or Issues?**

Create an issue at: https://github.com/Keyfactor/k8s-orchestrator/issues
