# Code Coverage Improvement Plan

## Current State

- **Line Coverage**: 60.51% (4,204 / 6,947 lines)
- **Branch Coverage**: 54.37% (1,385 / 2,547 branches)
- **Target**: 70% line coverage (4,863 lines needed)
- **Gap**: ~659 additional lines need coverage

## Priority Files (< 50% Coverage)

| Priority | File | Lines | Current | Target | Effort |
|----------|------|-------|---------|--------|--------|
| 1 | `Handlers/SecretHandlerFactory.cs` | 112 | 29.2% | 80% | **Easy** |
| 2 | `Jobs/Base/ReenrollmentBase.cs` + store types | 203 | 0% | 70% | **Easy** (stubs) |
| 3 | `Clients/CertificateOperations.cs` | 192 | 48.9% | 70% | Easy |
| 4 | `Jobs/JobBase.cs` (models) | 2,086 | 43.6% | 60% | Easy-Medium |
| 5 | `Clients/KubeClient.cs` | 2,316 | 27.8% | 50% | Medium-Hard |
| 6 | `Models/K8SCertificateContext.cs` | 499 | 0% | 50% | Low priority |

---

## Phase 1: Quick Wins - ALL 0% Coverage Items (Target: 67% coverage)

**Every 0% coverage item is trivial to test.** Here's the complete list:

### 1.1 Reenrollment Classes (0% → 100%)

**Files**: `ReenrollmentBase.cs` + 6 store-type stubs (~200 lines total)
**Effort**: 30 minutes
**Why easy**: They just return "not implemented"

```csharp
[Theory]
[InlineData(typeof(K8SSecret.Reenrollment))]
[InlineData(typeof(K8STLSSecr.Reenrollment))]
// ... all 6 store types
public void Reenrollment_ReturnsNotImplemented(Type type)
{
    var instance = Activator.CreateInstance(type, Mock.Of<IPAMSecretResolver>());
    var result = ((IReenrollmentJobExtension)instance).ProcessJob(config, _ => "");
    Assert.Equal(OrchestratorJobStatusJobResult.Failure, result.Result);
}
```

### 1.2 Model DTOs in JobBase.cs (0% → 100%)

**Classes**: `KubernetesCertStore`, `KubeCreds`, `Cert` (~40 lines total)
**Effort**: 15 minutes
**Why easy**: Just auto-properties

```csharp
[Fact]
public void KubernetesCertStore_Properties_Work()
{
    var store = new KubernetesCertStore { KubeNamespace = "test", KubeSecretName = "secret" };
    Assert.Equal("test", store.KubeNamespace);
}
```

### 1.3 Exception Classes (0% → 100%)

**Classes**: `InvalidK8SSecretException`, `JkSisPkcs12Exception` (~60 lines total)
**Effort**: 15 minutes
**Why easy**: Standard exception pattern

```csharp
[Fact]
public void InvalidK8SSecretException_WithMessage_ContainsMessage()
{
    var ex = new InvalidK8SSecretException("test message");
    Assert.Equal("test message", ex.Message);
}
```

### 1.4 K8SCertificateContext Model (0% → 70%)

**File**: `Models/K8SCertificateContext.cs` (499 lines)
**Effort**: 1 hour
**Why easy**: Model with computed properties, use existing test certificates

```csharp
[Fact]
public void K8SCertificateContext_WithCert_ComputesThumbprint()
{
    var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test");
    var context = new K8SCertificateContext { Certificate = cert.Certificate };
    Assert.NotEmpty(context.Thumbprint);
    Assert.NotEmpty(context.SubjectCN);
}
```

### 1.5 SecretHandlerFactory (29% → 80%)

**File**: `Handlers/SecretHandlerFactory.cs` (112 lines)
**Effort**: 30 minutes
**Why easy**: Simple switch statement

```csharp
[Theory]
[InlineData("K8SSecret", typeof(OpaqueSecretHandler))]
[InlineData("K8STLSSecr", typeof(TlsSecretHandler))]
[InlineData("K8SJKS", typeof(JksSecretHandler))]
[InlineData("K8SPKCS12", typeof(Pkcs12SecretHandler))]
[InlineData("K8SCluster", typeof(ClusterSecretHandler))]
[InlineData("K8SNS", typeof(NamespaceSecretHandler))]
[InlineData("K8SCert", typeof(CertificateSecretHandler))]
public void CreateHandler_ValidStoreType_ReturnsCorrectHandler(string storeType, Type expected)
```

### 1.6 CertificateOperations (49% → 70%)

**File**: `Clients/CertificateOperations.cs` (192 lines)
**Effort**: 1 hour
**Why moderate**: Needs mocked IKubernetes for CSR operations

---

**Phase 1 Total**: ~3-4 hours for all 0% items + SecretHandlerFactory + CertificateOperations

---

## Phase 2: Medium Impact (Target: 68% coverage)

### 2.1 KubeClient Unit Tests

**File**: `Clients/KubeClient.cs` (2,316 lines, 27.8% → 50%)
**Effort**: Medium-High (4-6 hours)
**Impact**: ~500 lines

This is the largest file with lowest coverage. Focus on:

**Testable without K8s cluster (mock IKubernetes):**
- `ParseKubeConfig()` - Various kubeconfig formats
- `GetClusterName()` - Cluster name extraction
- `CheckTlsVerifyOverride()` - TLS skip logic
- `RetryPolicy()` - Retry logic (mock failures)
- Connection validation logic

**Test file structure:**
```csharp
public class KubeClientUnitTests
{
    private readonly Mock<IKubernetes> _mockClient;

    [Fact]
    public void ParseKubeConfig_ValidJson_ReturnsConfig() { }

    [Fact]
    public void ParseKubeConfig_InvalidJson_ThrowsException() { }

    [Fact]
    public void GetClusterName_WithContext_ReturnsName() { }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    [InlineData("", false)]
    public void CheckTlsVerifyOverride_VariousInputs_ReturnsExpected() { }
}
```

### 2.2 JobBase Core Logic

**File**: `Jobs/JobBase.cs` - Core methods
**Effort**: Medium (3-4 hours)
**Impact**: ~200 lines

Focus on unit-testable methods:
- `ResolveStorePathAndApplyDefaults()`
- `ParseStoreProperties()`
- `ResolvePassword()` variations
- Path resolution logic

---

## Phase 3: Reenrollment Coverage (Target: 70% coverage)

### 3.1 ReenrollmentBase Tests (QUICK WIN)

**File**: `Jobs/Base/ReenrollmentBase.cs` (83 lines, 0% → 70%)
**Effort**: LOW (30 minutes)
**Impact**: ~58 lines

Reenrollment is **NOT IMPLEMENTED** for any store type - the classes just return "not implemented" failures. Testing is trivial:

```csharp
[Fact]
public void ProcessJob_ReturnsNotImplemented()
{
    var resolver = new Mock<IPAMSecretResolver>();
    var reenrollment = new K8SSecret.Reenrollment(resolver.Object);

    var config = new ReenrollmentJobConfiguration { Capability = "K8SSecret" };
    var result = reenrollment.ProcessJob(config, _ => "");

    Assert.Equal(OrchestratorJobStatusJobResult.Failure, result.Result);
    Assert.Contains("not implemented", result.FailureMessage, StringComparison.OrdinalIgnoreCase);
}
```

### 3.2 Store-Type Reenrollment Tests (QUICK WIN)

**Files**: `Jobs/StoreTypes/*/Reenrollment.cs` (120 lines total, 0% → 70%)
**Effort**: LOW (30 minutes)
**Impact**: ~84 lines

All 6 store-type Reenrollment classes are single-line stubs that inherit from ReenrollmentBase:
```csharp
public class Reenrollment : ReenrollmentBase
{
    public Reenrollment(IPAMSecretResolver resolver) : base(resolver) { }
}
```

One parameterized test covers all of them:
```csharp
[Theory]
[InlineData(typeof(K8SSecret.Reenrollment))]
[InlineData(typeof(K8STLSSecr.Reenrollment))]
[InlineData(typeof(K8SJKS.Reenrollment))]
[InlineData(typeof(K8SPKCS12.Reenrollment))]
[InlineData(typeof(K8SCluster.Reenrollment))]
[InlineData(typeof(K8SNS.Reenrollment))]
public void Reenrollment_AllStoreTypes_ReturnsNotImplemented(Type reenrollmentType) { }
```

---

## Phase 4: Optional Improvements (Beyond 70%)

### 4.1 K8SCertificateContext Model

**File**: `Models/K8SCertificateContext.cs` (499 lines, 0%)
**Effort**: Low-Medium
**Impact**: High line count but low priority (model class)

This is a large model file. Consider:
- Simple property tests
- Serialization round-trip tests
- Or mark as excluded from coverage if purely data

### 4.2 Error Path Coverage

Improve branch coverage by testing error scenarios:
- Network failures in KubeClient
- Invalid certificate formats
- Permission denied scenarios
- Timeout handling

---

## Implementation Order

```
Day 1: Quick Wins (Phase 1 + 3) - ~6 hours total
├── SecretHandlerFactory tests (1-2 hours)
├── Reenrollment tests - all store types (1 hour) ← TRIVIAL: just verify "not implemented"
├── CertificateOperations tests (1-2 hours)
└── JobBase model tests (1 hour)

Day 2-3: KubeClient (Phase 2.1) - ~6 hours total
├── ParseKubeConfig tests
├── Connection/validation tests
└── Retry logic tests

Day 4: JobBase Core Logic (Phase 2.2) - ~4 hours
├── ResolveStorePathAndApplyDefaults tests
├── ParseStoreProperties tests
└── ResolvePassword tests
```

---

## Test Infrastructure Needs

### For KubeClient Testing
```csharp
// Create mock IKubernetes for unit tests
var mockK8s = new Mock<IKubernetes>();
mockK8s.Setup(k => k.CoreV1.ReadNamespacedSecret(...))
    .Returns(new V1Secret { ... });
```

### For Reenrollment Testing
- Test certificate authority (mock or real)
- Pre-created CSRs with known states
- Certificate chain for validation

---

## Metrics Tracking

Run coverage after each phase:
```bash
make test-coverage
```

Expected progression:
| Phase | Target Coverage | Lines Covered |
|-------|-----------------|---------------|
| Start | 60.51% | 4,204 |
| Phase 1 | 65% | 4,516 |
| Phase 2 | 68% | 4,724 |
| Phase 3 | 70% | 4,863 |

---

## Files to Exclude from Coverage (Optional)

Consider excluding these from coverage metrics if they're not worth testing:
- `Models/K8SCertificateContext.cs` - Pure data model
- Generated code or third-party wrappers

Add to test project:
```xml
<ItemGroup>
  <AssemblyAttribute Include="System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage" />
</ItemGroup>
```

---

## Quick Reference: Test Commands

```bash
# Run all tests with coverage
make test-coverage

# Run specific test file
dotnet test --filter "FullyQualifiedName~SecretHandlerFactoryTests"

# View coverage report
make test-coverage-open

# Check current coverage
head -5 ./coverage/*/coverage.cobertura.xml
```
