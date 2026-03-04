# Integration Test Performance Improvement Plan

## Current State

- **Total Tests**: 896 (unit + integration)
- **Current Runtime**: ~37.5 minutes (net8.0 + net10.0)
- **Single Framework Runtime**: ~19 minutes (net8.0 only)

## Identified Slow Tests

Tests taking >5 seconds:
- `K8SClusterStoreTests.ClusterSecret_RsaKeyTypes_ValidPemFormat(keyType: Rsa4096)` - 14s
- `K8STLSSecrStoreTests.PemCertificate_VariousKeyTypes_ValidFormat(keyType: Dsa2048)` - 13s
- Tests with `Rsa4096` and `Dsa2048` key types are consistently slower due to key generation

## Improvement Strategies

### 1. Parallel Test Execution (High Impact)

**Current Issue**: Integration tests run sequentially due to shared Kubernetes cluster state.

**Solution**:
- Use test collections to group tests by store type
- Tests within different store types can run in parallel (different namespaces)
- Use unique namespace prefixes per test collection

**Implementation**:
```csharp
[Collection("K8SSecret Tests")]  // Same collection = sequential
[Collection("K8SJKS Tests")]     // Different collection = parallel
```

**Expected Improvement**: 40-50% reduction in runtime

### 2. Certificate Caching (Already Implemented)

The `CachedCertificateProvider` is already in use. Ensure all tests use it:
```csharp
// Good (fast)
var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test");

// Bad (slow - generates new key each time)
var cert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test");
```

**Audit needed**: Verify all tests use cached certificates where possible.

### 3. Reduce Large Key Sizes in Parameterized Tests

**Current Issue**: Theory tests with `Rsa4096` and `Rsa8192` run for each key type.

**Solution**:
- Move large key tests to dedicated Fact tests (run once)
- Use smaller keys (Rsa2048, EcP256) for parameterized tests

**Example**:
```csharp
// Instead of:
[Theory]
[InlineData(KeyType.Rsa2048)]
[InlineData(KeyType.Rsa4096)]
[InlineData(KeyType.Rsa8192)]
public void Test_AllRsaSizes(...) { }

// Use:
[Theory]
[InlineData(KeyType.Rsa2048)]
[InlineData(KeyType.EcP256)]  // Fast EC key
public void Test_CommonKeys(...) { }

[Fact]
public void Test_Rsa8192_SpecificBehavior() { }  // Run once
```

**Expected Improvement**: 20-30% for unit tests

### 4. Test Environment Setup Optimization

**Current Issue**: Each test class creates/deletes namespaces and secrets.

**Solution**:
- Use `IAsyncLifetime` with shared fixtures where possible
- Create namespaces once per collection, not per test class
- Use `[Collection]` with shared `ICollectionFixture<T>`

**Implementation**:
```csharp
[CollectionDefinition("K8S Integration")]
public class K8SIntegrationCollection : ICollectionFixture<K8SIntegrationFixture> { }

public class K8SIntegrationFixture : IAsyncLifetime
{
    public string SharedNamespace { get; private set; }

    public async Task InitializeAsync()
    {
        SharedNamespace = $"test-{Guid.NewGuid():N}";
        await CreateNamespace(SharedNamespace);
    }

    public async Task DisposeAsync()
    {
        await DeleteNamespace(SharedNamespace);
    }
}
```

### 5. Remove Unnecessary Delays

**Audit for**:
- `Thread.Sleep()` or `Task.Delay()` calls
- Polling with fixed delays (replace with polling with exponential backoff)

**Already Done**: K8SCert tests use `WaitForCsrCertificateAsync` with exponential backoff.

### 6. Single Framework CI Optimization

**Current**: Tests run on both net8.0 and net10.0 (doubles time).

**Solution**:
- Use `make test-integration-fast` (net8.0 only) for PR builds
- Run full multi-framework tests only on main branch merges

**Already Implemented**: `make test-ci` does this.

### 7. Test Isolation Improvements

**Issue**: Tests can interfere with each other if not properly isolated.

**Solution**:
- Each test should use unique resource names (already using GUIDs)
- Ensure cleanup happens even on test failure (`try/finally` in tests)
- Use `IAsyncDisposable` for deterministic cleanup

## Implementation Priority

| Priority | Task | Expected Savings | Effort |
|----------|------|------------------|--------|
| 1 | Parallel test collections | 40-50% | Medium |
| 2 | Audit certificate caching usage | 10-20% | Low |
| 3 | Move large key tests to Facts | 10-15% | Low |
| 4 | Shared test fixtures | 15-20% | Medium |
| 5 | Remove fixed delays | 5-10% | Low |

## Makefile Targets

New targets added:
- `make test-setup` - Set up test environment (creates CSRs for K8SCert tests)
- `make test-coverage-install` - Install reportgenerator tool
- `make test-coverage` - Full test coverage with HTML report (depends on test-setup)

## Monitoring

Track test duration trends:
```bash
# Extract test times from output
grep -E "Passed.*\[[0-9]+ (s|m)" test_output.log | \
  sort -t'[' -k2 -rn | head -20
```
