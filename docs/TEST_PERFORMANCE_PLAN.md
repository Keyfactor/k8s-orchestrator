# Integration Test Performance Improvement Plan

## Current State (as of 2026-03-06)

- **Total Tests**: 1,371 (1,156 unit + 215 integration)
- **Dual Framework**: Tests run on both net8.0 and net10.0

## Implemented Optimizations

### Certificate Caching (Done)

`CachedCertificateProvider` prevents redundant key generation:
```csharp
// Fast (cached)
var cert = CachedCertificateProvider.GetOrCreate(KeyType.Rsa2048, "Test");

// Slow (generates new key each time)
var cert = CertificateTestHelper.GenerateCertificate(KeyType.Rsa2048, "Test");
```

All tests use cached certificates. `Rsa8192` tests are isolated to dedicated Fact tests rather than Theory parameters.

### Single Framework CI (Done)

`make test-ci` runs net8.0 only for PR builds. Full multi-framework tests run on main branch merges.

### Exponential Backoff (Done)

K8SCert tests use `WaitForCsrCertificateAsync` with exponential backoff instead of fixed delays.

## Remaining Opportunities

### 1. Parallel Test Collections (High Impact)

**Current**: Integration tests run sequentially due to shared K8s state.
**Solution**: Use `[Collection]` attributes to run different store types in parallel (they use different namespaces).
**Expected**: 40-50% reduction in integration test runtime.

### 2. Shared Test Fixtures (Medium Impact)

**Current**: Each test class creates/deletes namespaces.
**Solution**: Use `ICollectionFixture<T>` for per-collection namespace setup.
**Expected**: 15-20% reduction from less namespace churn.

### 3. Audit for Fixed Delays (Low Impact)

Check for any remaining `Thread.Sleep()` or fixed `Task.Delay()` calls.

## Makefile Test Targets

```bash
make test-unit              # Unit tests only
make test-integration       # Integration tests (requires K8s cluster)
make testall                # All tests
make test                   # Interactive single test (fzf)
make test-coverage          # Full coverage report
make test-coverage-open     # Open HTML coverage report
make test-ci                # CI-optimized (single framework)
make test-cluster-cleanup   # Clean up test namespaces
```

## Monitoring

```bash
# Extract slowest tests
grep -E "Passed.*\[[0-9]+ (s|m)" test_output.log | \
  sort -t'[' -k2 -rn | head -20
```
