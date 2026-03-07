# Code Coverage Improvement Plan

## Current State (as of 2026-03-06)

- **Line Coverage**: ~84.1%
- **Branch Coverage**: ~78.9%
- **Total Tests**: 1,371 (1,156 unit + 215 integration)
- **Target**: Maintain >80% line coverage

## Coverage History

| Date | Line Coverage | Branch Coverage | Tests |
|------|--------------|-----------------|-------|
| Initial | 60.51% | 54.37% | ~896 |
| 2026-03-06 | ~84.1% | ~78.9% | 1,371 |

## Completed Improvements

The following phases from the original plan have been completed:

- **Phase 1 (Quick Wins)**: SecretHandlerFactory, Reenrollment stubs, CertificateOperations, JobBase models, Exception classes — all covered
- **Phase 3 (Reenrollment)**: All store-type reenrollment classes tested
- **SecretHandlerBase shared logic**: `IsSecretEmpty`, `ParseKeystoreAliasCore`, `ValidateCertOnlyUpdateCore` — all unit tested
- **Handler tests**: JKS, PKCS12, TLS, Opaque handlers tested via integration tests
- **CertificateUtilities/PrivateKeyFormatUtilities**: Comprehensive unit tests added

## Remaining Opportunities

### KubeClient Unit Tests (Medium Priority)

**File**: `Clients/KubeClient.cs` — largest file, still has lower coverage
**Testable without K8s cluster (mock IKubernetes):**
- `KubeconfigParser` parsing logic
- TLS verification skip logic
- Connection validation
- Retry policy behavior

### JobBase Core Logic (Low Priority)

**File**: `Jobs/Base/K8SJobBase.cs` — some internal methods have low coverage
- Store path resolution
- Store property parsing
- Password resolution variations

### Branch Coverage Gaps (Low Priority)

Many branches are error/edge-case paths that are hard to trigger in unit tests:
- Network failure paths in KubeClient
- Invalid certificate format edge cases
- Permission denied scenarios

## Quick Reference

```bash
# Run all tests with coverage
make test-coverage

# Run unit tests only with coverage
make test-unit

# View coverage report
make test-coverage-open

# Run specific test file
dotnet test --filter "FullyQualifiedName~SecretHandlerBaseTests"
```
