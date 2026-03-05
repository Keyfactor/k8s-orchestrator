# Testing Quick Start Guide

**5-minute guide to running tests for the Keyfactor Kubernetes Orchestrator Extension**

---

## 🎯 Makefile Shortcuts (Recommended)

```bash
make test-unit              # Run all unit tests
make test-integration       # Run integration tests
make test-coverage          # Generate coverage report
make test-store-jks         # Test JKS store type only
make test-store-pkcs12      # Test PKCS12 store type only
make test-cluster-setup     # Show cluster setup info
make test-cluster-cleanup   # Clean up test resources
```

**📖 Full documentation:** [MAKEFILE_TEST_TARGETS.md](MAKEFILE_TEST_TARGETS.md)

---

## 🚀 Quick Commands (Using dotnet directly)

### Run All Unit Tests
```bash
cd <repo-root>   # Change to the root of the k8s-orchestrator repository
dotnet test
```

### Run Unit Tests for Specific Store Type
```bash
# K8SJKS tests only
dotnet test --filter "FullyQualifiedName~K8SJKS&FullyQualifiedName!~Integration"

# All PEM-based tests (K8SSecret + K8STLSSecr)
dotnet test --filter "FullyQualifiedName~K8SSecret|FullyQualifiedName~K8STLSSecr"
```

### Run Integration Tests (Requires K8s Cluster)
```bash
# Option 1: Use existing cluster
export RUN_INTEGRATION_TESTS=true
dotnet test

# Option 2: Create kind cluster first
kind create cluster --name kf-integrations
kubectl config rename-context kind-kf-integrations kf-integrations
export RUN_INTEGRATION_TESTS=true
dotnet test
```

### Generate Code Coverage Report
```bash
# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults

# Install report generator (one-time)
dotnet tool install -g dotnet-reportgenerator-globaltool

# Generate HTML report
reportgenerator \
  -reports:"./TestResults/**/coverage.cobertura.xml" \
  -targetdir:"./TestResults/CoverageReport" \
  -reporttypes:Html

# Open report (macOS)
open ./TestResults/CoverageReport/index.html
```

---

## 📊 Test Results Summary

### Current Status
- **Unit Tests:** 412 tests, 100% passing ✅
- **Integration Tests:** 120 tests, 100% passing ✅
- **Total:** 532 tests across 7 store types

### What's Tested
✅ All 7 Kubernetes store types
✅ 11 key types (RSA, EC, DSA, Ed25519, Ed448)
✅ 20+ password scenarios
✅ Certificate chains
✅ Error conditions
✅ Edge cases

---

## 🤖 GitHub Actions (Automatic)

### What Runs on Every PR
1. **PR Quality Gate** (~3 min)
   - Fast build + quick unit tests
   - PR size and title validation

2. **Unit Tests** (~10 min)
   - All 412 unit tests
   - .NET 8.0 and 10.0
   - Code coverage

3. **Integration Tests** (~10 min)
   - All 120 integration tests
   - kind cluster (K8s v1.29)
   - Framework-specific namespace isolation
   - Automatic cleanup

**Total:** ~23 minutes for complete validation

### Manual Workflow Triggers
```bash
# Trigger unit tests
gh workflow run unit-tests.yml

# Trigger integration tests with specific K8s version
gh workflow run integration-tests.yml -f kubernetes-version=v1.28.0
```

---

## 📁 Documentation

| Document | Purpose |
|----------|---------|
| **`TESTING.md`** | Comprehensive testing guide (main reference) |
| **`TESTING_QUICKSTART.md`** | This file - quick commands |
| **`.github/workflows/README.md`** | GitHub Actions workflow details |

---

## 🐛 Common Issues & Solutions

### Issue: Integration tests skipped
```bash
# Solution: Set environment variable
export RUN_INTEGRATION_TESTS=true
dotnet test
```

### Issue: Kubeconfig not found
```bash
# Solution: Verify kubeconfig exists
ls -la ~/.kube/config

# Or create kind cluster
kind create cluster --name kf-integrations
```

### Issue: Context 'kf-integrations' not found
```bash
# Solution: Rename your context
kubectl config rename-context <your-context> kf-integrations

# Or for kind
kubectl config rename-context kind-kf-integrations kf-integrations
```

### Issue: Tests hang or timeout
```bash
# Solution: Check cluster health
kubectl cluster-info
kubectl get nodes

# Cleanup stuck namespaces
kubectl delete namespace -l managed-by=keyfactor-k8s-orchestrator-tests
```

---

## 🎯 Before Creating a PR

**Checklist:**
- [ ] Run unit tests locally: `dotnet test`
- [ ] All tests passing
- [ ] No compilation errors
- [ ] (Optional) Run integration tests if changes affect K8s operations
- [ ] Review changed files

**Then:**
1. Push branch to GitHub
2. Create PR
3. Wait for CI workflows (~23 min)
4. Review automated test results in PR

---

## 💡 Pro Tips

### Run Tests Faster
```bash
# Run specific test class
dotnet test --filter "FullyQualifiedName~K8SJKSStoreTests"

# Run specific test method
dotnet test --filter "FullyQualifiedName~K8SJKSStoreTests.DeserializeRemoteCertificateStore_ValidJks"

# Skip slow tests
dotnet test --filter "FullyQualifiedName!~Integration"
```

### Watch Mode (Auto-rerun on Changes)
```bash
dotnet watch test
```

### Parallel Execution
```bash
# Run with maximum parallelism
dotnet test --parallel
```

### Detailed Output
```bash
# Verbose logging
dotnet test --verbosity detailed

# Diagnostic logging
dotnet test --verbosity diagnostic
```

---

## 📞 Need Help?

1. **Check the docs:**
   - `TESTING.md` - Comprehensive guide
   - `.github/workflows/README.md` - CI/CD workflows

2. **Review test output:**
   ```bash
   dotnet test --verbosity detailed --logger "console;verbosity=detailed"
   ```

3. **Create an issue:**
   https://github.com/Keyfactor/k8s-orchestrator/issues

---

**Ready to test? Run:** `dotnet test` 🚀
