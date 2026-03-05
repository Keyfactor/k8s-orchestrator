# GitHub Actions Workflows

This directory contains CI/CD workflows for the Keyfactor Kubernetes Universal Orchestrator Extension.

## Workflows Overview

### 🧪 Testing Workflows

#### `unit-tests.yml` - Unit Test Suite
**Trigger:** Pull requests, pushes to main, manual dispatch
**Duration:** ~5 minutes
**Purpose:** Comprehensive unit testing across .NET versions

**What it does:**
- Runs all 134 unit tests
- Tests on .NET 8.0 and 10.0 (matrix)
- Collects code coverage
- Uploads coverage to Codecov (if configured)
- Generates HTML coverage report
- Publishes test results to PR

**Artifacts:**
- `unit-test-results-8.0.x` - Test results for .NET 8.0
- `unit-test-results-10.0.x` - Test results for .NET 10.0
- `coverage-report-net8` - HTML coverage report (.NET 8.0 only)

**Required secrets:**
- `CODECOV_TOKEN` (optional) - For uploading coverage to Codecov

**Manual trigger:**
```bash
gh workflow run unit-tests.yml
```

---

#### `integration-tests.yml` - Integration Test Suite
**Trigger:** Pull requests, pushes to main, manual dispatch
**Duration:** ~10 minutes
**Purpose:** End-to-end testing against real Kubernetes cluster

**What it does:**
- Creates kind (Kubernetes in Docker) cluster with K8s v1.29
- Runs all 55 integration tests
- Tests all 7 store types against live cluster
- Collects diagnostic info on failure
- Cleans up test resources
- Publishes test results to PR

**Artifacts:**
- `integration-test-results-k8s-v1.29.0` - Test results
- `kind-logs-k8s-v1.29.0` - Cluster logs (on failure only)

**Manual trigger with custom K8s version:**
```bash
gh workflow run integration-tests.yml -f kubernetes-version=v1.28.0
```

**Available K8s versions:**
- `v1.29.0` (default)
- `v1.28.0`
- `v1.27.0`

---

### 🔍 Quality & Security Workflows

#### `pr-quality-gate.yml` - PR Quality Gate
**Trigger:** Pull requests to main/release branches
**Duration:** ~3 minutes
**Purpose:** Fast quality checks for PRs

**What it does:**
- Builds solution (Release configuration)
- Runs quick unit tests (excludes integration tests)
- Checks PR size (warns if >1000 lines changed)
- Validates PR title (conventional commits)
- Checks for breaking changes in commits
- Verifies required files exist
- Warns about prohibited keywords (TODO, FIXME, etc.)
- Auto-labels PR based on files changed

**Note:** This provides fast feedback. Comprehensive tests run in `unit-tests.yml` and `integration-tests.yml`.

---

#### `code-quality.yml` - Code Quality Analysis
**Trigger:** Pull requests, scheduled
**Purpose:** Static code analysis and linting

---

#### `codeql-analysis.yml` - CodeQL Security Scanning
**Trigger:** Pull requests, scheduled, push to main
**Purpose:** Automated security vulnerability detection

---

#### `container-security-scan.yml` - Container Security
**Trigger:** Pull requests affecting Dockerfiles, scheduled
**Purpose:** Docker image security scanning

---

#### `dotnet-security-scan.yml` - .NET Security Analysis
**Trigger:** Pull requests, scheduled
**Purpose:** .NET-specific security vulnerability scanning

---

#### `dependency-review.yml` - Dependency Review
**Trigger:** Pull requests
**Purpose:** Reviews dependency changes for known vulnerabilities

---

#### `dependency-submission.yml` - Dependency Graph
**Trigger:** Push to main
**Purpose:** Submits dependency graph to GitHub

---

#### `license-compliance.yml` - License Compliance Check
**Trigger:** Pull requests, scheduled
**Purpose:** Ensures all dependencies have compatible licenses

---

#### `sbom-generation.yml` - Software Bill of Materials
**Trigger:** Releases, manual
**Purpose:** Generates SBOM (Software Bill of Materials)

---

#### `secret-scanning.yml` - Secret Scanning
**Trigger:** Push, pull requests
**Purpose:** Prevents committing secrets/credentials

---

## Workflow Dependencies

```
┌─────────────────────────────────────────────────────────┐
│                     Pull Request                        │
└─────────────┬───────────────────────────────────────────┘
              │
              ├──► pr-quality-gate.yml (fast feedback)
              │     └──► Build + Quick Tests (~3 min)
              │
              ├──► unit-tests.yml (comprehensive)
              │     ├──► .NET 8.0 Tests + Coverage (~5 min)
              │     └──► .NET 10.0 Tests (~5 min)
              │
              ├──► integration-tests.yml (e2e)
              │     └──► K8s v1.29 Tests (~10 min)
              │
              ├──► code-quality.yml
              ├──► codeql-analysis.yml
              ├──► dotnet-security-scan.yml
              ├──► dependency-review.yml
              ├──► license-compliance.yml
              └──► secret-scanning.yml
```

## Test Workflow Details

### Unit Tests Matrix

| .NET Version | Tests Run | Coverage | Artifacts |
|--------------|-----------|----------|-----------|
| 8.0.x | 134 unit tests | ✅ Yes | Results + Coverage |
| 10.0.x | 134 unit tests | ❌ No | Results only |

**Why matrix?**
- Ensures compatibility with both target frameworks
- Catches framework-specific issues early
- Coverage collected once (.NET 8.0) to avoid duplication

### Integration Tests Setup

**Kubernetes Cluster:**
- **Provider:** kind (Kubernetes in Docker)
- **Version:** v1.29.0 (configurable via workflow_dispatch)
- **Configuration:** Single control-plane node
- **Context:** Renamed to `kf-integrations` for test compatibility

**Test Namespaces Created:**
```
keyfactor-k8sjks-integration-tests
keyfactor-k8spkcs12-integration-tests
keyfactor-k8scert-integration-tests
keyfactor-k8ssecret-integration-tests
keyfactor-k8stlssecr-integration-tests
keyfactor-k8scluster-test-ns1
keyfactor-k8scluster-test-ns2
keyfactor-k8sns-integration-tests
```

**Cleanup:**
- Automatic cleanup after tests complete
- Cleans up even if tests fail
- Exports logs on failure for debugging

## Understanding Test Results

### Where to Find Results

**In GitHub UI:**
1. Go to PR/commit → "Checks" tab
2. Click on workflow name
3. View test results inline

**As Artifacts:**
1. Go to workflow run
2. Scroll to "Artifacts" section
3. Download test results or coverage reports

### Test Result Formats

**Unit Tests:**
- `.trx` files - Test results (TRX format)
- `coverage.opencover.xml` - Code coverage (OpenCover format)
- HTML report - Human-readable coverage report

**Integration Tests:**
- `.trx` files - Test results (TRX format)
- Kind logs - Cluster logs (on failure)

### Reading Test Summaries

Test results are automatically added to PR as comments:

```markdown
## Unit Test Results (.NET 8.0)
✅ 134 tests passed
❌ 0 tests failed
⏭️ 0 tests skipped

## Integration Test Results
✅ 55 tests passed
❌ 0 tests failed
⏭️ 0 tests skipped
```

### Coverage Report

Coverage reports show:
- **Line coverage** - % of lines executed
- **Branch coverage** - % of conditional branches taken
- **Method coverage** - % of methods called

**Target metrics:**
- Line coverage: >80% (good), >90% (excellent)
- Branch coverage: >70% (good), >85% (excellent)

## Troubleshooting Workflow Failures

### Unit Test Failures

**Check:**
1. Review test output in workflow logs
2. Download `unit-test-results` artifact
3. Open `.trx` file in Visual Studio or rider
4. Check if failure is .NET version specific

**Common causes:**
- Framework-specific API differences
- Nullable reference warnings treated as errors
- Missing dependencies

### Integration Test Failures

**Check:**
1. Review test output in workflow logs
2. Download `integration-test-results` artifact
3. If available, download `kind-logs` artifact
4. Review namespace diagnostic info in logs

**Common causes:**
- Cluster not ready (timeout issues)
- Resource limits (kind cluster too small)
- Test namespace conflicts
- Kubeconfig context issues

### Workflow Syntax Errors

**Check:**
```bash
# Validate workflow syntax locally
gh workflow view unit-tests.yml

# Check workflow runs
gh run list --workflow=unit-tests.yml

# View logs
gh run view <run-id> --log
```

## Local Testing

### Test Workflows Locally

Use [act](https://github.com/nektos/act) to run workflows locally:

```bash
# Install act (macOS)
brew install act

# Run unit tests workflow
act pull_request --workflows .github/workflows/unit-tests.yml

# Run integration tests (requires Docker)
act pull_request --workflows .github/workflows/integration-tests.yml

# Run specific job
act -j test --workflows .github/workflows/unit-tests.yml
```

**Note:** Integration tests work best in actual CI due to kind cluster requirements.

## Maintenance

### Updating Workflow Versions

Dependencies to keep updated:
- `actions/checkout` - Currently v4
- `actions/setup-dotnet` - Currently v4
- `actions/upload-artifact` - Currently v4
- `EnricoMi/publish-unit-test-result-action` - Currently v2
- `helm/kind-action` - Currently using kind v0.20.0
- `codecov/codecov-action` - Currently v4

### Adding New Workflows

When adding new workflows:
1. Follow existing naming convention: `kebab-case.yml`
2. Add comprehensive comments
3. Include `workflow_dispatch` for manual testing
4. Set appropriate `timeout-minutes`
5. Add to this README
6. Test locally with `act` if possible

### Modifying Test Workflows

When modifying test workflows:
1. Test changes on a branch first
2. Verify both success and failure paths work
3. Check artifact uploads work correctly
4. Update this README if behavior changes
5. Consider backward compatibility

## Performance Optimization

### Workflow Speed Tips

**Unit Tests:**
- ✅ Cache restored packages (coming soon)
- ✅ Run .NET versions in parallel (matrix)
- ✅ Skip coverage on non-primary version
- ⚠️ Consider: Splitting into separate jobs by store type

**Integration Tests:**
- ✅ Use kind (faster than minikube/k3s)
- ✅ Single control-plane node (faster startup)
- ✅ Proper cleanup (prevents resource buildup)
- ⚠️ Consider: Reuse cluster across test suites

### Cost Optimization

**Free tier limits (GitHub Actions):**
- Public repos: Unlimited minutes
- Private repos: 2000 minutes/month

**Current usage per PR:**
- PR Quality Gate: ~3 minutes
- Unit Tests (matrix): ~10 minutes total (2x 5 min)
- Integration Tests: ~10 minutes
- **Total: ~23 minutes per PR**

## Best Practices

### ✅ Do's

- ✅ Run tests locally before pushing
- ✅ Keep workflows focused (single responsibility)
- ✅ Use matrices for version testing
- ✅ Upload artifacts for debugging
- ✅ Add timeouts to prevent hanging jobs
- ✅ Clean up resources after tests
- ✅ Use meaningful job/step names
- ✅ Add workflow dispatch for manual testing

### ❌ Don'ts

- ❌ Don't skip test failures in workflows
- ❌ Don't commit secrets (use GitHub Secrets)
- ❌ Don't run integration tests unnecessarily
- ❌ Don't ignore workflow warnings
- ❌ Don't make workflows too complex
- ❌ Don't forget to add `continue-on-error` where appropriate
- ❌ Don't leave hanging resources

## Additional Resources

- **Testing Guide:** See `TESTING.md`
- **Test Implementation:** See `UNIT_TEST_COMPLETION_SUMMARY.md`
- **Development Guide:** See `Development.md`
- **GitHub Actions Docs:** https://docs.github.com/en/actions

---

**Questions about workflows?**

Create an issue at: https://github.com/Keyfactor/k8s-orchestrator/issues
