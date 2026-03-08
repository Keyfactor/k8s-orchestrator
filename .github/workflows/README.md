# GitHub Actions Workflows

This directory contains CI/CD workflows for the Keyfactor Kubernetes Universal Orchestrator Extension.

## Architecture

This repository uses [Keyfactor Actions](https://github.com/Keyfactor/actions) v6 for standard CI/CD workflows, supplemented by repo-specific workflows for testing and security scanning.

```
Keyfactor Actions v6 (via starter.yml)
├── PR Quality Checks (15 automated checks)
│   ├── Secrets scanning (Gitleaks)
│   ├── Dependency review (CVE + licenses)
│   ├── Code quality (Roslyn analyzers)
│   ├── PR title validation (Conventional Commits)
│   ├── License compliance
│   └── More...
├── Release Management
├── Build & Packaging
├── SBOM Generation
└── Post-Release Tasks

Repo-Specific Workflows
├── unit-tests.yml (enhanced testing with Codecov)
├── integration-tests.yml (K8s cluster testing)
├── dotnet-security-scan.yml (scheduled vulnerability scans)
├── sbom-generation.yml (repo-specific SBOM config)
└── dependency-submission.yml (GitHub dependency graph)
```

## Workflows Overview

### 🚀 Core Workflow

#### `keyfactor-starter-workflow.yml` - Keyfactor CI/CD Bootstrap
**Trigger:** Pull requests, pushes, branch creation, manual dispatch
**Purpose:** Orchestrates standard Keyfactor CI/CD pipeline via v6

**What it provides:**
- Automatic language detection
- PR quality checks (secrets, dependencies, code quality, etc.)
- Version computation and release creation
- .NET build and packaging
- SBOM generation
- README generation
- Integration catalog updates

**See:** [Keyfactor Actions Documentation](https://github.com/Keyfactor/actions)

---

### 🧪 Testing Workflows

#### `unit-tests.yml` - Unit Test Suite
**Trigger:** Pull requests, pushes to main (on .cs/.csproj changes), manual dispatch
**Duration:** ~5 minutes
**Purpose:** Comprehensive unit testing with coverage reporting

**What it does:**
- Runs unit tests on .NET 8.0 and 10.0 (matrix strategy)
- Collects code coverage (OpenCover format)
- Uploads coverage to Codecov
- Generates HTML coverage reports
- Publishes test results to PR comments

**Artifacts:**
- `unit-test-results-8.0.x` - Test results for .NET 8.0
- `unit-test-results-10.0.x` - Test results for .NET 10.0
- `coverage-report-net8` - HTML coverage report

**Required secrets:**
- `V2BUILDTOKEN` - GitHub token for NuGet auth
- `CODECOV_TOKEN` (optional) - For Codecov uploads

---

#### `integration-tests.yml` - Integration Test Suite
**Trigger:** Pull requests, pushes to main (on .cs/.csproj changes), manual dispatch
**Duration:** ~10 minutes
**Purpose:** End-to-end testing against real Kubernetes cluster

**What it does:**
- Creates kind (Kubernetes in Docker) cluster
- Supports K8s versions: 1.27, 1.28, 1.29, 1.30, 1.31
- Runs all 7 store type tests
- Collects diagnostic logs on failure
- Publishes test results to PR

**Manual trigger with version selection:**
```bash
gh workflow run integration-tests.yml -f kubernetes_version=1.30
```

---

### 🔒 Security Workflows

#### `dotnet-security-scan.yml` - Vulnerability Scanning
**Trigger:** Push to main/release-*, PRs, weekly schedule, manual dispatch
**Purpose:** Detect vulnerable NuGet packages

**What it does:**
- Scans for known vulnerabilities via `dotnet list package --vulnerable`
- Checks for outdated packages
- Uploads vulnerability reports

**Artifacts:**
- `dotnet-security-scan-report` - Vulnerability scan results

---

### 📦 Dependency Workflows

#### `dependency-submission.yml` - Dependency Graph
**Trigger:** Push to main, manual dispatch
**Purpose:** Submit dependencies to GitHub Dependency Graph

**What it does:**
- Extracts NuGet dependencies
- Submits to GitHub for security alerts and Dependabot

---

#### `sbom-generation.yml` - Software Bill of Materials
**Trigger:** Push to main, tags, releases, manual dispatch
**Purpose:** Generate CycloneDX SBOM

**What it does:**
- Generates SBOM in JSON and XML formats
- Attaches to releases
- Uploads as artifacts (90-day retention)

---

## Quality Checks (via Keyfactor Actions v6)

The following checks run automatically on PRs via the starter workflow:

| Check | Blocking | Description |
|-------|----------|-------------|
| Secrets Scan | Yes | Gitleaks secret detection |
| Dependency Review | Yes | CVE and license scanning |
| Vulnerability Scan | Yes | `dotnet list --vulnerable` |
| License Compliance | Yes | GPL/AGPL detection |
| PR Title | Yes | Conventional Commits format |
| PR Size | Yes (>3000 lines) | Encourages smaller PRs |
| CHANGELOG | Yes | Ensures documentation |
| Code Quality | Yes | Roslyn analyzers |
| Unit Tests | Yes | .NET test execution |
| Code Formatting | Warning | `dotnet format` |
| Breaking Changes | Info | Flags for release notes |

---

## Required Secrets

| Secret | Required For | Description |
|--------|--------------|-------------|
| `V2BUILDTOKEN` | All workflows | GitHub token for API/NuGet access |
| `KF_GPG_PRIVATE_KEY` | Go builds | GPG signing key |
| `KF_GPG_PASSPHRASE` | Go builds | GPG passphrase |
| `CODECOV_TOKEN` | Unit tests | Codecov upload (optional) |
| `SAST_TOKEN` | Polaris scans | Security scanning |
| `DOCTOOL_ENTRA_USERNAME` | README gen | Entra authentication |
| `DOCTOOL_ENTRA_PASSWD` | README gen | Entra password |
| `COMMAND_CLIENT_ID` | README gen | Command API auth |
| `COMMAND_CLIENT_SECRET` | README gen | Command API auth |

---

## Manual Workflow Triggers

```bash
# Run unit tests
gh workflow run unit-tests.yml

# Run integration tests with specific K8s version
gh workflow run integration-tests.yml -f kubernetes_version=1.30

# Run security scan
gh workflow run dotnet-security-scan.yml

# Generate SBOM
gh workflow run sbom-generation.yml

# Submit dependencies
gh workflow run dependency-submission.yml
```

---

## Migration Notes

This repository was updated to use Keyfactor Actions v6, which consolidates many quality checks:

**Removed (now in v6):**
- `pr-quality-gate.yml` → `pr-quality-checks.yml`
- `code-quality.yml` → code-quality-csharp job
- `secret-scanning.yml` → secrets-scan job
- `dependency-review.yml` → dependency-review job
- `license-compliance.yml` → license-compliance job

**Kept (repo-specific features):**
- `unit-tests.yml` - Codecov, matrix testing, coverage reports
- `integration-tests.yml` - K8s-specific testing
- `dotnet-security-scan.yml` - Scheduled vulnerability scans
- `sbom-generation.yml` - Repo-specific SBOM config
- `dependency-submission.yml` - GitHub dependency graph
