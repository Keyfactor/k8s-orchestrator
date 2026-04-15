# GitHub Advanced Security Workflows

This document describes the security and code quality workflows configured for this repository.

## GitHub Advanced Security (GHAS) Workflows

### 1. CodeQL Analysis (`codeql-analysis.yml`)
**Purpose**: Automated security vulnerability detection in C# code

**Runs on**:
- Push to `main` and `release-*` branches
- Pull requests to `main` and `release-*` branches
- Weekly schedule (Mondays at 6:00 AM UTC)
- Manual trigger

**What it does**:
- Analyzes C# code for security vulnerabilities
- Uses GitHub's CodeQL engine with security-extended and security-and-quality query packs
- Reports findings to GitHub Security tab
- Builds the project to ensure complete analysis

**Configuration**: Uses default CodeQL queries plus extended security queries for comprehensive coverage.

---

### 2. Dependency Review (`dependency-review.yml`)
**Purpose**: Automated dependency vulnerability scanning on pull requests

**Runs on**:
- Pull requests to `main` and `release-*` branches

**What it does**:
- Scans all dependencies for known vulnerabilities
- Checks licenses for compliance
- Fails PRs with moderate or higher severity vulnerabilities
- Posts summary comments on PRs

**Configuration**:
- Fails on: moderate or higher severity vulnerabilities
- License checks: enabled
- Vulnerability checks: enabled

---

### 3. Dependency Submission (`dependency-submission.yml`)
**Purpose**: Keep GitHub's dependency graph updated

**Runs on**:
- Push to `main` branch
- Manual trigger

**What it does**:
- Submits dependency snapshot to GitHub
- Updates dependency graph automatically
- Enables Dependabot alerts

---

## Security Scanning Workflows

### 4. .NET Security Scan (`dotnet-security-scan.yml`)
**Purpose**: Scan for vulnerable NuGet packages

**Runs on**:
- Push to `main` and `release-*` branches
- Pull requests
- Weekly schedule (Tuesdays at 8:00 AM UTC)
- Manual trigger

**What it does**:
- Runs `dotnet list package --vulnerable` to find vulnerable dependencies
- Checks for outdated packages using dotnet-outdated tool
- Fails build if critical vulnerabilities are found
- Uploads scan results as artifacts

---

### 5. Secret Scanning (`secret-scanning.yml`)
**Purpose**: Detect exposed secrets and credentials

**Runs on**:
- Push to any branch
- Pull requests to `main` and `release-*` branches
- Manual trigger

**What it does**:
- Uses TruffleHog OSS to scan for secrets
- Scans full git history
- Reports findings to Security tab

**Note**: GitHub's native Secret Scanning with push protection should also be enabled in repository settings.

---

## Code Quality Workflows

### 6. Code Quality Analysis (`code-quality.yml`)
**Purpose**: Enforce code quality standards

**Runs on**:
- Push to `main` and `release-*` branches
- Pull requests
- Manual trigger

**What it does**:
- Checks code formatting with `dotnet format`
- Runs .NET code analyzers
- Generates code metrics
- Reports quality issues

---

### 7. PR Quality Gate (`pr-quality-gate.yml`)
**Purpose**: Comprehensive PR validation

**Runs on**:
- Pull requests to `main` and `release-*` branches

**What it does**:
- Builds and tests the solution
- Checks PR size and provides warnings for large PRs
- Validates PR title format (Conventional Commits)
- Checks for required files
- Warns about prohibited keywords (TODO, FIXME, etc.)
- Auto-labels PRs based on changed files

**PR Title Format**: Must follow Conventional Commits:
```
<type>: <description>

Types: feat, fix, docs, style, refactor, perf, test, chore, ci
Example: feat: Add support for PKCS12 certificates
```

---

### 8. License Compliance (`license-compliance.yml`)
**Purpose**: Track and validate dependency licenses

**Runs on**:
- Push to `main`
- Pull requests
- Monthly schedule (1st of each month at 9:00 AM UTC)
- Manual trigger

**What it does**:
- Generates license reports for all dependencies
- Exports license texts
- Warns about restricted licenses (GPL, AGPL)
- Uploads reports as artifacts

---

## Supply Chain Security

### 9. SBOM Generation (`sbom-generation.yml`)
**Purpose**: Generate Software Bill of Materials

**Runs on**:
- Push to `main`
- Tagged releases (`v*.*.*`)
- Release published events
- Manual trigger

**What it does**:
- Generates SBOM using CycloneDX
- Creates JSON and XML formats
- Uploads as build artifacts
- Attaches SBOM to GitHub releases

**Formats**: CycloneDX JSON and XML

---

### 10. Container Security Scan (`container-security-scan.yml`)
**Purpose**: Scan Docker container images for vulnerabilities

**Runs on**:
- Push to branches (when Dockerfile changes)
- Pull requests (when Dockerfile changes)
- Manual trigger

**Status**: Currently disabled (`if: false`) - enable when Dockerfile is added

**What it does**:
- Builds container image
- Scans with Trivy for vulnerabilities
- Scans with Grype/Anchore
- Reports to GitHub Security tab
- Fails on HIGH or CRITICAL vulnerabilities

---

## Required Secrets

The following secrets should already be configured in repository settings:

| Secret Name | Used By | Purpose |
|------------|---------|---------|
| `V2BUILDTOKEN` | Keyfactor Workflow | Already configured |
| `SAST_TOKEN` | Keyfactor Workflow | Already configured |

No additional secrets are required for the security and quality workflows.

## GitHub Advanced Security Features

Ensure these are enabled in repository settings:

1. **Secret scanning** - Automatically detect exposed secrets
2. **Secret scanning push protection** - Block pushes containing secrets
3. **Dependency graph** - Track project dependencies
4. **Dependabot alerts** - Get notified of vulnerable dependencies
5. **Dependabot security updates** - Auto-create PRs to fix vulnerabilities
6. **Code scanning** - CodeQL analysis results

## Best Practices

1. **Review security alerts promptly**: Check the Security tab regularly
2. **Keep dependencies updated**: Review Dependabot PRs weekly
3. **Fix vulnerabilities before merging**: All security checks should pass
4. **Monitor SBOM changes**: Review supply chain changes in releases
5. **Use semantic PR titles**: Helps with changelog generation
6. **Keep PRs small**: Aim for < 500 lines changed per PR
7. **Run manual scans**: Use workflow_dispatch for on-demand scanning

## Scheduled Scans Summary

| Workflow | Schedule | Day | Time (UTC) |
|----------|----------|-----|------------|
| CodeQL Analysis | Weekly | Monday | 6:00 AM |
| .NET Security Scan | Weekly | Tuesday | 8:00 AM |
| License Compliance | Monthly | 1st | 9:00 AM |

## Troubleshooting

**CodeQL fails to build**: Ensure all .NET SDKs are correctly specified in the workflow.

**Dependency Review blocking PRs**: Check for vulnerable dependencies with `dotnet list package --vulnerable`.

**Secret scanning false positives**: Mark as false positive in Security tab, or update `.github/secret_scanning.yml` to exclude patterns.

**SBOM generation fails**: Ensure CycloneDX tool is compatible with your .NET version.

**Container scan disabled**: Enable by setting `if: true` in `container-security-scan.yml` once you have a Dockerfile.

## Additional Resources

- [GitHub Advanced Security Documentation](https://docs.github.com/en/code-security)
- [CodeQL for C#](https://codeql.github.com/docs/codeql-language-guides/codeql-for-csharp/)
- [Dependency Review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
