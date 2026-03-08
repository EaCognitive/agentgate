# GitHub Actions Workflows

Enterprise-grade CI/CD workflows for AgentGate.

## Overview

This directory contains three production-ready GitHub Actions workflows:

1. **ci.yml** - Continuous Integration
2. **security.yml** - Security Scanning
3. **release.yml** - Release Management

## Workflows

### 1. CI Workflow (ci.yml)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual dispatch

**Jobs:**

| Job | Description | Timeout |
|-----|-------------|---------|
| `lint` | Code quality checks (ruff, pyright, mypy) | 10min |
| `test` | Cross-platform testing (Ubuntu, macOS, Windows) | 20min |
| `coverage-report` | Coverage analysis and reporting | 5min |
| `integration-tests` | Integration tests with Redis | 15min |
| `build-package` | Build Python distribution packages | 10min |
| `verify-install` | Verify package installation | 10min |
| `publish-pypi` | Publish to PyPI (tags only) | 10min |
| `status-check` | Overall CI status verification | 5min |

**Key Features:**
- Python 3.10, 3.11, 3.12 matrix testing
- Cross-platform validation (Linux, macOS, Windows)
- Comprehensive linting with ruff and type checking with pyright/mypy
- Code coverage tracking with Codecov integration
- Integration testing with Redis service
- Package build verification
- Automatic PyPI publishing on version tags

**Artifacts:**
- Test results (JUnit XML)
- Coverage reports (XML)
- Distribution packages (wheel, sdist)

### 2. Security Workflow (security.yml)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Daily schedule (2 AM UTC)
- Manual dispatch

**Jobs:**

| Job | Description | Tool |
|-----|-------------|------|
| `dependency-review` | Review dependency changes | GitHub Dependency Review |
| `bandit` | Python security linting | Bandit |
| `safety` | Vulnerability scanning | Safety |
| `pip-audit` | PyPI package auditing | pip-audit |
| `trivy` | Filesystem vulnerability scan | Trivy |
| `codeql` | Static analysis | GitHub CodeQL |
| `secret-scan` | Secret detection | TruffleHog |
| `semgrep` | SAST analysis | Semgrep |
| `license-check` | License compliance | pip-licenses |
| `security-summary` | Consolidated results | - |

**Key Features:**
- Multiple security scanning tools for comprehensive coverage
- SARIF report integration with GitHub Security tab
- Automated dependency vulnerability detection
- Secret scanning in git history
- License compliance verification (blocks GPL/AGPL)
- Daily scheduled scans for continuous monitoring

**Artifacts:**
- Bandit security reports (JSON)
- Safety vulnerability reports (JSON)
- Pip-audit reports (JSON)
- Trivy scan results (JSON)
- License compliance reports (JSON)

### 3. Release Workflow (release.yml)

**Triggers:**
- Push of version tags (v*.*.*)
- Manual dispatch with version input

**Jobs:**

| Job | Description | Timeout |
|-----|-------------|---------|
| `validate-release` | Version validation | 5min |
| `build-and-test` | Build and test before release | 20min |
| `build-docker` | Multi-arch Docker image build | 30min |
| `scan-docker` | Container security scanning | 15min |
| `sign-artifacts` | Sigstore artifact signing | 10min |
| `create-release` | GitHub release creation | 10min |
| `publish-pypi` | PyPI publication | 10min |
| `notify-slack` | Slack notification (optional) | 5min |
| `release-summary` | Release status summary | 5min |

**Key Features:**
- Semantic version validation
- Multi-architecture Docker builds (amd64, arm64)
- Container security scanning with Trivy
- SBOM generation (SPDX format)
- Artifact signing with Sigstore Cosign
- GitHub Container Registry (ghcr.io) publishing
- Automated GitHub Release creation
- PyPI package publication
- Optional Slack notifications

**Docker Image Tags:**
- `v1.2.3` - Full version
- `v1.2` - Major.minor
- `v1` - Major version
- `latest` - Latest release (main branch only)

**Artifacts:**
- Python packages (wheel, sdist)
- Package signatures (.sig files)
- SBOM (sbom.spdx.json)
- Release notes

## Configuration

### Required Secrets

| Secret | Purpose | Used In |
|--------|---------|---------|
| `PYPI_TOKEN` | PyPI API token for package publishing | ci.yml, release.yml |
| `CODECOV_TOKEN` | Codecov API token for coverage uploads | ci.yml |

### Optional Configuration

| Variable | Purpose | Used In |
|----------|---------|---------|
| `SLACK_WEBHOOK_URL` | Slack webhook for release notifications | release.yml |

### Setting Up Secrets

1. **PyPI Token:**
   ```bash
   # Generate token at https://pypi.org/manage/account/token/
   # Add to repository secrets as PYPI_TOKEN
   ```

2. **Codecov Token:**
   ```bash
   # Get token from https://codecov.io/gh/EaCognitive/agentgate
   # Add to repository secrets as CODECOV_TOKEN
   ```

3. **GitHub Container Registry:**
   ```bash
   # Automatically uses GITHUB_TOKEN (no setup needed)
   ```

### Repository Settings

#### Enable GitHub Security Features

1. Go to repository Settings > Security > Code security and analysis
2. Enable:
   - Dependency graph
   - Dependabot alerts
   - Dependabot security updates
   - Code scanning (CodeQL)
   - Secret scanning

#### Configure Environments

1. Create `pypi` environment in Settings > Environments
2. Add protection rules:
   - Required reviewers (optional)
   - Deployment branch pattern: `refs/tags/v*`

## Usage

### Running CI

CI runs automatically on every push and pull request. To run manually:

```bash
gh workflow run ci.yml
```

### Running Security Scans

Security scans run automatically on push/PR and daily. To run manually:

```bash
gh workflow run security.yml
```

### Creating a Release

1. **Update version in pyproject.toml:**
   ```toml
   version = "1.2.3"
   ```

2. **Commit and tag:**
   ```bash
   git add pyproject.toml
   git commit -m "Bump version to 1.2.3"
   git tag v1.2.3
   git push origin main --tags
   ```

3. **Release workflow runs automatically**

Alternatively, trigger manually:
```bash
gh workflow run release.yml -f version=v1.2.3
```

### Viewing Results

#### CI Status
```bash
gh run list --workflow=ci.yml
gh run view <run-id>
```

#### Security Reports
```bash
gh run list --workflow=security.yml
gh run view <run-id>

# Download artifacts
gh run download <run-id>
```

#### Release Status
```bash
gh release list
gh release view v1.2.3
```

## Workflow Status Badges

Add to README.md:

```markdown
![CI](https://github.com/EaCognitive/agentgate/workflows/CI/badge.svg)
![Security](https://github.com/EaCognitive/agentgate/workflows/Security%20Scan/badge.svg)
[![codecov](https://codecov.io/gh/EaCognitive/agentgate/branch/main/graph/badge.svg)](https://codecov.io/gh/EaCognitive/agentgate)
```

## Maintenance

### Updating Dependencies

GitHub Actions are automatically updated via Dependabot. Review and merge PRs promptly.

### Workflow Optimization

Monitor workflow duration in Actions tab:
- Target: CI < 15 minutes
- Target: Security < 30 minutes
- Target: Release < 60 minutes

### Artifact Retention

- Test results: 30 days
- Security reports: 30 days
- Python packages: 30 days
- SBOM: 90 days
- Signatures: 90 days

## Troubleshooting

### CI Failures

**Test failures:**
```bash
# Download test artifacts
gh run download <run-id> -n test-results-ubuntu-latest-3.12

# Run locally
uv run pytest tests/ -v
```

**Type check failures:**
```bash
uv run mypy ea_agentgate
uv run npx pyright ea_agentgate
```

### Security Scan Issues

**Bandit warnings:**
- Review bandit-report.json artifact
- Add `# nosec` comments with justification if false positive

**Dependency vulnerabilities:**
- Check safety-report.json and pip-audit-report.json
- Update affected dependencies
- Create security advisories if needed

### Release Failures

**Version mismatch:**
- Ensure pyproject.toml version matches tag
- Tag format must be `v1.2.3`

**PyPI upload failure:**
- Verify PYPI_TOKEN is valid
- Check if version already exists on PyPI

**Docker build failure:**
- Check Dockerfile.server syntax
- Verify multi-arch build compatibility

## Best Practices

1. **Always run tests locally before pushing:**
   ```bash
   uv run pytest tests/ -v
   uv run ruff check ea_agentgate
   uv run mypy ea_agentgate
   ```

2. **Review security reports weekly:**
   - Check GitHub Security tab
   - Address high/critical findings promptly

3. **Semantic versioning:**
   - Major: Breaking changes (v2.0.0)
   - Minor: New features (v1.1.0)
   - Patch: Bug fixes (v1.0.1)

4. **Keep changelog updated:**
   - Document all changes
   - Link to issues/PRs

5. **Monitor workflow costs:**
   - GitHub Actions minutes usage
   - Optimize matrix builds if needed

## Support

For issues with workflows:
1. Check workflow logs in Actions tab
2. Review this documentation
3. Open an issue with workflow run URL
4. Tag with `ci/cd` label

## License

These workflows are part of AgentGate and are licensed under MIT License.
