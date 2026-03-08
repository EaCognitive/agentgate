# Contributing to AgentGate

Thank you for your interest in contributing to AgentGate! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- Docker & Docker Compose
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/agentgate.git
cd agentgate
git remote add upstream https://github.com/EaCognitive/agentgate.git
```

## Development Setup

### Backend (Python)

```bash
# Create virtual environment
uv venv
source .venv/bin/activate

# Install all dependencies including dev tools
uv pip install -e ".[server,dev,all]"

# Setup pre-commit hooks
pre-commit install
```

### Frontend (Dashboard)

```bash
cd dashboard
npm install
```

### Database & Services

```bash
# Start PostgreSQL and Redis
docker compose up -d postgres redis

# Or use the full stack
docker compose up -d
```

### Environment Configuration

```bash
cp .env.example .env
# Edit .env with your configuration
```

## Making Changes

### Branch Naming

Use descriptive branch names:

```
feature/add-semantic-caching
fix/rate-limiter-redis-connection
docs/update-api-reference
refactor/middleware-chain
```

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add semantic caching middleware
fix: resolve Redis connection timeout in rate limiter
docs: update API authentication guide
test: add integration tests for PII vault
refactor: simplify middleware chain execution
chore: update dependencies
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding or updating tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `chore`: Maintenance tasks

## Code Standards

### Python

**Linting & Formatting:**
```bash
# Run ruff linter
ruff check ea_agentgate server

# Run ruff formatter
ruff format ea_agentgate server

# Run all linters
make lint
```

**Type Checking:**
```bash
# Pyright (strict mode)
pyright ea_agentgate

# MyPy
mypy ea_agentgate --strict
```

**Style Guidelines:**
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use `"""docstrings"""` for all public functions and classes
- Prefer `async`/`await` for I/O operations

### TypeScript

**Linting:**
```bash
cd dashboard
npm run lint
```

**Type Checking:**
```bash
npm run typecheck
# or
npx tsc --noEmit
```

**Style Guidelines:**
- Strict TypeScript mode enabled
- Use functional components with hooks
- Prefer named exports
- Use TanStack Query for server state

## Testing

### Backend Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ea_agentgate --cov-report=html

# Run specific test file
pytest tests/test_pii_vault.py

# Run tests matching pattern
pytest -k "rate_limit"

# Run only unit tests
pytest -m "not integration"

# Run integration tests (requires services)
pytest -m "integration"
```

### Frontend Tests

```bash
cd dashboard

# Unit tests
npm test

# E2E tests (requires running server)
npm run test:e2e

# E2E with UI
npm run test:e2e:ui
```

### Test Requirements

- All new features must include tests
- Minimum 90% coverage for new code
- Integration tests for API endpoints
- E2E tests for critical user flows

## Submitting Changes

### Pull Request Process

1. **Update your fork:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push your branch:**
   ```bash
   git push origin feature/your-feature
   ```

3. **Create Pull Request:**
   - Use a descriptive title following commit conventions
   - Fill out the PR template completely
   - Link related issues

4. **PR Requirements:**
   - All CI checks must pass
   - At least 1 approval required
   - No merge conflicts
   - Documentation updated if needed

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] E2E tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings introduced
```

## Release Process

Releases are automated via GitHub Actions when tags are pushed:

```bash
# Version bump (updates pyproject.toml)
bump2version patch  # 1.0.0 -> 1.0.1
bump2version minor  # 1.0.0 -> 1.1.0
bump2version major  # 1.0.0 -> 2.0.0

# Create and push tag
git tag v1.0.1
git push origin v1.0.1
```

The release workflow will:
1. Run full test suite
2. Build Python package
3. Build Docker images
4. Publish to PyPI
5. Create GitHub release
6. Push to container registry

## Getting Help

- **Discord:** [Join our community](https://discord.gg/agentgate)
- **Issues:** [GitHub Issues](https://github.com/EaCognitive/agentgate/issues)
- **Discussions:** [GitHub Discussions](https://github.com/EaCognitive/agentgate/discussions)

## Recognition

Contributors are recognized in release notes and the project README.

Thank you for contributing to AgentGate!

---

**Erick Aleman | AI Architect | AI Engineer | erick@eacognitive.com**
