# Publishing AgentGate to PyPI

Use this guide when you are cutting a package release to PyPI. It is a
repository maintenance workflow, not part of the dashboard docs path.

## Prerequisites

1. Create a PyPI account at <https://pypi.org/account/register/>.
2. Verify the account email address.
3. Create an API token at <https://pypi.org/manage/account/token/>.
4. Store the token securely. PyPI tokens begin with `pypi-`.

## Release Steps

### 1. Install build tooling

```bash
python3 -m pip install --upgrade build twine
```

### 2. Remove previous build artifacts

```bash
rm -rf dist/ build/ *.egg-info
```

### 3. Build the package

```bash
python3 -m build
```

Expected artifacts:

- `dist/ea_agentgate-<version>-py3-none-any.whl`
- `dist/ea_agentgate-<version>.tar.gz`

### 4. Validate the distribution

```bash
python3 -m twine check dist/*
```

The command must report `PASSED` before upload.

### 5. Upload to PyPI

```bash
python3 -m twine upload dist/*
```

Credentials:

- username: `__token__`
- password: your PyPI API token

### 6. Verify the published package

```bash
pip install ea-agentgate
python3 -c "from ea_agentgate import Agent; print('import ok')"
```

## Version Update Policy

Before rebuilding a new release:

1. Bump `version` in `pyproject.toml`.
2. Update `ea_agentgate/__init__.py` if it exposes `__version__`.
3. Rebuild and rerun `twine check`.

PyPI does not allow overwriting an existing version. If upload fails because the
file already exists, publish a new version number.

## README Badge

If the README contains a PyPI badge, it should point to:

```markdown
[![PyPI version](https://badge.fury.io/py/ea-agentgate.svg)](https://pypi.org/project/ea-agentgate/)
```

## Common Failures

- `File already exists`
  The version has already been published. Bump the version and rebuild.
- `Invalid username/password`
  Use `__token__` as the username and the API token as the password.
- badge delay
  Badge providers may take several minutes to refresh after a release.
