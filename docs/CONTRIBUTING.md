# Contributing to AgentGate

Thank you for your interest in contributing to AgentGate. This document provides guidelines for contributions.

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/EaCognitive/agentgate.git
cd agentgate
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Run tests to verify setup:
```bash
pytest
```

## Code Standards

- Format code with `ruff format`
- Lint with `ruff check`
- Type check with `mypy ea_agentgate`
- All code must pass CI checks before merging

## Pull Request Process

1. Fork the repository and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass locally
4. Update documentation if needed
5. Submit a pull request with a clear description

## Commit Messages

Use clear, descriptive commit messages:
- `feat: add new middleware for X`
- `fix: resolve issue with Y`
- `docs: update README`
- `test: add tests for Z`

## Testing

- Write tests for all new features
- Maintain or improve code coverage
- Use pytest fixtures for common setup

## Questions?

Open an issue for questions or discussion.
