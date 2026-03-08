#!/usr/bin/env python3
"""Validate repository naming governance for Python and non-code assets.

Rules:
1. Python importable paths (`server`, `ea_agentgate`, `tests`) must be snake_case.
2. Non-code asset/config paths (`deploy`, `docs`) must be kebab-case.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


SNAKE_CASE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
KEBAB_CASE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PYTHON_ROOTS = ("server", "ea_agentgate", "tests")
ASSET_ROOTS = ("deploy", "docs")
SKIP_NAMES = frozenset(
    {
        "__init__.py",
        "__main__.py",
        "__pycache__",
        "_version.py",
        ".gitkeep",
        "_binder",
        "_helpers.tpl",
        "README.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "Chart.yaml",
        "Chart.lock",
    }
)


def _is_allowed_helm_chart_artifact(path: Path) -> bool:
    """Allow Helm-managed chart package filenames with semantic versions."""
    parts = path.parts
    if len(parts) < 4:
        return False
    if parts[0:3] != ("deploy", "helm", "agentgate"):
        return False
    if "charts" not in parts:
        return False
    return path.suffix == ".tgz"


def _is_allowed_internal_report(path: Path) -> bool:
    """Allow uppercase historical report names under docs/internal-reports."""
    parts = path.parts
    if len(parts) < 3:
        return False
    return parts[0:2] == ("docs", "internal-reports") and path.suffix == ".md"


def _repository_paths() -> list[Path]:
    """Return current working tree paths from tracked and untracked repository files."""
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
        text=True,
    )
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
        text=True,
    )
    raw_paths = tracked.stdout.split("\0") + untracked.stdout.split("\0")
    unique_paths = {Path(raw_path) for raw_path in raw_paths if raw_path}
    return sorted(path for path in unique_paths if path.exists())


def _iter_components(path: Path) -> list[str]:
    """Return normalized path components without empty segments."""
    return [part for part in path.parts if part not in {".", ""}]


def _validate_python_path(path: Path, components: list[str]) -> list[str]:
    """Validate snake_case rules for Python import paths."""
    violations: list[str] = []
    for component in components:
        if component in SKIP_NAMES:
            continue
        if component.endswith(".py"):
            stem = component[:-3]
            if stem and not SNAKE_CASE_RE.fullmatch(stem):
                violations.append(f"{path}: python module '{component}' must be snake_case")
            continue
        if "." in component:
            continue
        if not SNAKE_CASE_RE.fullmatch(component):
            violations.append(f"{path}: python path segment '{component}' must be snake_case")
    return violations


def _validate_asset_path(path: Path, components: list[str]) -> list[str]:
    """Validate kebab-case rules for asset and docs paths."""
    if _is_allowed_helm_chart_artifact(path) or _is_allowed_internal_report(path):
        return []

    violations: list[str] = []
    for component in components:
        if component in SKIP_NAMES or component.startswith(".") or component.endswith(".py"):
            continue
        if "." in component:
            stem = component.rsplit(".", maxsplit=1)[0]
            if not KEBAB_CASE_RE.fullmatch(stem):
                violations.append(f"{path}: asset file stem '{stem}' must be kebab-case")
            continue
        if not KEBAB_CASE_RE.fullmatch(component):
            violations.append(f"{path}: asset path segment '{component}' must be kebab-case")
    return violations


def _validate_path(path: Path) -> list[str]:
    """Validate one path and return violation messages."""
    components = _iter_components(path)
    if not components:
        return []

    root = components[0]
    if root in PYTHON_ROOTS:
        return _validate_python_path(path, components)
    if root in ASSET_ROOTS:
        return _validate_asset_path(path, components)
    return []


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate naming governance rules.")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional explicit paths to validate. Defaults to tracked repository files.",
    )
    return parser.parse_args()


def main() -> int:
    """Run the naming governance check for explicit paths or the current repository."""
    args = _parse_args()
    if args.paths:
        paths = [Path(item) for item in args.paths]
    else:
        paths = _repository_paths()

    violations: list[str] = []
    for path in paths:
        violations.extend(_validate_path(path))

    if violations:
        print("Naming convention violations found:")
        for violation in violations:
            print(f"- {violation}")
        return 1

    print("Naming conventions check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
