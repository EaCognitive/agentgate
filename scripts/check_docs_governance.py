#!/usr/bin/env python3
"""Strict docs governance checks for AgentGate."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
BINDER_DIR = REPO_ROOT / "docs" / "_binder"
ALLOWED_CLASSES = {"core", "reference", "archive", "duplicate"}
ALLOWED_ROOT_MARKDOWN = {
    "README.md",
    "README_PYPI.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "CLAUDE.md",
}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
NAV_EXEMPT_CLASSES = {"archive", "duplicate"}
IGNORED_MARKDOWN_PREFIXES = (
    ".agent/",
    ".agents/",
    ".backup/",
    ".codex/",
    ".pytest_cache/",
    ".venv/",
    "dashboard/.next/",
    "dashboard/e2e/test-results/",
    "dashboard/node_modules/",
    ".worktrees/",
    "tests/artifacts/workflow/",
    "tests/artifacts/reports/latest_policy_governance_report/",
    "CLAUDE.md",
)


class GovernanceError(Exception):
    """Raised when docs governance validation fails."""


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file and enforce mapping root type."""
    if not path.exists():
        raise GovernanceError(f"Required YAML file missing: {path.relative_to(REPO_ROOT)}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise GovernanceError(f"YAML root must be a mapping: {path.relative_to(REPO_ROOT)}")
    return data


def list_markdown_files() -> list[str]:
    """Return tracked markdown files with filesystem fallback for non-git contexts."""
    files: list[str] = []
    if shutil.which("git"):
        result = subprocess.run(
            ["git", "ls-files", "*.md", "*.MD"],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            files = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    if not files:
        if shutil.which("rg"):
            result = subprocess.run(
                ["rg", "--files", "-g", "*.md", "-g", "*.MD"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        else:
            markdown_paths = list(REPO_ROOT.rglob("*.md")) + list(REPO_ROOT.rglob("*.MD"))
            files = [
                path.relative_to(REPO_ROOT).as_posix()
                for path in markdown_paths
                if path.is_file()
            ]

    return sorted(
        path
        for path in set(files)
        if not any(path.startswith(prefix) for prefix in IGNORED_MARKDOWN_PREFIXES)
    )


def parse_nav(nav_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse nav sections and return flattened page entries."""
    sections = nav_data.get("sections")
    if not isinstance(sections, list):
        raise GovernanceError("docs/_binder/nav.yaml must include a 'sections' list")

    pages: list[dict[str, Any]] = []
    for section in sections:
        pages.extend(_parse_nav_section(section))
    return pages


def _parse_nav_section(section: Any) -> list[dict[str, Any]]:
    """Parse and validate one nav section."""
    if not isinstance(section, dict):
        raise GovernanceError("Each section in nav.yaml must be a mapping")

    section_id = section.get("id")
    section_title = section.get("title")
    section_pages = section.get("pages")

    if not isinstance(section_id, str) or not section_id:
        raise GovernanceError("Each section in nav.yaml must define a non-empty string 'id'")
    if not isinstance(section_title, str) or not section_title:
        raise GovernanceError(f"Section '{section_id}' must define a non-empty string 'title'")
    if not isinstance(section_pages, list):
        raise GovernanceError(f"Section '{section_id}' must define a 'pages' list")

    pages: list[dict[str, Any]] = []
    for page in section_pages:
        if not isinstance(page, dict):
            raise GovernanceError(f"Section '{section_id}' has a non-mapping page entry")
        pages.append({**page, "_section_id": section_id, "_section_title": section_title})
    return pages


def normalize_link_target(raw_target: str) -> str:
    """Normalize markdown link target and strip optional title suffix."""
    target = raw_target.strip().strip("<>")
    if " " in target:
        target = target.split(" ", 1)[0]
    return target


def is_external_or_non_file_link(target: str) -> bool:
    """Return True when link target should be skipped for file checks."""
    lowered = target.lower()
    return lowered.startswith(("http://", "https://", "mailto:", "tel:", "#"))


def check_broken_links(files_to_check: set[str], classification_map: dict[str, str]) -> list[str]:
    """Validate internal markdown links and return collected errors."""
    errors: list[str] = []
    for rel_path in sorted(files_to_check):
        errors.extend(_check_file_links(rel_path, classification_map))
    return errors


def _check_file_links(rel_path: str, classification_map: dict[str, str]) -> list[str]:
    """Validate markdown links inside one file."""
    errors: list[str] = []
    if classification_map.get(rel_path) == "archive":
        return errors

    absolute = REPO_ROOT / rel_path
    try:
        content = absolute.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"Cannot read markdown file '{rel_path}': {exc}")
        return errors

    for match in LINK_RE.finditer(content):
        href = normalize_link_target(match.group(1))
        error = _validate_link_target(rel_path, absolute, href)
        if error:
            errors.append(error)
    return errors


def _validate_link_target(rel_path: str, absolute: Path, href: str) -> str | None:
    """Validate one link target from a markdown file."""
    error: str | None = None
    if href and not is_external_or_non_file_link(href) and not href.startswith("/"):
        clean_path = href.split("#", 1)[0].split("?", 1)[0]
        if clean_path:
            resolved = (absolute.parent / clean_path).resolve()
            if not str(resolved).startswith(str(REPO_ROOT.resolve())):
                error = (
                    f"Invalid path traversal in '{rel_path}': '{href}' resolves outside repository"
                )
            elif not (resolved.exists() and resolved.is_file()):
                md_fallback = resolved.with_suffix(".md")
                if not (md_fallback.exists() and md_fallback.is_file()):
                    error = f"Broken internal link in '{rel_path}': '{href}'"
    return error


def build_classification_map(
    class_entries: Any,
    markdown_set: set[str],
) -> tuple[dict[str, str], list[str]]:
    """Build path->class mapping and return validation errors."""
    errors: list[str] = []
    if not isinstance(class_entries, list):
        return {}, ["docs/_binder/classification.yaml must contain a 'files' list"]

    classification_map: dict[str, str] = {}
    for entry in class_entries:
        _add_classification_entry(entry, classification_map, errors)

    missing_classification = sorted(markdown_set - set(classification_map.keys()))
    if missing_classification:
        errors.append("Unclassified markdown files: " + ", ".join(missing_classification))

    extra_classification = sorted(set(classification_map.keys()) - markdown_set)
    if extra_classification:
        errors.append(
            "classification.yaml references missing markdown files: "
            + ", ".join(extra_classification)
        )

    return classification_map, errors


def _add_classification_entry(
    entry: Any,
    classification_map: dict[str, str],
    errors: list[str],
) -> None:
    """Validate and add one classification mapping entry."""
    if not isinstance(entry, dict):
        errors.append("classification.yaml contains a non-mapping file entry")
        return

    rel = entry.get("path")
    klass = entry.get("class")
    if not isinstance(rel, str) or not rel:
        errors.append("classification.yaml entry missing valid 'path'")
        return
    if not isinstance(klass, str) or klass not in ALLOWED_CLASSES:
        errors.append(
            f"classification.yaml entry for '{rel}' must use one of: {sorted(ALLOWED_CLASSES)}"
        )
        return
    if rel in classification_map:
        errors.append(f"classification.yaml duplicate path entry: '{rel}'")
        return
    classification_map[rel] = klass


def validate_root_markdown(markdown_files: list[str]) -> list[str]:
    """Validate allowed root-level markdown files."""
    unexpected_root_docs = [
        path for path in markdown_files if "/" not in path and path not in ALLOWED_ROOT_MARKDOWN
    ]
    if not unexpected_root_docs:
        return []
    return ["Unexpected root-level markdown files: " + ", ".join(unexpected_root_docs)]


def validate_nav_pages(
    nav_pages: list[dict[str, Any]],
    markdown_set: set[str],
) -> tuple[set[str], list[str]]:
    """Validate nav pages and return nav paths plus errors."""
    errors: list[str] = []
    slug_seen: set[str] = set()
    alias_seen: dict[str, str] = {}
    nav_paths: set[str] = set()

    for page in nav_pages:
        _validate_single_nav_page(
            page,
            markdown_set,
            slug_seen=slug_seen,
            alias_seen=alias_seen,
            nav_paths=nav_paths,
            errors=errors,
        )

    return nav_paths, errors


def _validate_single_nav_page(
    page: dict[str, Any],
    markdown_set: set[str],
    *,
    slug_seen: set[str],
    alias_seen: dict[str, str],
    nav_paths: set[str],
    errors: list[str],
) -> None:
    """Validate one nav page entry."""
    page_id = page.get("id")
    title = page.get("title")
    slug = page.get("slug")
    page_path = page.get("path")
    external_url = page.get("external_url")
    aliases = page.get("aliases", [])
    section_id = page.get("_section_id", "")

    if not isinstance(page_id, str) or not page_id:
        errors.append(f"Nav page in section '{section_id}' must define non-empty string 'id'")
        return
    if not isinstance(title, str) or not title:
        errors.append(f"Nav page '{page_id}' must define non-empty string 'title'")
    if not isinstance(slug, str) or not slug:
        errors.append(f"Nav page '{page_id}' must define non-empty string 'slug'")
        return

    if slug in slug_seen:
        errors.append(f"Duplicate nav slug detected: '{slug}'")
    slug_seen.add(slug)

    if bool(page_path) == bool(external_url):
        errors.append(f"Nav page '{page_id}' must define exactly one of 'path' or 'external_url'")

    _validate_nav_page_path(page_id, page_path, markdown_set, nav_paths, errors)
    _validate_nav_aliases(
        page_id,
        section_id,
        slug,
        aliases,
        alias_seen=alias_seen,
        errors=errors,
    )


def _validate_nav_page_path(
    page_id: str,
    page_path: Any,
    markdown_set: set[str],
    nav_paths: set[str],
    errors: list[str],
) -> None:
    """Validate optional path mapping for one nav page."""
    if not isinstance(page_path, str):
        return
    nav_paths.add(page_path)
    if page_path not in markdown_set:
        errors.append(f"Nav page '{page_id}' references missing file path: '{page_path}'")


def _validate_nav_aliases(
    page_id: str,
    section_id: str,
    slug: str,
    aliases: Any,
    *,
    alias_seen: dict[str, str],
    errors: list[str],
) -> None:
    """Validate alias uniqueness for one nav page."""
    if not isinstance(aliases, list):
        errors.append(f"Nav page '{page_id}' aliases must be a list")
        return

    for alias in aliases:
        if not isinstance(alias, str) or not alias:
            errors.append(f"Nav page '{page_id}' has invalid alias value")
            continue

        alias_keys = {alias, f"{section_id}/{alias}" if "/" not in alias else alias}
        for alias_key in alias_keys:
            existing_slug = alias_seen.get(alias_key)
            if existing_slug and existing_slug != slug:
                errors.append(
                    f"Alias collision for '{alias_key}' between '{existing_slug}' and '{slug}'"
                )
            alias_seen[alias_key] = slug


def validate_nav_coverage(
    markdown_set: set[str],
    nav_paths: set[str],
    classification_map: dict[str, str],
) -> list[str]:
    """Validate nav coverage vs classification policy."""
    errors: list[str] = []
    required_nav_files = {
        path for path, klass in classification_map.items() if klass not in NAV_EXEMPT_CLASSES
    }
    missing_from_nav = sorted(required_nav_files - nav_paths)
    if missing_from_nav:
        errors.append(
            "Required markdown files missing from nav.yaml: " + ", ".join(missing_from_nav)
        )

    non_nav_classified_files = {
        path for path, klass in classification_map.items() if klass in NAV_EXEMPT_CLASSES
    }
    orphan_files = sorted(markdown_set - nav_paths - non_nav_classified_files)
    if orphan_files:
        errors.append(
            "Orphan markdown files (neither in nav nor duplicate/archive class): "
            + ", ".join(orphan_files)
        )
    return errors


def validate_migration_map(migration: dict[str, Any]) -> list[str]:
    """Validate migration map structure."""
    migration_entries = migration.get("entries")
    if isinstance(migration_entries, list):
        return []
    return ["migration-map.yaml must contain an 'entries' list"]


def run_governance_checks() -> list[str]:
    """Run all governance checks and return collected errors."""
    errors: list[str] = []

    try:
        nav = load_yaml(BINDER_DIR / "nav.yaml")
        classification = load_yaml(BINDER_DIR / "classification.yaml")
        migration = load_yaml(BINDER_DIR / "migration-map.yaml")
    except GovernanceError as exc:
        return [str(exc)]

    markdown_files = list_markdown_files()
    markdown_set = set(markdown_files)

    classification_map, classification_errors = build_classification_map(
        classification.get("files"),
        markdown_set,
    )
    errors.extend(classification_errors)
    errors.extend(validate_root_markdown(markdown_files))

    try:
        nav_pages = parse_nav(nav)
    except GovernanceError as exc:
        errors.append(str(exc))
        nav_pages = []

    nav_paths, nav_errors = validate_nav_pages(nav_pages, markdown_set)
    errors.extend(nav_errors)
    errors.extend(validate_nav_coverage(markdown_set, nav_paths, classification_map))
    errors.extend(validate_migration_map(migration))
    errors.extend(check_broken_links(nav_paths, classification_map))

    if not errors:
        non_nav_classified_files = {
            path for path, klass in classification_map.items() if klass in NAV_EXEMPT_CLASSES
        }
        print(
            "Docs governance check passed: "
            f"{len(markdown_files)} markdown files, "
            f"{len(nav_paths)} nav pages, "
            f"{len(non_nav_classified_files)} non-nav classified files"
        )

    return errors


def main() -> int:
    """CLI entrypoint for docs governance check."""
    errors = run_governance_checks()
    if not errors:
        return 0

    print("Docs governance check failed:")
    for item in errors:
        print(f"- {item}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
