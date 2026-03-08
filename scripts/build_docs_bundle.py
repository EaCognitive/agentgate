#!/usr/bin/env python3
"""Generate dashboard docs bundle JSON from markdown and binder metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
BINDER_DIR = REPO_ROOT / "docs" / "_binder"
OUT_FILE = REPO_ROOT / "dashboard" / "src" / "generated" / "docs-bundle.json"


def load_yaml(path: Path) -> Any:
    """Load a YAML file and return the parsed object."""
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def main() -> int:
    """Build the dashboard docs bundle from binder metadata and markdown files."""
    nav = load_yaml(BINDER_DIR / "nav.yaml")
    classification = load_yaml(BINDER_DIR / "classification.yaml")
    migration = load_yaml(BINDER_DIR / "migration-map.yaml")

    contents: dict[str, str] = {}
    for section in nav.get("sections", []):
        for page in section.get("pages", []):
            page_path = page.get("path")
            if not page_path:
                continue
            abs_path = REPO_ROOT / page_path
            if not abs_path.exists():
                raise FileNotFoundError(f"Referenced docs file missing: {page_path}")
            contents[page_path] = abs_path.read_text(encoding="utf-8")

    bundle = {
        "version": 1,
        "nav": nav,
        "classification": classification,
        "migration": migration,
        "contents": contents,
    }

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote docs bundle: {OUT_FILE.relative_to(REPO_ROOT)} ({len(contents)} pages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
