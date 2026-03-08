"""Shared JSON policy file loading helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_policy_json(path: str | Path) -> tuple[Path, dict[str, Any]]:
    """Load a JSON policy document from disk with chained errors."""
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")

    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Failed to read policy file: {file_path}") from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in policy file '{file_path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Invalid policy in '{file_path}': expected a JSON object")
    return file_path, data
