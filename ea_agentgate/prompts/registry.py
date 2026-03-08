"""Helpers for loading prompts from the managed prompt registry."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

_REGISTRY_FILE = "registry.json"


@lru_cache(maxsize=1)
def load_prompt_registry() -> dict[str, Any]:
    """Load and cache the prompt registry from package data."""
    registry_path = resources.files(__package__).joinpath(_REGISTRY_FILE)
    with registry_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Prompt registry must be a JSON object")
    return data


def _require_string(mapping: dict[str, Any], key: str) -> str:
    """Return a required string key from a mapping."""
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise KeyError(f"Prompt registry missing valid '{key}'")
    return value


def get_semantic_prompt(check_type: str) -> dict[str, str]:
    """Get semantic validator prompts for a check type."""
    registry = load_prompt_registry()
    semantic_section = registry.get("semantic_validator")
    if not isinstance(semantic_section, dict):
        raise KeyError("Prompt registry missing 'semantic_validator'")

    prompt_entry = semantic_section.get(check_type)
    if not isinstance(prompt_entry, dict):
        raise KeyError(f"Prompt registry missing semantic check '{check_type}'")

    return {
        "system": _require_string(prompt_entry, "system"),
        "prompt": _require_string(prompt_entry, "prompt"),
    }


def get_pii_detection_prompt() -> str:
    """Get the LLM prompt used by the PII detector."""
    registry = load_prompt_registry()
    pii_section = registry.get("pii_vault")
    if not isinstance(pii_section, dict):
        raise KeyError("Prompt registry missing 'pii_vault'")

    detection = pii_section.get("llm_detection")
    if not isinstance(detection, dict):
        raise KeyError("Prompt registry missing 'pii_vault.llm_detection'")

    return _require_string(detection, "prompt")
