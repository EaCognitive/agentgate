"""Canonical role utilities and legacy alias handling."""

from __future__ import annotations

import os


CANONICAL_ROLES = frozenset(
    {
        "admin",
        "security_admin",
        "approver",
        "auditor",
        "developer",
        "agent_operator",
        "service_agent",
        "viewer",
    }
)

LEGACY_ROLE_ALIASES = {
    "operator": "approver",
}


def is_legacy_alias_enabled() -> bool:
    """Return True when legacy role aliases are accepted."""
    value = os.getenv("ROLE_OPERATOR_ALIAS_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "no", "off"}


def normalize_role(role: str, *, allow_legacy_alias: bool = True) -> str:
    """Normalize role names and apply allowed legacy aliases."""
    normalized = role.strip().lower()
    if allow_legacy_alias and is_legacy_alias_enabled():
        return LEGACY_ROLE_ALIASES.get(normalized, normalized)
    return normalized


def validate_role(role: str, *, allow_legacy_alias: bool = True) -> str:
    """Validate a role and return canonical value.

    Raises:
        ValueError: If the role is not recognized.
    """
    normalized = normalize_role(role, allow_legacy_alias=allow_legacy_alias)
    if normalized not in CANONICAL_ROLES:
        if role.strip().lower() in LEGACY_ROLE_ALIASES and not is_legacy_alias_enabled():
            raise ValueError("Legacy role alias 'operator' is disabled. Use 'approver'.")
        raise ValueError(f"Unsupported role: {role}")
    return normalized


def default_risk_for_role(role: str) -> str:
    """Return baseline principal risk level for a canonical role."""
    normalized = normalize_role(role)
    if normalized in {"admin", "security_admin", "approver", "agent_operator"}:
        return "R2"
    return "R1"
