"""MCP privilege helpers for admin-gated operations."""

from __future__ import annotations

import os
from typing import Any

from .roles import normalize_role

_DEFAULT_PRIVILEGED_ROLES = ("admin",)
_DEFAULT_REQUIRED_SCOPES = ("mcp:admin", "mcp:access")
_TRUTHY_VALUES = {"1", "true", "yes", "on"}


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _TRUTHY_VALUES


def _parse_csv_items(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def mcp_privileged_roles() -> set[str]:
    """Return normalized roles that can perform MCP-privileged operations."""
    configured = os.getenv("MCP_PRIVILEGED_ROLES", ",".join(_DEFAULT_PRIVILEGED_ROLES))
    roles = {normalize_role(role, allow_legacy_alias=True) for role in _parse_csv_items(configured)}
    roles.discard("")
    if roles:
        return roles
    return set(_DEFAULT_PRIVILEGED_ROLES)


def mcp_required_scopes() -> set[str]:
    """Return accepted scope values for MCP-privileged operations."""
    configured = os.getenv("MCP_REQUIRED_SCOPES", ",".join(_DEFAULT_REQUIRED_SCOPES))
    scopes = set(_parse_csv_items(configured))
    if scopes:
        return scopes
    return set(_DEFAULT_REQUIRED_SCOPES)


def mcp_scope_enforced(environment: str) -> bool:
    """Return True when MCP scope checks are required."""
    explicit = os.getenv("MCP_REQUIRE_SCOPE")
    if explicit is not None and explicit.strip():
        return _is_truthy(explicit)
    return environment.strip().lower() in {"staging", "production"}


def extract_scopes_from_claims(claims: dict[str, Any] | None) -> set[str]:
    """Extract normalized scope values from JWT claims."""
    if not claims:
        return set()

    values: set[str] = set()
    direct_scopes = claims.get("scopes")
    if isinstance(direct_scopes, list):
        values.update(str(item).strip().lower() for item in direct_scopes if str(item).strip())
    elif isinstance(direct_scopes, str):
        values.update(
            token.strip().lower()
            for token in direct_scopes.replace(",", " ").split(" ")
            if token.strip()
        )

    for key in ("scope", "scp"):
        raw_value = claims.get(key)
        if isinstance(raw_value, list):
            values.update(str(item).strip().lower() for item in raw_value if str(item).strip())
        elif isinstance(raw_value, str):
            values.update(
                token.strip().lower()
                for token in raw_value.replace(",", " ").split(" ")
                if token.strip()
            )
    return values


def evaluate_mcp_privilege(
    *,
    role: str,
    claims: dict[str, Any] | None,
    environment: str,
) -> tuple[bool, str]:
    """Evaluate whether a role/claims tuple satisfies MCP privilege policy."""
    normalized_role = normalize_role(role, allow_legacy_alias=True)
    allowed_roles = mcp_privileged_roles()
    if normalized_role not in allowed_roles:
        return False, "Role is not permitted for MCP-privileged access"

    if not mcp_scope_enforced(environment):
        return True, ""

    scopes = extract_scopes_from_claims(claims)
    required_scopes = mcp_required_scopes()
    if required_scopes.intersection(scopes):
        return True, ""
    return False, "Required MCP scope claim is missing"
