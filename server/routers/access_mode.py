"""Route access-mode metadata helpers and startup validation."""

from __future__ import annotations

from typing import Literal
from collections.abc import Callable

from fastapi import FastAPI
from fastapi.routing import APIRoute

AccessMode = Literal["read_only", "write_only", "read_write"]
_ACCESS_MODE_ATTR = "__agentgate_access_mode__"
_READ_METHODS = {"GET"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

PROTECTED_PREFIXES = (
    "/api/audit",
    "/api/approvals",
    "/api/security/threats",
    "/api/traces",
    "/api/costs",
    "/api/feedback",
    "/api/policies",
)


def route_access_mode(mode: AccessMode) -> Callable:
    """Attach explicit access mode metadata to a route handler."""
    if mode not in {"read_only", "write_only", "read_write"}:
        raise ValueError(f"Unsupported route access mode: {mode}")

    def decorator(func: Callable) -> Callable:
        """Set the access mode attribute on the route handler."""
        setattr(func, _ACCESS_MODE_ATTR, mode)
        return func

    return decorator


def _get_mode(route: APIRoute) -> AccessMode | None:
    return getattr(route.endpoint, _ACCESS_MODE_ATTR, None)


def validate_route_access_modes(app: FastAPI) -> None:
    """Fail startup when protected routes are missing access mode annotation."""
    missing: list[str] = []
    invalid: list[str] = []

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not route.path.startswith(PROTECTED_PREFIXES):
            continue
        mode = _get_mode(route)
        if mode is None:
            missing.append(f"{','.join(sorted(route.methods or []))} {route.path}")
            continue

        methods = {m for m in (route.methods or set()) if m not in {"HEAD", "OPTIONS"}}
        if mode == "read_only" and not methods.issubset(_READ_METHODS):
            invalid.append(f"{route.path}: read_only incompatible with {sorted(methods)}")
        if mode == "write_only" and not methods.issubset(_WRITE_METHODS):
            invalid.append(f"{route.path}: write_only incompatible with {sorted(methods)}")

    if missing or invalid:
        details = []
        if missing:
            details.append("Missing access mode annotations: " + "; ".join(missing))
        if invalid:
            details.append("Invalid access mode contracts: " + "; ".join(invalid))
        raise RuntimeError(" | ".join(details))
