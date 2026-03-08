"""Dependency readiness checks for runtime health probes."""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from importlib import import_module
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from server.config import get_settings
from server.models import get_session_context
from server.policy_governance.kernel.solver_engine import (
    validate_runtime_z3_configuration,
)
from server.runtime.profile import RuntimeProfile, resolve_runtime_profile

from .schema_guard import check_schema_compatibility

try:
    ASYNC_REDIS_CLASS = getattr(import_module("redis.asyncio"), "Redis")
except ModuleNotFoundError:  # pragma: no cover - optional dependency guard
    ASYNC_REDIS_CLASS = None

logger = logging.getLogger(__name__)
READINESS_ERRORS = (
    OSError,
    RuntimeError,
    ValueError,
    SQLAlchemyError,
)
_ACTIVE_GUARDRAILS_RELEASE_QUERY = text(
    """
    SELECT git_sha, release_hash, activated_at
    FROM mcp_guardrails_releases
    WHERE is_active IS TRUE
    ORDER BY activated_at DESC
    LIMIT 1
    """
)


@dataclass(slots=True)
class ReadinessReport:
    """Readiness result including per-dependency check states."""

    ready: bool
    profile: str
    checks: dict[str, dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        """Return report as JSON-serializable payload."""
        return {
            "ready": self.ready,
            "profile": self.profile,
            "checks": self.checks,
        }


def _status(ok: bool, reason: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {"ok": ok, "reason": reason}
    payload["details"] = details or {}
    return payload


def _redact_connection_url(raw_url: str) -> str:
    """Redact credentials from connection URLs before returning probe details."""
    parsed = urlsplit(raw_url)
    if not parsed.scheme:
        return "<redacted>"

    host = parsed.hostname
    if not host:
        return f"{parsed.scheme}://<redacted>"

    port = f":{parsed.port}" if parsed.port is not None else ""
    has_credentials = parsed.username is not None or parsed.password is not None
    userinfo = "<redacted>@" if has_credentials else ""
    netloc = f"{userinfo}{host}{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


async def _close_redis_client(client: Any) -> None:
    """Close redis clients across redis-py minor versions."""
    close_method = getattr(client, "aclose", None)
    if close_method is None:
        close_method = getattr(client, "close", None)
    if close_method is None:
        return

    result = close_method()
    if inspect.isawaitable(result):
        await result


async def _check_redis(strict_profile: bool) -> dict[str, Any]:
    settings = get_settings()
    redis_url = str(settings.redis_url or "").strip()

    if not redis_url:
        return _status(False, "redis_url_missing")

    if redis_url.startswith("memory://"):
        if strict_profile:
            return _status(
                False,
                "redis_memory_backend_not_allowed_in_strict_profile",
                {"redis_url": redis_url},
            )
        return _status(
            True,
            "redis_memory_backend",
            {"redis_url": redis_url},
        )

    if ASYNC_REDIS_CLASS is None:
        return _status(False, "redis_client_library_unavailable")

    redacted_redis_url = _redact_connection_url(redis_url)
    client = ASYNC_REDIS_CLASS.from_url(redis_url, decode_responses=True)
    try:
        ping_result = client.ping()
        if inspect.isawaitable(ping_result):
            await ping_result
        return _status(True, "redis_reachable", {"redis_url": redacted_redis_url})
    except READINESS_ERRORS as exc:
        return _status(
            False,
            "redis_unreachable",
            {"redis_url": redacted_redis_url, "error": str(exc)},
        )
    finally:
        await _close_redis_client(client)


def _check_solver() -> dict[str, Any]:
    try:
        solver_status = validate_runtime_z3_configuration(
            require_solver_health=True,
        )
    except RuntimeError as exc:
        return _status(False, "solver_runtime_unhealthy", {"error": str(exc)})

    mode = str(solver_status.get("configured_mode", "off"))
    z3_healthy = bool(solver_status.get("z3_healthy", False))
    z3_check = str(solver_status.get("z3_check_result", "unknown"))
    if z3_check == "error":
        return _status(False, "solver_check_error", solver_status)
    if mode in {"shadow", "enforce"} and not z3_healthy:
        return _status(False, "solver_unhealthy_for_mode", solver_status)
    return _status(True, "solver_ready", solver_status)


async def _check_guardrails_release(
    session: Any,
    *,
    strict_profile: bool,
) -> dict[str, Any]:
    if not strict_profile:
        return _status(True, "guardrails_release_not_required_for_profile")

    try:
        result = await session.execute(_ACTIVE_GUARDRAILS_RELEASE_QUERY)
    except READINESS_ERRORS as exc:
        return _status(
            False,
            "guardrails_release_lookup_failed",
            {"error": str(exc)},
        )

    row = result.mappings().first()
    if row is None:
        return _status(False, "active_guardrails_release_missing")
    return _status(
        True,
        "active_guardrails_release_present",
        {
            "git_sha": str(row.get("git_sha")),
            "release_hash": str(row.get("release_hash")),
        },
    )


async def evaluate_readiness() -> ReadinessReport:
    """Evaluate runtime readiness for health/readiness probe."""
    profile = resolve_runtime_profile()
    strict_profile = profile == RuntimeProfile.CLOUD_STRICT
    checks: dict[str, dict[str, Any]] = {}

    try:
        async with get_session_context() as session:
            await session.execute(text("SELECT 1"))
            checks["database"] = _status(True, "database_reachable")

            schema_result = await check_schema_compatibility(
                session,
                strict_profile=strict_profile,
            )
            checks["schema"] = schema_result.as_dict()

            checks["guardrails_release"] = await _check_guardrails_release(
                session,
                strict_profile=strict_profile,
            )
    except READINESS_ERRORS as exc:
        checks["database"] = _status(
            False,
            "database_unreachable",
            {"error": str(exc)},
        )
        checks["schema"] = _status(
            False,
            "schema_check_failed_due_database",
            {"error": str(exc)},
        )
        if strict_profile:
            checks["guardrails_release"] = _status(
                False,
                "guardrails_release_check_failed_due_database",
                {"error": str(exc)},
            )
        else:
            checks["guardrails_release"] = _status(
                True,
                "guardrails_release_not_required_for_profile",
            )

    checks["redis"] = await _check_redis(strict_profile)
    checks["solver"] = _check_solver()

    ready = all(item.get("ok", False) for item in checks.values())
    logger.debug(
        "Readiness evaluated",
        extra={
            "ready": ready,
            "profile": profile,
            "checks": checks,
        },
    )
    return ReadinessReport(
        ready=ready,
        profile=profile.value,
        checks=checks,
    )
