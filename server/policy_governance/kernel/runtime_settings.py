"""Runtime system-setting helpers shared by routers and services."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from server.models import SystemSetting
from server.utils.db import execute as db_execute


DEFAULT_RUNTIME_SETTINGS: dict[str, Any] = {
    "ai_write_governance_mode": "human_gated",
    "pii_unknown_token_policy": "fail_closed",
    "enforce_scoped_reads": True,
    "pii_token_format": "<TYPE_N>",
}


async def get_runtime_setting(
    session: AsyncSession,
    key: str,
    default: Any = None,
) -> Any:
    """Resolve a runtime setting from DB, falling back to secure defaults."""
    stmt = select(SystemSetting).where(SystemSetting.key == key)
    result = await db_execute(session, stmt)
    setting = result.scalar_one_or_none()
    if setting is not None:
        return setting.value
    if key in DEFAULT_RUNTIME_SETTINGS:
        return DEFAULT_RUNTIME_SETTINGS[key]
    return default


def to_bool(value: Any, default: bool) -> bool:
    """Convert a setting value to bool with permissive string support."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, int):
        return value != 0
    return default


async def get_scoped_reads_enabled(session: AsyncSession) -> bool:
    """Return scoped-read enforcement state."""
    value = await get_runtime_setting(
        session,
        "enforce_scoped_reads",
        default=DEFAULT_RUNTIME_SETTINGS["enforce_scoped_reads"],
    )
    return to_bool(value, default=True)


async def get_unknown_token_policy(session: AsyncSession) -> str:
    """Return unknown-token policy normalized to known values."""
    value = await get_runtime_setting(
        session,
        "pii_unknown_token_policy",
        default=DEFAULT_RUNTIME_SETTINGS["pii_unknown_token_policy"],
    )
    normalized = str(value).strip().lower()
    if normalized not in {"fail_closed", "best_effort"}:
        return "fail_closed"
    return normalized


async def get_ai_write_governance_mode(session: AsyncSession) -> str:
    """Return AI write-governance mode normalized to known values."""
    value = await get_runtime_setting(
        session,
        "ai_write_governance_mode",
        default=DEFAULT_RUNTIME_SETTINGS["ai_write_governance_mode"],
    )
    normalized = str(value).strip().lower()
    if normalized not in {"human_gated", "auto_low_risk"}:
        return "human_gated"
    return normalized
