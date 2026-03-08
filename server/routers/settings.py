"""System settings routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, SQLModel

from ..models import SystemSetting, SystemSettingRead, Permission, User, get_session
from ..policy_governance.kernel.runtime_settings import DEFAULT_RUNTIME_SETTINGS, to_bool
from ..utils.db import execute as db_execute, commit as db_commit
from .auth import require_permission

router = APIRouter(prefix="/settings", tags=["settings"])

DEFAULT_SETTINGS: dict[str, object] = {
    "organization_name": "AgentGate",
    "support_email": "support@agentgate.io",
    "data_retention_days": 30,
    "audit_retention_days": 365,
    "enable_threat_detection": True,
    "ai_write_governance_mode": DEFAULT_RUNTIME_SETTINGS["ai_write_governance_mode"],
    "pii_unknown_token_policy": DEFAULT_RUNTIME_SETTINGS["pii_unknown_token_policy"],
    "enforce_scoped_reads": DEFAULT_RUNTIME_SETTINGS["enforce_scoped_reads"],
    "pii_token_format": DEFAULT_RUNTIME_SETTINGS["pii_token_format"],
}


class SettingsUpdateRequest(SQLModel):
    """Request model for bulk system settings update."""

    settings: dict[str, object]


def _validate_setting_value(key: str, value: object) -> object:
    """Validate and normalize mutable setting payload values."""
    if key == "ai_write_governance_mode":
        normalized = str(value).strip().lower()
        if normalized not in {"human_gated", "auto_low_risk"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ai_write_governance_mode must be 'human_gated' or 'auto_low_risk'",
            )
        return normalized

    if key == "pii_unknown_token_policy":
        normalized = str(value).strip().lower()
        if normalized not in {"fail_closed", "best_effort"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="pii_unknown_token_policy must be 'fail_closed' or 'best_effort'",
            )
        return normalized

    if key == "enforce_scoped_reads":
        return to_bool(value, default=True)

    if key == "pii_token_format":
        normalized = str(value).strip()
        if normalized != "<TYPE_N>":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="pii_token_format currently supports only '<TYPE_N>'",
            )
        return normalized

    return value


@router.get("", response_model=list[SystemSettingRead])
async def list_settings(
    current_user: Annotated[User, Depends(require_permission(Permission.CONFIG_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """List system settings, merging defaults."""
    _ = current_user
    result = await db_execute(session, select(SystemSetting))
    settings = result.scalars().all()
    settings_by_key = {s.key: s for s in settings}

    # Ensure defaults exist in DB for consistent UI
    for key, value in DEFAULT_SETTINGS.items():
        if key not in settings_by_key:
            updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            setting = SystemSetting(key=key, value=value, updated_at=updated_at)
            session.add(setting)
            settings_by_key[key] = setting

    await db_commit(session)
    return list(settings_by_key.values())


@router.put("", response_model=list[SystemSettingRead])
async def update_settings(
    payload: SettingsUpdateRequest,
    current_user: Annotated[User, Depends(require_permission(Permission.CONFIG_UPDATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Update system settings."""
    _ = current_user
    if not payload.settings:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No settings provided")

    result = await db_execute(session, select(SystemSetting))
    existing = result.scalars().all()
    settings_by_key = {s.key: s for s in existing}

    for key, value in payload.settings.items():
        if key not in DEFAULT_SETTINGS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown setting: {key}"
            )
        normalized_value = _validate_setting_value(key, value)
        setting = settings_by_key.get(key)
        updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if not setting:
            setting = SystemSetting(key=key, value=normalized_value, updated_at=updated_at)
        else:
            setting.value = normalized_value
            setting.updated_at = updated_at
        session.add(setting)
        settings_by_key[key] = setting

    await db_commit(session)
    return list(settings_by_key.values())
