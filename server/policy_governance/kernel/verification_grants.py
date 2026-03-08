"""Verification grant validation and consumption helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from server.models import User, VerificationGrant
from server.security.identity.policy import normalize_assurance_level, normalize_risk_level
from server.utils.db import commit as db_commit, execute as db_execute

_RISK_ORDER = {
    "R0": 0,
    "R1": 1,
    "R2": 2,
    "R3": 3,
    "R4": 4,
}

_ASSURANCE_ORDER = {
    "A1": 1,
    "A2": 2,
    "A3": 3,
}

_RISK_TIER_TO_LEVEL = {
    "low": "R1",
    "medium": "R2",
    "high": "R3",
    "critical": "R4",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def risk_tier_to_level(risk_tier: str) -> str:
    """Map counterfactual risk tier labels to canonical risk levels."""
    normalized_tier = risk_tier.strip().lower()
    if normalized_tier not in _RISK_TIER_TO_LEVEL:
        raise ValueError(f"Unsupported risk tier: {risk_tier}")
    return _RISK_TIER_TO_LEVEL[normalized_tier]


def _is_assurance_sufficient(current: str, required: str) -> bool:
    current_level = _ASSURANCE_ORDER[normalize_assurance_level(current)]
    required_level = _ASSURANCE_ORDER[normalize_assurance_level(required)]
    return current_level >= required_level


def _is_risk_coverage_sufficient(grant_risk_level: str, required_risk_level: str) -> bool:
    grant_level = _RISK_ORDER[normalize_risk_level(grant_risk_level)]
    required_level = _RISK_ORDER[normalize_risk_level(required_risk_level)]
    return grant_level >= required_level


def _validate_grant_usage(
    grant: VerificationGrant,
    current_user: User,
    required_risk_level: str,
    session_assurance: str,
    *,
    tenant_id: str | None,
    expected_purpose_prefix: str | None,
) -> None:
    """Validate all constraints on a verification grant before consumption.

    Raises HTTPException when any constraint is violated.
    """
    now = _utc_now()
    if grant.revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant is revoked",
        )
    if grant.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Grant already consumed",
        )
    if grant.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant expired",
        )
    if grant.user_id is not None and grant.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant subject mismatch",
        )
    if tenant_id and grant.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant tenant mismatch",
        )
    if expected_purpose_prefix and not grant.purpose.startswith(expected_purpose_prefix):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant purpose mismatch",
        )
    if current_user.principal_id and grant.principal_id != current_user.principal_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant principal mismatch",
        )
    if not _is_risk_coverage_sufficient(grant.risk_level, required_risk_level):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Grant risk coverage is insufficient for requested operation",
        )
    if not _is_assurance_sufficient(session_assurance, grant.required_assurance):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Session assurance "
                f"{normalize_assurance_level(session_assurance)}"
                f" does not satisfy required level "
                f"{normalize_assurance_level(grant.required_assurance)}"
            ),
        )


async def consume_verification_grant(
    session: AsyncSession,
    *,
    grant_token: str,
    current_user: User,
    required_risk_level: str,
    session_assurance: str,
    tenant_id: str | None = None,
    expected_purpose_prefix: str | None = None,
) -> VerificationGrant:
    """Validate and consume a verification grant in a single atomic operation."""
    result = await db_execute(
        session,
        select(VerificationGrant).where(VerificationGrant.grant_token == grant_token),
    )
    grant = result.scalar_one_or_none()
    if grant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Grant not found",
        )

    _validate_grant_usage(
        grant,
        current_user,
        required_risk_level,
        session_assurance,
        tenant_id=tenant_id,
        expected_purpose_prefix=expected_purpose_prefix,
    )

    grant.used_at = _utc_now()
    session.add(grant)
    await db_commit(session)
    return cast(VerificationGrant, grant)
