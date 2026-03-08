"""Verification grant authorization routes for sensitive security operations."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import VerificationGrant, User, get_session
from server.security.identity import get_principal_risk
from server.security.identity.policy import (
    normalize_assurance_level,
    normalize_risk_level,
    required_assurance_for_risk,
)
from server.policy_governance.kernel.verification_grants import (
    consume_verification_grant as consume_grant_token,
)
from server.utils.db import commit as db_commit

from .auth import get_current_auth_claims, get_current_user

router = APIRouter(prefix="/verification", tags=["verification"])
_ASSURANCE_ORDER = {
    "A1": 1,
    "A2": 2,
    "A3": 3,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_assurance_sufficient(current: str, required: str) -> bool:
    return (
        _ASSURANCE_ORDER[normalize_assurance_level(current)]
        >= _ASSURANCE_ORDER[normalize_assurance_level(required)]
    )


class VerificationAuthorizeRequest(BaseModel):
    """Request payload for issuing verification grants."""

    purpose: str = Field(default="penetration_test", min_length=1, max_length=255)
    required_risk: str | None = Field(default=None, max_length=4)
    ttl_seconds: int = Field(default=900, ge=60, le=3600)
    metadata: dict = Field(default_factory=dict)


@router.post("/authorize")
async def authorize_verification(
    payload: VerificationAuthorizeRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_claims: Annotated[dict, Depends(get_current_auth_claims)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Issue short-lived verification grant token for sensitive workflows."""
    tenant_id = current_user.tenant_id or "default"
    principal_id = current_user.principal_id or f"user:{current_user.id}"
    principal_risk = await get_principal_risk(
        session,
        principal_id=current_user.principal_id,
        fallback_role=current_user.role,
    )
    required_risk = normalize_risk_level(payload.required_risk or principal_risk)
    required_assurance = required_assurance_for_risk(required_risk)
    session_assurance = normalize_assurance_level(str(auth_claims.get("session_assurance", "A1")))

    if not _is_assurance_sufficient(session_assurance, required_assurance):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Session assurance {session_assurance} does not satisfy "
                f"required level {required_assurance}"
            ),
        )

    # High-risk verification operations require elevated operational roles.
    normalized_role = current_user.role.strip().lower()
    if required_risk in {"R3", "R4"} and normalized_role not in {
        "admin",
        "security_admin",
        "approver",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="High-risk verification grants require admin/security approver roles",
        )
    if required_risk in {"R3", "R4"} and not payload.metadata.get("approval_id"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="High-risk verification grants require approval metadata (approval_id)",
        )

    now = _utc_now()
    token = f"vgr_{secrets.token_urlsafe(32)}"
    grant = VerificationGrant(
        grant_token=token,
        principal_id=principal_id,
        user_id=current_user.id,
        tenant_id=tenant_id,
        purpose=payload.purpose,
        risk_level=required_risk,
        required_assurance=required_assurance,
        issued_at=now,
        expires_at=now + timedelta(seconds=payload.ttl_seconds),
        metadata_json=payload.metadata,
    )
    session.add(grant)
    await db_commit(session)

    return {
        "success": True,
        "grant": {
            "grant_token": token,
            "purpose": grant.purpose,
            "risk_level": grant.risk_level,
            "required_assurance": grant.required_assurance,
            "issued_at": grant.issued_at,
            "expires_at": grant.expires_at,
            "tenant_id": grant.tenant_id,
        },
    }


class VerificationGrantConsumeRequest(BaseModel):
    """Request payload for consuming verification grants."""

    grant_token: str = Field(min_length=10, max_length=256)


@router.post("/consume")
async def consume_verification_grant_endpoint(
    payload: VerificationGrantConsumeRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_claims: Annotated[dict, Depends(get_current_auth_claims)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Validate and consume a verification grant token."""
    session_assurance = normalize_assurance_level(str(auth_claims.get("session_assurance", "A1")))
    grant = await consume_grant_token(
        session,
        grant_token=payload.grant_token,
        current_user=current_user,
        required_risk_level="R0",
        session_assurance=session_assurance,
        tenant_id=current_user.tenant_id or "default",
        expected_purpose_prefix="penetration_test",
    )

    return {
        "success": True,
        "grant": {
            "purpose": grant.purpose,
            "risk_level": grant.risk_level,
            "required_assurance": grant.required_assurance,
            "tenant_id": grant.tenant_id,
            "used_at": grant.used_at,
        },
    }
