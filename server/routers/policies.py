"""API endpoints for policy management.

Provides REST API for managing security policies including loading,
unloading, testing, and listing active policy sets.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import true
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from ea_agentgate.security.policy_engine import PolicyEngine
from server.models.database import get_session
from server.models.security_policy_schemas import SecurityPolicy
from server.policy_governance.kernel.runtime_settings import get_scoped_reads_enabled
from server.routers.access_mode import route_access_mode
from server.models.user_schemas import User
from server.routers.auth import get_current_user, require_admin
from server.utils.db import (
    commit as db_commit,
    execute as db_execute,
    refresh as db_refresh,
)

_LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/policies", tags=["policies"])


def _policy_scope_query(
    query,
    *,
    current_user: User,
    scoped_reads_enabled: bool,
):
    if not scoped_reads_enabled or current_user.role == "admin":
        return query
    return query.where(SecurityPolicy.created_by_user_id == current_user.id)


# =============================================================================
# Global Policy Engine Instance
# =============================================================================

POLICY_ENGINE = PolicyEngine()


# =============================================================================
# Request/Response Models
# =============================================================================


class PolicySetRequest(BaseModel):
    """Request model for creating/loading a policy set."""

    policy_json: dict[str, Any] = Field(description="Policy set JSON conforming to schema")
    origin: str = Field(
        default="manual",
        description="Origin of the policy: 'manual', 'mcp', or 'system'",
    )
    locked: bool = Field(
        default=False,
        description="Whether the policy should be locked from editing",
    )


class PolicySetResponse(BaseModel):
    """Response model for policy set data."""

    policy_set_id: str
    version: str
    description: str
    default_effect: str
    rule_count: int
    loaded: bool
    db_id: int | None = None
    origin: str | None = None
    locked: bool = False
    is_active: bool = False


class PolicyDetailResponse(BaseModel):
    """Full policy detail including rules and conditions."""

    policy_set_id: str
    version: str
    description: str
    default_effect: str
    rule_count: int
    locked: bool
    is_active: bool
    db_id: int | None = None
    origin: str | None = None
    policy_json: dict[str, Any]


class PolicyListResponse(BaseModel):
    """Response model for listing policies."""

    loaded_policies: list[str]
    db_policies: list[PolicySetResponse]


class EvaluateRequest(BaseModel):
    """Request model for policy evaluation testing."""

    policy_set_id: str | None = Field(
        default=None,
        description="Policy set ID to evaluate (None = all sets)",
    )
    request_context: dict[str, Any] = Field(description="Request context for evaluation")


class EvaluateResponse(BaseModel):
    """Response model for policy evaluation result."""

    allowed: bool
    effect: str
    matched_rules: list[str]
    reason: str
    policy_set_id: str
    evaluation_time_ms: float


# =============================================================================
# Helper Functions
# =============================================================================


def _resolve_hmac_secret() -> str:
    """Resolve the HMAC secret from environment configuration.

    In production, the AGENTGATE_HMAC_SECRET environment variable
    must be set. In development, a placeholder value is used when
    the variable is absent.

    Returns:
        The resolved HMAC secret string.

    Raises:
        ValueError: If running in production without the secret.
    """
    hmac_secret = os.getenv("AGENTGATE_HMAC_SECRET", "")
    if not hmac_secret:
        env = os.getenv("AGENTGATE_ENV", "development")
        if env == "production":
            raise ValueError("AGENTGATE_HMAC_SECRET must be set in production")
        hmac_secret = "dev-only-hmac-placeholder"
    return hmac_secret


def _compute_hmac(policy_json: dict[str, Any], secret: str) -> str:
    """Compute HMAC-SHA256 signature for policy JSON.

    Args:
        policy_json: Policy JSON data.
        secret: Secret key for HMAC.

    Returns:
        Hexadecimal HMAC signature.
    """
    canonical_json = json.dumps(policy_json, sort_keys=True)
    signature = hmac.new(
        secret.encode("utf-8"),
        canonical_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return signature


def _verify_hmac(
    policy_json: dict[str, Any],
    signature: str,
    secret: str,
) -> bool:
    """Verify HMAC signature for policy JSON.

    Args:
        policy_json: Policy JSON data.
        signature: Expected HMAC signature.
        secret: Secret key for HMAC.

    Returns:
        True if signature is valid, False otherwise.
    """
    expected = _compute_hmac(policy_json, secret)
    return hmac.compare_digest(expected, signature)


# =============================================================================
# Endpoints
# =============================================================================


@route_access_mode("read_only")
@router.get("", response_model=PolicyListResponse)
async def list_policies(
    _current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyListResponse:
    """List all loaded and database-stored policies.

    Returns:
        List of loaded policy IDs and database policies.
    """
    loaded_policies = POLICY_ENGINE.list_loaded_policies()

    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    stmt = _policy_scope_query(
        select(SecurityPolicy),
        current_user=_current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )
    result = await db_execute(session, stmt)
    db_policies_raw = result.scalars().all()

    db_policies = [
        PolicySetResponse(
            policy_set_id=p.policy_json.get("policy_set_id", ""),
            version=p.policy_json.get("version", ""),
            description=p.policy_json.get("description", ""),
            default_effect=p.policy_json.get("default_effect", ""),
            rule_count=len(p.policy_json.get("rules", [])),
            loaded=p.policy_json.get("policy_set_id", "") in loaded_policies,
            db_id=p.id,
            origin=p.origin,
            locked=p.locked,
            is_active=p.is_active,
        )
        for p in db_policies_raw
    ]

    return PolicyListResponse(
        loaded_policies=loaded_policies,
        db_policies=db_policies,
    )


@route_access_mode("read_only")
@router.get("/{policy_set_id}/detail", response_model=PolicyDetailResponse)
async def get_policy_detail(
    policy_set_id: str,
    _current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicyDetailResponse:
    """Return full policy detail including rules and conditions.

    Args:
        policy_set_id: ID of the policy set.
        _current_user: Authenticated user.
        session: Database session.

    Returns:
        Full policy detail with policy_json.

    Raises:
        HTTPException: If policy not found.
    """
    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    stmt = _policy_scope_query(
        select(SecurityPolicy).where(
            SecurityPolicy.policy_id == policy_set_id,
        ),
        current_user=_current_user,
        scoped_reads_enabled=scoped_reads_enabled,
    )
    result = await db_execute(session, stmt)
    db_policy = result.scalar_one_or_none()

    if not db_policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_set_id}' not found",
        )

    policy_json = db_policy.policy_json or {}
    return PolicyDetailResponse(
        policy_set_id=policy_json.get("policy_set_id", ""),
        version=policy_json.get("version", ""),
        description=policy_json.get("description", ""),
        default_effect=policy_json.get("default_effect", ""),
        rule_count=len(policy_json.get("rules", [])),
        locked=db_policy.locked,
        is_active=db_policy.is_active,
        db_id=db_policy.id,
        origin=db_policy.origin,
        policy_json=policy_json,
    )


@route_access_mode("write_only")
@router.post("", response_model=PolicySetResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    request: PolicySetRequest,
    current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicySetResponse:
    """Create and load a new policy set.

    Validates the policy, stores it in the database, and loads it
    into the policy engine.

    Args:
        request: Policy set creation request.
        current_user: Authenticated user (admin required).
        session: Database session.

    Returns:
        Created policy set metadata.

    Raises:
        HTTPException: If policy is invalid or already exists.
    """
    try:
        policy_set = POLICY_ENGINE.load_policy_from_dict(request.policy_json)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid policy: {exc}",
        ) from exc

    stmt = select(SecurityPolicy).where(SecurityPolicy.policy_id == policy_set.policy_set_id)
    result = await db_execute(session, stmt)
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"Policy '{policy_set.policy_set_id}' already exists. Use PUT to update."),
        )

    hmac_secret = _resolve_hmac_secret()
    signature = _compute_hmac(request.policy_json, hmac_secret)

    db_policy = SecurityPolicy(
        policy_id=policy_set.policy_set_id,
        version=1,
        policy_json=request.policy_json,
        origin=request.origin,
        created_by_user_id=current_user.id,
        hmac_signature=signature,
        locked=request.locked,
        is_active=False,
    )

    session.add(db_policy)
    await session.commit()
    await session.refresh(db_policy)

    POLICY_ENGINE.load_policy_set(policy_set)

    _LOG.info(
        "Created policy '%s' (origin=%s, locked=%s)",
        policy_set.policy_set_id,
        request.origin,
        request.locked,
    )

    return PolicySetResponse(
        policy_set_id=policy_set.policy_set_id,
        version=policy_set.version,
        description=policy_set.description,
        default_effect=policy_set.default_effect.value,
        rule_count=len(policy_set.rules),
        loaded=True,
        db_id=db_policy.id,
        origin=db_policy.origin,
        locked=db_policy.locked,
        is_active=db_policy.is_active,
    )


@route_access_mode("write_only")
@router.delete("/{policy_set_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_set_id: str,
    _current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Unload and delete a policy set.

    Removes the policy from the engine and deletes it from the database.

    Args:
        policy_set_id: ID of the policy set to delete.
        _current_user: Authenticated user (admin required).
        session: Database session.

    Raises:
        HTTPException: If policy does not exist or is locked.
    """
    stmt = select(SecurityPolicy).where(SecurityPolicy.policy_id == policy_set_id)
    result = await db_execute(session, stmt)
    db_policy = result.scalar_one_or_none()

    if not db_policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_set_id}' not found",
        )

    if db_policy.locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"Policy '{policy_set_id}' is locked and cannot be deleted"),
        )

    try:
        POLICY_ENGINE.unload_policy_set(policy_set_id)
    except KeyError:
        pass

    await session.delete(db_policy)
    await session.commit()

    _LOG.info("Deleted policy '%s'", policy_set_id)


@route_access_mode("read_write")
@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_policy(
    request: EvaluateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> EvaluateResponse:
    """Evaluate a request context against policy sets.

    Tests policy evaluation without persisting results.
    Useful for testing and debugging policies.

    Args:
        request: Evaluation request with context.
        _current_user: Authenticated user.

    Returns:
        Policy evaluation decision.

    Raises:
        HTTPException: If policy set not found.
    """
    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    if scoped_reads_enabled and current_user.role != "admin":
        if request.policy_set_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scoped reads enabled: policy_set_id is required for non-admin users",
            )
        stmt = select(SecurityPolicy).where(SecurityPolicy.policy_id == request.policy_set_id)
        stmt = _policy_scope_query(
            stmt,
            current_user=current_user,
            scoped_reads_enabled=scoped_reads_enabled,
        )
        result = await db_execute(session, stmt)
        if result.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy '{request.policy_set_id}' not found",
            )

    try:
        if request.policy_set_id is not None:
            decision = POLICY_ENGINE.evaluate(
                policy_set_id=request.policy_set_id,
                request_context=request.request_context,
            )
        else:
            decision = POLICY_ENGINE.evaluate_all(
                request_context=request.request_context,
            )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return EvaluateResponse(
        allowed=decision.allowed,
        effect=decision.effect.value,
        matched_rules=decision.matched_rules,
        reason=decision.reason,
        policy_set_id=decision.policy_set_id,
        evaluation_time_ms=decision.evaluation_time_ms,
    )


@route_access_mode("write_only")
@router.post("/{db_id}/load", response_model=PolicySetResponse)
async def load_policy_from_db(
    db_id: int,
    _current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicySetResponse:
    """Load a policy from database into the engine.

    Verifies HMAC signature before loading.

    Args:
        db_id: Database ID of the policy to load.
        _current_user: Authenticated user (admin required).
        session: Database session.

    Returns:
        Loaded policy set metadata.

    Raises:
        HTTPException: If policy not found or HMAC invalid.
    """
    stmt = select(SecurityPolicy).where(SecurityPolicy.id == db_id)
    result = await db_execute(session, stmt)
    db_policy = result.scalar_one_or_none()

    if not db_policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy with ID {db_id} not found",
        )

    hmac_secret = _resolve_hmac_secret()
    if not _verify_hmac(
        db_policy.policy_json,
        db_policy.hmac_signature,
        hmac_secret,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="HMAC signature verification failed",
        )

    try:
        policy_set = POLICY_ENGINE.load_policy_from_dict(db_policy.policy_json)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid policy: {exc}",
        ) from exc

    POLICY_ENGINE.load_policy_set(policy_set)

    _LOG.info(
        "Loaded policy '%s' from database (id=%d)",
        policy_set.policy_set_id,
        db_id,
    )

    return PolicySetResponse(
        policy_set_id=policy_set.policy_set_id,
        version=policy_set.version,
        description=policy_set.description,
        default_effect=policy_set.default_effect.value,
        rule_count=len(policy_set.rules),
        loaded=True,
        db_id=db_policy.id,
        origin=db_policy.origin,
        locked=db_policy.locked,
        is_active=db_policy.is_active,
    )


class PolicyPatchRequest(BaseModel):
    """Request model for partial policy updates."""

    locked: bool | None = Field(
        default=None,
        description="Set locked status of the policy",
    )


@route_access_mode("write_only")
@router.patch(
    "/{policy_set_id}",
    response_model=PolicySetResponse,
)
async def patch_policy(
    policy_set_id: str,
    request: PolicyPatchRequest,
    _current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicySetResponse:
    """Update attributes of an existing policy set.

    Currently supports toggling the locked status.

    Args:
        policy_set_id: ID of the policy set to update.
        request: Fields to update.
        _current_user: Authenticated user (admin required).
        session: Database session.

    Returns:
        Updated policy set metadata.

    Raises:
        HTTPException: If policy not found.
    """
    stmt = select(SecurityPolicy).where(SecurityPolicy.policy_id == policy_set_id)
    result = await db_execute(session, stmt)
    db_policy = result.scalar_one_or_none()

    if not db_policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_set_id}' not found",
        )

    if request.locked is not None:
        db_policy.locked = request.locked

    session.add(db_policy)
    await session.commit()
    await session.refresh(db_policy)

    policy_json = db_policy.policy_json or {}
    return PolicySetResponse(
        policy_set_id=policy_json.get("policy_set_id", ""),
        version=policy_json.get("version", ""),
        description=policy_json.get("description", ""),
        default_effect=policy_json.get("default_effect", ""),
        rule_count=len(policy_json.get("rules", [])),
        loaded=(policy_json.get("policy_set_id", "") in POLICY_ENGINE.list_loaded_policies()),
        db_id=db_policy.id,
        origin=db_policy.origin,
        locked=db_policy.locked,
        is_active=db_policy.is_active,
    )


def _utc_now() -> datetime:
    """Return current UTC timestamp without timezone info."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _build_policy_response(db_policy: SecurityPolicy) -> PolicySetResponse:
    """Build a PolicySetResponse from a SecurityPolicy database record."""
    policy_json = db_policy.policy_json or {}
    return PolicySetResponse(
        policy_set_id=policy_json.get("policy_set_id", ""),
        version=policy_json.get("version", ""),
        description=policy_json.get("description", ""),
        default_effect=policy_json.get("default_effect", ""),
        rule_count=len(policy_json.get("rules", [])),
        loaded=(policy_json.get("policy_set_id", "") in POLICY_ENGINE.list_loaded_policies()),
        db_id=db_policy.id,
        origin=db_policy.origin,
        locked=db_policy.locked,
        is_active=db_policy.is_active,
    )


@route_access_mode("write_only")
@router.post(
    "/{db_id}/activate",
    response_model=PolicySetResponse,
)
async def activate_policy(
    db_id: int,
    current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicySetResponse:
    """Activate a policy, deactivating any currently active policy.

    Only one policy can be active at a time. Activating a policy
    automatically deactivates all others.

    Args:
        db_id: Database ID of the policy to activate.
        current_user: Authenticated admin user.
        session: Database session.

    Returns:
        Updated policy metadata with is_active=True.

    Raises:
        HTTPException: If policy not found.
    """
    stmt = select(SecurityPolicy).where(SecurityPolicy.id == db_id)
    result = await db_execute(session, stmt)
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy with ID {db_id} not found",
        )

    # Deactivate all currently active policies
    active_stmt = select(SecurityPolicy).where(
        col(SecurityPolicy.is_active) == true(),
    )
    active_result = await db_execute(session, active_stmt)
    for active_policy in active_result.scalars().all():
        active_policy.is_active = False
        active_policy.activated_at = None
        active_policy.activated_by_user_id = None
        session.add(active_policy)

    # Activate the target policy
    target.is_active = True
    target.activated_at = _utc_now()
    target.activated_by_user_id = current_user.id
    session.add(target)

    await db_commit(session)
    await db_refresh(session, target)

    _LOG.info(
        "Activated policy db_id=%d (policy_id='%s') by user=%d",
        db_id,
        target.policy_id,
        current_user.id,
    )

    return _build_policy_response(target)


@route_access_mode("write_only")
@router.post(
    "/{db_id}/deactivate",
    response_model=PolicySetResponse,
)
async def deactivate_policy(
    db_id: int,
    _current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PolicySetResponse:
    """Deactivate a policy.

    Args:
        db_id: Database ID of the policy to deactivate.
        _current_user: Authenticated admin user.
        session: Database session.

    Returns:
        Updated policy metadata with is_active=False.

    Raises:
        HTTPException: If policy not found.
    """
    stmt = select(SecurityPolicy).where(SecurityPolicy.id == db_id)
    result = await db_execute(session, stmt)
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy with ID {db_id} not found",
        )

    target.is_active = False
    target.activated_at = None
    target.activated_by_user_id = None
    session.add(target)

    await db_commit(session)
    await db_refresh(session, target)

    _LOG.info("Deactivated policy db_id=%d (policy_id='%s')", db_id, target.policy_id)

    return _build_policy_response(target)


__all__ = [
    "router",
    "POLICY_ENGINE",
]
