"""Formal security and delegation API routes.

Provides proof-carrying admissibility evaluation, delegation lifecycle,
invariant synthesis, honey-token management, and runtime solver
diagnostics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import (
    Permission,
    User,
    get_session,
)
from server.policy_governance.kernel.delegation_lineage import (
    DelegationLineageError,
    issue_delegation_grant,
    revoke_delegation_grant,
)
from server.policy_governance.kernel.enforcement import (
    SecurityEnforcementError,
    enforce_action,
)
from server.policy_governance.kernel.solver_engine import (
    validate_runtime_z3_configuration,
)
from server.policy_governance.kernel.spec_synthesizer import (
    SynthesisConfig,
    approve_proposal,
    get_pending_proposals,
    persist_synthesis_results,
    reject_proposal,
    run_synthesis,
)
from server.policy_governance.kernel.deception_injector import (
    HoneyTokenType,
    create_honey_token,
    deactivate_honey_token,
    get_triggers,
    list_honey_tokens,
)
from .auth import require_permission
from .policy_governance_verification import (
    router as _verification_router,
    CertificateVerifyRequest,
)

__all__ = ["router", "CertificateVerifyRequest"]

router = APIRouter(
    prefix="/security",
    tags=["security-formal"],
)


def _runtime_solver_payload(
    certificate: Any,
) -> dict[str, Any]:
    """Extract runtime solver metadata from certificate."""
    proof_payload = getattr(
        certificate,
        "proof_payload",
        {},
    )
    if not isinstance(proof_payload, dict):
        return {}
    runtime_solver = proof_payload.get(
        "runtime_solver",
    )
    if not isinstance(runtime_solver, dict):
        return {}
    return runtime_solver


# ------------------------------------------------------------------
# Request / response models
# ------------------------------------------------------------------


class AdmissibilityEvaluateRequest(BaseModel):
    """Request for formal admissibility evaluation."""

    principal: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    runtime_context: dict[str, Any] = Field(
        default_factory=dict,
    )
    delegation_ref: str | None = None
    tenant_id: str | None = None
    chain_id: str = Field(
        default="api-security-evaluation",
        min_length=1,
    )


class DelegationIssueRequest(BaseModel):
    """Request for delegation grant issuance."""

    principal: str = Field(min_length=1)
    delegate: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    allowed_actions: list[str] = Field(min_length=1)
    resource_scope: str = Field(min_length=1)
    expires_at: datetime
    parent_grant_id: str | None = None
    obligations: dict[str, Any] = Field(
        default_factory=dict,
    )
    context_constraints: dict[str, Any] = Field(
        default_factory=dict,
    )


class DelegationRevokeRequest(BaseModel):
    """Request for delegation revocation."""

    grant_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    transitive: bool = True


class RuntimeSolverStatusResponse(BaseModel):
    """Runtime solver diagnostics response."""

    configured_mode: str
    environment: str
    off_mode_allowed: bool
    z3_available: bool
    z3_healthy: bool
    z3_check_result: str
    z3_error: str | None = None


# ------------------------------------------------------------------
# Admissibility evaluation
# ------------------------------------------------------------------


@router.post("/admissibility/evaluate")
async def evaluate_admissibility(
    payload: AdmissibilityEvaluateRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Evaluate theorem admissibility and persist evidence."""
    payload_context = dict(payload.runtime_context)
    payload_context.setdefault("role", current_user.role)
    payload_context.setdefault(
        "authenticated_principal",
        current_user.email,
    )
    try:
        certificate = await enforce_action(
            session=session,
            principal=payload.principal,
            action=payload.action,
            resource=payload.resource,
            runtime_context=payload_context,
            delegation_ref=payload.delegation_ref,
            tenant_id=payload.tenant_id,
            chain_id=payload.chain_id,
        )
        return {
            "success": True,
            "certificate": certificate.model_dump(
                mode="json",
            ),
            "runtime_solver": (_runtime_solver_payload(certificate)),
        }
    except SecurityEnforcementError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": "inadmissible",
                "certificate": (
                    exc.certificate.model_dump(
                        mode="json",
                    )
                ),
                "runtime_solver": (
                    _runtime_solver_payload(
                        exc.certificate,
                    )
                ),
            },
        ) from exc


# ------------------------------------------------------------------
# Delegation lifecycle
# ------------------------------------------------------------------


@router.post(
    "/delegation/issue",
    status_code=status.HTTP_201_CREATED,
)
async def issue_delegation(
    payload: DelegationIssueRequest,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Issue delegation grant with attenuation checks."""
    expires_at = payload.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc,
        )
    expires_naive = expires_at.astimezone(
        timezone.utc,
    ).replace(tzinfo=None)

    now_naive = datetime.now(timezone.utc).replace(
        tzinfo=None,
    )
    if expires_naive <= now_naive:
        raise HTTPException(
            status_code=(status.HTTP_422_UNPROCESSABLE_ENTITY),
            detail="expires_at must be in the future",
        )

    try:
        grant = await issue_delegation_grant(
            session,
            principal=payload.principal,
            delegate=payload.delegate,
            tenant_id=payload.tenant_id,
            allowed_actions=payload.allowed_actions,
            resource_scope=payload.resource_scope,
            expires_at=expires_naive,
            parent_grant_id=(payload.parent_grant_id),
            obligations=payload.obligations,
            context_constraints=(payload.context_constraints),
            issued_by_user_id=current_user.id,
            signature="pending-signature",
        )
    except DelegationLineageError as exc:
        raise HTTPException(
            status_code=(status.HTTP_422_UNPROCESSABLE_ENTITY),
            detail=str(exc),
        ) from exc

    return {
        "success": True,
        "grant": {
            "grant_id": grant.grant_id,
            "principal": grant.principal,
            "delegate": grant.delegate,
            "tenant_id": grant.tenant_id,
            "parent_grant_id": (grant.parent_grant_id),
            "hop_index": grant.hop_index,
            "allowed_actions": (grant.allowed_actions),
            "resource_scope": grant.resource_scope,
            "expires_at": grant.expires_at,
            "revoked": grant.revoked,
        },
    }


@router.post("/delegation/revoke")
async def revoke_delegation(
    payload: DelegationRevokeRequest,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Revoke delegation grant transitively."""
    try:
        revocation = await revoke_delegation_grant(
            session,
            grant_id=payload.grant_id,
            tenant_id=payload.tenant_id,
            reason=payload.reason,
            revoked_by_user_id=current_user.id,
            transitive=payload.transitive,
        )
    except DelegationLineageError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    return {
        "success": True,
        "revocation": {
            "revocation_id": (revocation.revocation_id),
            "grant_id": revocation.grant_id,
            "tenant_id": revocation.tenant_id,
            "transitive": revocation.transitive,
            "revoked_at": revocation.revoked_at,
        },
    }


# ------------------------------------------------------------------
# Runtime solver diagnostics
# ------------------------------------------------------------------


@router.get(
    "/admissibility/runtime-status",
    response_model=RuntimeSolverStatusResponse,
)
async def admissibility_runtime_status(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
):
    """Return runtime solver diagnostics."""
    _ = current_user
    try:
        status_payload = validate_runtime_z3_configuration(
            require_solver_health=True,
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=(status.HTTP_500_INTERNAL_SERVER_ERROR),
            detail={
                "error": ("runtime_solver_misconfigured"),
                "message": str(exc),
            },
        ) from exc

    return RuntimeSolverStatusResponse(
        configured_mode=str(
            status_payload["configured_mode"],
        ),
        environment=str(
            status_payload["environment"],
        ),
        off_mode_allowed=bool(
            status_payload["off_mode_allowed"],
        ),
        z3_available=bool(
            status_payload["z3_available"],
        ),
        z3_healthy=bool(
            status_payload["z3_healthy"],
        ),
        z3_check_result=str(
            status_payload["z3_check_result"],
        ),
        z3_error=status_payload.get("z3_error"),
    )


# ------------------------------------------------------------------
# Feature: Invariant Synthesis
# ------------------------------------------------------------------


class SynthesisRunRequest(BaseModel):
    """Request for invariant synthesis run."""

    iterations: int = Field(
        default=10000,
        ge=1,
        le=100000,
    )
    seed: int | None = None
    risk_tier: str = Field(
        default="high",
        pattern="^(low|medium|high|critical)$",
    )


class SynthesisRejectRequest(BaseModel):
    """Request for proposal rejection."""

    reason: str = Field(default="", max_length=1024)


@router.post("/synthesis/run")
async def run_synthesis_endpoint(
    payload: SynthesisRunRequest,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Trigger bounded invariant synthesis run."""
    _ = current_user
    config = SynthesisConfig(
        iterations=payload.iterations,
        seed=payload.seed,
    )
    result = await run_synthesis(config)
    count = await persist_synthesis_results(
        session,
        result,
    )

    return {
        "success": True,
        "run_id": result.run_id,
        "iterations_completed": (result.iterations_completed),
        "invariants_found": count,
        "duration_ms": round(result.duration_ms, 2),
    }


@router.get("/synthesis/proposals")
async def list_synthesis_proposals(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: str = "pending",
):
    """List invariant synthesis proposals by status."""
    _ = current_user
    proposals = await get_pending_proposals(
        session,
        status_filter=status_filter,
    )
    return {
        "success": True,
        "proposals": proposals,
        "count": len(proposals),
    }


@router.post(
    "/synthesis/proposals/{invariant_id}/approve",
)
async def approve_synthesis_proposal(
    invariant_id: Annotated[str, Path(min_length=1)],
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Approve a pending invariant proposal."""
    _ = current_user
    success = await approve_proposal(
        session,
        invariant_id,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proposal not found",
        )
    return {
        "success": True,
        "invariant_id": invariant_id,
    }


@router.post(
    "/synthesis/proposals/{invariant_id}/reject",
)
async def reject_synthesis_proposal(
    invariant_id: Annotated[str, Path(min_length=1)],
    payload: SynthesisRejectRequest,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Reject a pending invariant proposal."""
    _ = current_user
    success = await reject_proposal(
        session,
        invariant_id,
        reason=payload.reason,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proposal not found",
        )
    return {
        "success": True,
        "invariant_id": invariant_id,
    }


# ------------------------------------------------------------------
# Feature: Semantic Honey-Tokens
# ------------------------------------------------------------------


class HoneyTokenCreateRequest(BaseModel):
    """Request for honey token creation."""

    name: str = Field(min_length=1, max_length=255)
    token_type: str = Field(min_length=1)
    resource_pattern: str = Field(min_length=1)
    description: str = Field(
        default="",
        max_length=2048,
    )


@router.post(
    "/honey-tokens",
    status_code=status.HTTP_201_CREATED,
)
async def create_honey_token_endpoint(
    payload: HoneyTokenCreateRequest,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new honey-token canary."""
    _ = current_user
    try:
        ht_type = HoneyTokenType(payload.token_type)
    except ValueError as exc:
        valid = [t.value for t in HoneyTokenType]
        raise HTTPException(
            status_code=(status.HTTP_422_UNPROCESSABLE_ENTITY),
            detail=(f"Invalid token_type. Valid: {valid}"),
        ) from exc

    token = await create_honey_token(
        session,
        name=payload.name,
        token_type=ht_type,
        resource_pattern=payload.resource_pattern,
        description=payload.description,
    )
    return {
        "success": True,
        "token": {
            "token_id": token.token_id,
            "name": token.name,
            "token_type": token.token_type.value,
            "resource_pattern": (token.resource_pattern),
            "is_active": token.is_active,
        },
    }


@router.get("/honey-tokens")
async def list_honey_tokens_endpoint(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """List active honey tokens (no trap hashes)."""
    _ = current_user
    tokens = await list_honey_tokens(session)
    return {
        "success": True,
        "tokens": [
            {
                "token_id": t.token_id,
                "name": t.name,
                "token_type": t.token_type.value,
                "resource_pattern": (t.resource_pattern),
                "is_active": t.is_active,
            }
            for t in tokens
        ],
        "count": len(tokens),
    }


@router.get("/honey-tokens/triggers")
async def list_honey_token_triggers(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.AUDIT_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    principal: str = "",
):
    """List deception trigger events."""
    _ = current_user
    triggers = await get_triggers(
        session,
        principal=principal or None,
    )
    return {
        "success": True,
        "triggers": [
            {
                "trigger_id": t.trigger_id,
                "token_id": t.token_id,
                "principal": t.principal,
                "action": t.action,
                "resource": t.resource,
                "severity": t.severity,
                "trust_action": t.trust_action,
            }
            for t in triggers
        ],
        "count": len(triggers),
    }


@router.delete("/honey-tokens/{token_id}")
async def deactivate_honey_token_endpoint(
    token_id: Annotated[str, Path(min_length=1)],
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                Permission.CONFIG_UPDATE,
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Deactivate a honey token."""
    _ = current_user
    success = await deactivate_honey_token(
        session,
        token_id,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found",
        )
    return {"success": True, "token_id": token_id}


router.include_router(_verification_router)
