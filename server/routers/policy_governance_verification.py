"""Verification, evidence, and consensus API routes.

Extracted from policy_governance.py to satisfy REQ-MOD-01.
Covers certificate verification, counterfactual verification,
evidence chain integrity, transparency log, safety nodes,
and global revocations.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.functions import count as sql_count
from sqlmodel import col, select

from server.models import (
    DecisionCertificateRecord,
    Permission,
    PolicyDecisionRecord,
    User,
    get_session,
)
from server.policy_governance.kernel.counterfactual_verifier import (
    verify_counterfactual_plan,
)
from server.policy_governance.kernel.evidence_log import (
    verify_decision_certificate,
    verify_evidence_chain,
)
from server.security.identity import (
    normalize_assurance_level,
    normalize_role,
    required_assurance_for_risk,
)
from server.security.identity.store import (
    generate_decision_id,
)
from server.policy_governance.kernel.verification_grants import (
    consume_verification_grant as consume_grant_token,
    risk_tier_to_level,
)
from server.policy_governance.kernel.consensus_verifier import (
    get_global_revocations,
    get_safety_nodes,
    get_transparency_log,
    register_safety_node,
    remove_safety_node,
    verify_transparency_log,
)
from server.utils.db import (
    commit as db_commit,
    execute as db_execute,
)

from .auth import (
    get_current_auth_claims,
    require_permission,
)


router = APIRouter(tags=["security-formal"])

_ASSURANCE_ORDER = {
    "A1": 1,
    "A2": 2,
    "A3": 3,
}
_TENANT_RESOURCE_PATTERN = re.compile(
    r"tenant[:/](?P<tenant>[A-Za-z0-9._-]+)",
)


def _is_assurance_sufficient(
    current: str,
    required: str,
) -> bool:
    """Check if current assurance meets required level."""
    current_level = _ASSURANCE_ORDER[normalize_assurance_level(current)]
    required_level = _ASSURANCE_ORDER[normalize_assurance_level(required)]
    return current_level >= required_level


def _extract_resource_tenant(
    resource: str,
) -> str | None:
    """Extract tenant identifier from resource string."""
    match = _TENANT_RESOURCE_PATTERN.search(resource)
    if not match:
        return None
    return match.group("tenant")


@dataclass(slots=True)
class CounterfactualContext:
    """Derived authorization context for a counterfactual verification run."""

    tenant_scope: str
    required_risk: str
    required_assurance: str
    session_assurance: str
    normalized_role: str


def _counterfactual_context(
    payload: "CounterfactualVerifyRequest",
    current_user: User,
    auth_claims: dict[str, Any],
) -> CounterfactualContext:
    """Build normalized counterfactual verification context."""
    required_risk = risk_tier_to_level(payload.risk_tier)
    return CounterfactualContext(
        tenant_scope=payload.tenant_id or current_user.tenant_id or "default",
        required_risk=required_risk,
        required_assurance=required_assurance_for_risk(required_risk),
        session_assurance=normalize_assurance_level(
            str(auth_claims.get("session_assurance", "A1")),
        ),
        normalized_role=normalize_role(current_user.role),
    )


def _ensure_counterfactual_access(context: CounterfactualContext) -> None:
    """Validate assurance and role requirements for the counterfactual request."""
    if not _is_assurance_sufficient(context.session_assurance, context.required_assurance):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Session assurance "
                f"{context.session_assurance} does not "
                f"satisfy required level "
                f"{context.required_assurance}. Step-up "
                f"authentication is required."
            ),
        )

    high_risk_roles = {"admin", "security_admin", "approver"}
    if context.required_risk in {"R3", "R4"} and context.normalized_role not in high_risk_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="High-risk verification requires admin/security approver roles",
        )


async def _maybe_consume_verification_grant(
    session: AsyncSession,
    *,
    payload: "CounterfactualVerifyRequest",
    context: CounterfactualContext,
    current_user: User,
) -> None:
    """Validate and consume the verification grant token when required."""
    environment = os.getenv("AGENTGATE_ENV", "development").strip().lower()
    requires_grant = environment in {"staging", "production"} or context.required_risk in {
        "R3",
        "R4",
    }
    if requires_grant and not payload.verification_grant_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "verification_grant_token is required "
                "for counterfactual verification "
                "in this environment/risk tier"
            ),
        )
    if payload.verification_grant_token:
        await consume_grant_token(
            session,
            grant_token=payload.verification_grant_token,
            current_user=current_user,
            required_risk_level=context.required_risk,
            session_assurance=context.session_assurance,
            tenant_id=context.tenant_scope,
            expected_purpose_prefix="penetration_test",
        )


def _enriched_counterfactual_steps(
    payload: "CounterfactualVerifyRequest",
    *,
    current_user: User,
    context: CounterfactualContext,
) -> list[dict[str, Any]]:
    """Inject actor context into each counterfactual step after scope validation."""
    enriched_steps: list[dict[str, Any]] = []
    principal_id = current_user.principal_id or f"user:{current_user.id}"
    for step in payload.steps:
        resource = str(step.get("resource", ""))
        scoped_tenant = _extract_resource_tenant(resource)
        if scoped_tenant and scoped_tenant != context.tenant_scope:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Step resource tenant "
                    f"'{scoped_tenant}' is outside "
                    f"authorized scope "
                    f"'{context.tenant_scope}'"
                ),
            )

        step_copy = dict(step)
        step_context = step_copy.get("context", {})
        if not isinstance(step_context, dict):
            step_context = {}
        step_context["actor_principal_id"] = principal_id
        step_context["actor_role"] = context.normalized_role
        step_context["actor_tenant_id"] = context.tenant_scope
        step_context["session_assurance"] = context.session_assurance
        step_copy["context"] = step_context
        enriched_steps.append(step_copy)
    return enriched_steps


def _counterfactual_obligations(context: CounterfactualContext) -> list[str]:
    """Build the obligation list associated with a counterfactual decision."""
    obligations = ["verification_grant", "immutable_evidence_record"]
    if context.required_risk in {"R3", "R4"}:
        obligations.append("human_approval")
    if context.session_assurance == "A3":
        obligations.append("step_up_satisfied")
    return obligations


async def _record_counterfactual_decision(
    session: AsyncSession,
    *,
    current_user: User,
    context: CounterfactualContext,
    safe: bool,
) -> str:
    """Persist the counterfactual authorization decision record."""
    decision_id = generate_decision_id(prefix="cfv")
    record_principal = current_user.principal_id or f"user:{current_user.id}"
    session.add(
        PolicyDecisionRecord(
            decision_id=decision_id,
            principal_id=record_principal,
            tenant_id=context.tenant_scope,
            action="security.counterfactual.verify",
            resource=f"tenant:{context.tenant_scope}:counterfactual",
            allowed=safe,
            reason="counterfactual_safe" if safe else "counterfactual_blocked",
            effective_risk=context.required_risk,
            required_assurance=context.required_assurance,
            session_assurance=context.session_assurance,
            required_step_up=False,
            required_approval=context.required_risk in {"R3", "R4"},
            obligations_json=_counterfactual_obligations(context),
            trace_id=None,
        )
    )
    await db_commit(session)
    return decision_id


# ------------------------------------------------------------------
# Request / response models
# ------------------------------------------------------------------


class CertificateVerifyRequest(BaseModel):
    """Request payload for certificate verification."""

    decision_id: str = Field(min_length=1)


class CounterfactualVerifyRequest(BaseModel):
    """Request for bounded counterfactual verification."""

    principal: str = Field(min_length=1)
    tenant_id: str | None = None
    risk_tier: str = Field(
        default="high",
        pattern="^(low|medium|high|critical)$",
    )
    steps: list[dict[str, Any]] = Field(min_length=1)
    verification_grant_token: str | None = Field(
        default=None,
        min_length=10,
        max_length=256,
    )


class TransparencyLogVerifyRequest(BaseModel):
    """Request for transparency log verification."""

    start_index: int = Field(default=0, ge=0)
    end_index: int | None = None


class SafetyNodeRegisterRequest(BaseModel):
    """Request for safety node registration."""

    endpoint_url: str = Field(min_length=1)
    public_key_pem: str = Field(min_length=1)
    is_local: bool = False


# ------------------------------------------------------------------
# Certificate verification
# ------------------------------------------------------------------


@router.post("/certificate/verify")
async def verify_certificate(
    payload: CertificateVerifyRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Verify persisted certificate signature."""
    _ = current_user
    run = await verify_decision_certificate(
        session,
        decision_id=payload.decision_id,
    )
    return {
        "success": True,
        "valid": bool(run.verification_result),
        "verification_run": {
            "run_id": run.run_id,
            "decision_id": run.decision_id,
            "verification_result": (run.verification_result),
            "details": run.details,
            "checked_at": run.checked_at,
        },
    }


@router.post("/formal/verify")
async def verify_certificate_legacy(
    payload: CertificateVerifyRequest,
    response: Response,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Compatibility alias for /security/formal/verify."""
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = (
        '299 - "Deprecated endpoint. Use /api/security/certificate/verify instead."'
    )
    result = await verify_certificate(
        payload,
        current_user,
        session,
    )
    verification_run = result["verification_run"]
    return {
        "valid": bool(verification_run["verification_result"]),
        "decision_id": (verification_run["decision_id"]),
        "verification_run": verification_run,
        "deprecated": True,
        "replacement_endpoint": ("/api/security/certificate/verify"),
    }


# ------------------------------------------------------------------
# Counterfactual verification
# ------------------------------------------------------------------


@router.post("/counterfactual/verify")
async def verify_counterfactual(
    payload: CounterfactualVerifyRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    auth_claims: Annotated[
        dict[str, Any],
        Depends(get_current_auth_claims),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Perform bounded counterfactual verification."""
    context = _counterfactual_context(payload, current_user, auth_claims)
    _ensure_counterfactual_access(context)
    await _maybe_consume_verification_grant(
        session,
        payload=payload,
        context=context,
        current_user=current_user,
    )
    enriched_steps = _enriched_counterfactual_steps(
        payload,
        current_user=current_user,
        context=context,
    )

    result = await verify_counterfactual_plan(
        session,
        principal=payload.principal,
        tenant_id=context.tenant_scope,
        steps=enriched_steps,
        risk_tier=payload.risk_tier,
    )

    decision_id = await _record_counterfactual_decision(
        session,
        current_user=current_user,
        context=context,
        safe=result.safe,
    )

    return {
        "success": True,
        "decision_id": decision_id,
        "safe": result.safe,
        "risk_tier": result.risk_tier,
        "evaluated_steps": result.evaluated_steps,
        "bound": result.bound,
        "blocked_step_index": (result.blocked_step_index),
        "counterexample": result.counterexample,
        "trace": result.trace,
        "verification_grant_consumed": bool(
            payload.verification_grant_token,
        ),
    }


# ------------------------------------------------------------------
# Evidence chain
# ------------------------------------------------------------------


@router.get("/evidence/chain/{chain_id}")
async def get_evidence_chain_status(
    chain_id: Annotated[str, Path(min_length=1)],
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.AUDIT_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Verify integrity of immutable evidence chain."""
    _ = current_user
    status_result = await verify_evidence_chain(
        session,
        chain_id=chain_id,
    )
    return {
        "success": True,
        "chain_id": status_result.chain_id,
        "valid": status_result.valid,
        "checked_entries": (status_result.checked_entries),
        "failure_reason": (status_result.failure_reason),
        "failed_hop_index": (status_result.failed_hop_index),
    }


@router.get("/formal/evidence")
async def get_evidence_chain_status_legacy(
    response: Response,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.AUDIT_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    chain_id: str = Query(
        default="global",
        min_length=1,
    ),
):
    """Compatibility alias for /security/formal/evidence."""
    response.headers["Deprecation"] = "true"
    response.headers["Warning"] = (
        '299 - "Deprecated endpoint. Use /api/security/evidence/chain/{chain_id} instead."'
    )
    result = await get_evidence_chain_status(
        chain_id,
        current_user,
        session,
    )
    return {
        "valid": bool(result["valid"]),
        "integrity_verified": bool(result["valid"]),
        "entries_verified": (result["checked_entries"]),
        "total_entries": result["checked_entries"],
        "chain_id": result["chain_id"],
        "failure_reason": result["failure_reason"],
        "failed_hop_index": (result["failed_hop_index"]),
        "deprecated": True,
        "replacement_endpoint": ("/api/security/evidence/chain/{chain_id}"),
    }


# ------------------------------------------------------------------
# Distributed Certificate Consensus
# ------------------------------------------------------------------


@router.get("/transparency-log")
async def get_transparency_log_endpoint(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.AUDIT_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = 100,
    offset: int = 0,
):
    """Query certificate transparency log."""
    _ = current_user
    entries = await get_transparency_log(
        session,
        limit=limit,
        offset=offset,
    )
    return {
        "success": True,
        "entries": [
            {
                "log_index": e.log_index,
                "decision_id": e.decision_id,
                "certificate_hash": (e.certificate_hash),
                "result": e.result,
                "node_id": e.node_id,
            }
            for e in entries
        ],
        "count": len(entries),
    }


@router.post("/transparency-log/verify")
async def verify_transparency_log_endpoint(
    payload: TransparencyLogVerifyRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.AUDIT_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Verify transparency log integrity."""
    _ = current_user
    verification = await verify_transparency_log(
        session,
        start_index=payload.start_index,
        end_index=payload.end_index,
    )
    return {
        "success": True,
        "valid": verification.valid,
        "checked_entries": (verification.checked_entries),
        "failure_reason": (verification.failure_reason),
        "failed_index": verification.failed_index,
    }


@router.post(
    "/safety-nodes",
    status_code=status.HTTP_201_CREATED,
)
async def register_safety_node_endpoint(
    payload: SafetyNodeRegisterRequest,
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
    """Register a safety node for consensus."""
    _ = current_user
    node = await register_safety_node(
        session,
        endpoint_url=payload.endpoint_url,
        public_key_pem=payload.public_key_pem,
        is_local=payload.is_local,
    )
    return {
        "success": True,
        "node": {
            "node_id": node.node_id,
            "endpoint_url": node.endpoint_url,
            "is_local": node.is_local,
            "trust_score": node.trust_score,
        },
    }


@router.get("/safety-nodes")
async def list_safety_nodes_endpoint(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """List registered safety nodes."""
    _ = current_user
    nodes = await get_safety_nodes(session)
    return {
        "success": True,
        "nodes": [
            {
                "node_id": n.node_id,
                "endpoint_url": n.endpoint_url,
                "is_local": n.is_local,
                "trust_score": n.trust_score,
            }
            for n in nodes
        ],
        "count": len(nodes),
    }


@router.delete("/safety-nodes/{node_id}")
async def remove_safety_node_endpoint(
    node_id: Annotated[str, Path(min_length=1)],
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
    """Remove a safety node from the registry."""
    _ = current_user
    success = await remove_safety_node(
        session,
        node_id,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Node not found",
        )
    return {"success": True, "node_id": node_id}


@router.get("/global-revocations")
async def list_global_revocations(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.AUDIT_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """List all global certificate revocations."""
    _ = current_user
    revocations = await get_global_revocations(
        session,
    )
    return {
        "success": True,
        "revocations": revocations,
        "count": len(revocations),
    }


# ------------------------------------------------------------------
# Certificate lookup, stats, and retrieval
# ------------------------------------------------------------------


@router.get("/certificates/lookup")
async def lookup_certificates(
    *,
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    alpha_hash: str | None = Query(default=None),
    gamma_hash: str | None = Query(default=None),
    theorem_hash: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    """Look up decision certificates by hash values."""
    _ = current_user
    if not any([alpha_hash, gamma_hash, theorem_hash]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=("At least one of alpha_hash, gamma_hash, or theorem_hash is required"),
        )

    statement = select(DecisionCertificateRecord)
    if alpha_hash is not None:
        statement = statement.where(
            DecisionCertificateRecord.alpha_hash == alpha_hash,
        )
    if gamma_hash is not None:
        statement = statement.where(
            DecisionCertificateRecord.gamma_hash == gamma_hash,
        )
    if theorem_hash is not None:
        statement = statement.where(
            DecisionCertificateRecord.theorem_hash == theorem_hash,
        )
    statement = statement.order_by(desc(DecisionCertificateRecord.created_at))
    statement = statement.limit(limit)
    result = await db_execute(session, statement)
    rows = result.scalars().all()

    certificates = [
        {
            "decision_id": r.decision_id,
            "theorem_hash": r.theorem_hash,
            "result": r.result,
            "proof_type": r.proof_type,
            "alpha_hash": r.alpha_hash,
            "gamma_hash": r.gamma_hash,
            "principal": r.principal,
            "action": r.action,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
    return {
        "success": True,
        "certificates": certificates,
        "count": len(certificates),
    }


@router.get("/certificates/stats")
async def certificate_stats(
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    hours: int = Query(default=24, ge=1, le=720),
):
    """Aggregate certificate statistics over a time window."""
    _ = current_user
    since = datetime.now(timezone.utc) - timedelta(
        hours=hours,
    )

    by_result_stmt = (
        select(
            DecisionCertificateRecord.result,
            sql_count(),
        )
        .where(
            col(DecisionCertificateRecord.created_at) >= since,
        )
        .group_by(DecisionCertificateRecord.result)
    )
    by_proof_stmt = (
        select(
            DecisionCertificateRecord.proof_type,
            sql_count(),
        )
        .where(
            col(DecisionCertificateRecord.created_at) >= since,
        )
        .group_by(DecisionCertificateRecord.proof_type)
    )

    result_rows = await db_execute(session, by_result_stmt)
    proof_rows = await db_execute(session, by_proof_stmt)

    by_result: dict[str, int] = {}
    for label, cnt in result_rows:
        by_result[label] = cnt
    by_proof_type: dict[str, int] = {}
    for label, cnt in proof_rows:
        by_proof_type[label] = cnt

    total = sum(by_result.values())
    admissible = by_result.get("admissible", 0)
    inadmissible = by_result.get("inadmissible", 0)

    return {
        "success": True,
        "total_decisions": total,
        "admissible": admissible,
        "inadmissible": inadmissible,
        "by_result": by_result,
        "by_proof_type": by_proof_type,
        "period_hours": hours,
    }


@router.get("/certificates/{decision_id}")
async def get_certificate(
    decision_id: Annotated[str, Path(min_length=1)],
    current_user: Annotated[
        User,
        Depends(require_permission(Permission.CONFIG_READ)),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Retrieve a single decision certificate by ID."""
    _ = current_user
    statement = select(DecisionCertificateRecord).where(
        DecisionCertificateRecord.decision_id == decision_id,
    )
    result = await db_execute(session, statement)
    cert = result.scalars().first()
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found",
        )
    return {
        "success": True,
        "certificate": {
            "decision_id": cert.decision_id,
            "theorem_hash": cert.theorem_hash,
            "result": cert.result,
            "proof_type": cert.proof_type,
            "alpha_hash": cert.alpha_hash,
            "gamma_hash": cert.gamma_hash,
            "principal": cert.principal,
            "action": cert.action,
            "resource": cert.resource,
            "tenant_id": cert.tenant_id,
            "solver_version": cert.solver_version,
            "signature": cert.signature,
            "created_at": cert.created_at.isoformat(),
        },
    }
