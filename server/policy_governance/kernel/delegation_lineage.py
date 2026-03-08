"""Delegation lineage issuance and validation utilities.

This module enforces chain-of-command constraints for delegated authority,
including attenuation, tenant isolation, expiry, and revocation semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypedDict, cast
from uuid import uuid4

from sqlalchemy import false
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from server.models.formal_security_schemas import DelegationGrant, DelegationRevocation
from server.utils.db import commit as db_commit
from server.utils.db import execute as db_execute
from server.utils.db import refresh as db_refresh


DEFAULT_MAX_DELEGATION_DEPTH = 8


def utc_now() -> datetime:
    """Return timezone-naive UTC timestamp for DB comparisons."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(slots=True)
class LineageValidationResult:
    """Lineage validation output with detailed evidence payload."""

    valid: bool
    reason: str
    chain: list[str]
    witness: dict[str, Any]


class DelegationLineageError(RuntimeError):
    """Raised when delegation issuance/revocation constraints are violated."""


class DelegationGrantRequest(TypedDict, total=False):
    """Structured inputs required to issue a delegation grant."""

    principal: str
    delegate: str
    tenant_id: str
    allowed_actions: list[str]
    resource_scope: str
    expires_at: datetime
    parent_grant_id: str | None
    obligations: dict[str, Any] | None
    context_constraints: dict[str, Any] | None
    issued_by_user_id: int | None
    signature: str


_DELEGATION_REQUEST_DEFAULTS: DelegationGrantRequest = {
    "parent_grant_id": None,
    "obligations": None,
    "context_constraints": None,
    "issued_by_user_id": None,
    "signature": "pending",
}


def _parse_delegation_grant_request(
    request: DelegationGrantRequest | None,
    legacy_kwargs: dict[str, Any],
) -> DelegationGrantRequest:
    """Build a validated delegation grant request from kwargs."""
    required_keys = {
        "principal",
        "delegate",
        "tenant_id",
        "allowed_actions",
        "resource_scope",
        "expires_at",
    }
    resolved: DelegationGrantRequest = dict(_DELEGATION_REQUEST_DEFAULTS)
    if request:
        resolved.update(request)
    resolved.update(legacy_kwargs)
    missing_keys = sorted(required_keys - set(resolved))
    if missing_keys:
        names = ", ".join(missing_keys)
        raise TypeError(f"Missing delegation grant option(s): {names}")
    return resolved


def _resource_scope_matches(scope: str, resource: str) -> bool:
    """Evaluate whether a resource is covered by a delegation scope."""
    if scope == "*":
        return True
    if scope.endswith("*"):
        return resource.startswith(scope[:-1])
    return scope == resource


def _actions_contain(required_action: str, allowed_actions: list[str]) -> bool:
    """Check whether a required action is allowed by delegated action set."""
    return "*" in allowed_actions or required_action in allowed_actions


def _is_subset(child_actions: list[str], parent_actions: list[str]) -> bool:
    """Check attenuation invariant for action permissions."""
    if "*" in parent_actions:
        return True
    return set(child_actions).issubset(set(parent_actions))


def _scope_subset(child_scope: str, parent_scope: str) -> bool:
    """Check attenuation invariant for resource scopes."""
    if parent_scope == "*":
        return True
    if parent_scope.endswith("*"):
        return child_scope.startswith(parent_scope[:-1])
    return child_scope == parent_scope


def _validate_parent_grant_constraints(
    parent: DelegationGrant,
    principal: str,
    tenant_id: str,
    allowed_actions: list[str],
    resource_scope: str,
) -> None:
    """Validate attenuation constraints against a parent delegation grant.

    Raises DelegationLineageError when any constraint is violated.
    """
    if parent.revoked:
        raise DelegationLineageError("Parent delegation grant has been revoked")
    if parent.expires_at <= utc_now():
        raise DelegationLineageError("Parent delegation grant has expired")
    if parent.tenant_id != tenant_id:
        raise DelegationLineageError("Cross-tenant delegation is not permitted")
    if parent.delegate != principal:
        raise DelegationLineageError("Parent delegate must match principal")
    if not _is_subset(allowed_actions, parent.allowed_actions):
        raise DelegationLineageError("Delegated actions violate attenuation constraint")
    if not _scope_subset(resource_scope, parent.resource_scope):
        raise DelegationLineageError("Delegated resource scope violates attenuation constraint")


async def issue_delegation_grant(
    session: AsyncSession,
    *,
    request: DelegationGrantRequest | None = None,
    **legacy_kwargs: Any,
) -> DelegationGrant:
    """Issue a new delegation grant with attenuation validation."""
    if request is not None and legacy_kwargs:
        names = ", ".join(sorted(legacy_kwargs))
        raise TypeError(f"Unsupported delegation grant option(s): {names}")
    request = _parse_delegation_grant_request(request, legacy_kwargs)

    hop_index = 0

    if request["parent_grant_id"]:
        result = await db_execute(
            session,
            select(DelegationGrant).where(DelegationGrant.grant_id == request["parent_grant_id"]),
        )
        parent = result.scalar_one_or_none()
        if parent is None:
            raise DelegationLineageError("Parent delegation grant does not exist")
        _validate_parent_grant_constraints(
            parent,
            request["principal"],
            request["tenant_id"],
            request["allowed_actions"],
            request["resource_scope"],
        )
        hop_index = parent.hop_index + 1

    if hop_index >= DEFAULT_MAX_DELEGATION_DEPTH:
        raise DelegationLineageError("Delegation depth exceeds configured maximum")

    expires_at = request["expires_at"]
    if expires_at.tzinfo is not None:
        expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)

    grant = DelegationGrant(
        grant_id=f"g_{uuid4().hex}",
        principal=request["principal"],
        delegate=request["delegate"],
        tenant_id=request["tenant_id"],
        parent_grant_id=request["parent_grant_id"],
        hop_index=hop_index,
        allowed_actions=sorted(set(request["allowed_actions"])),
        resource_scope=request["resource_scope"],
        obligations=request["obligations"] or {},
        context_constraints=request["context_constraints"] or {},
        signature=request["signature"],
        issued_by_user_id=request["issued_by_user_id"],
        expires_at=expires_at,
    )
    session.add(grant)
    await db_commit(session)
    await db_refresh(session, grant)
    return grant


async def revoke_delegation_grant(
    session: AsyncSession,
    *,
    grant_id: str,
    tenant_id: str,
    reason: str,
    revoked_by_user_id: int | None,
    transitive: bool = True,
) -> DelegationRevocation:
    """Revoke delegation grant and optionally revoke descendants transitively."""
    result = await db_execute(
        session,
        select(DelegationGrant).where(
            DelegationGrant.grant_id == grant_id,
            DelegationGrant.tenant_id == tenant_id,
        ),
    )
    grant = result.scalar_one_or_none()
    if grant is None:
        raise DelegationLineageError("Delegation grant not found")

    now = utc_now()
    grant.revoked = True
    grant.revoked_at = now
    session.add(grant)

    if transitive:
        await _revoke_descendants(session, grant.grant_id, now)

    revocation = DelegationRevocation(
        revocation_id=f"r_{uuid4().hex}",
        grant_id=grant.grant_id,
        tenant_id=tenant_id,
        revoked_by_user_id=revoked_by_user_id,
        reason=reason,
        transitive=transitive,
    )
    session.add(revocation)
    await db_commit(session)
    await db_refresh(session, revocation)
    return revocation


async def _revoke_descendants(
    session: AsyncSession,
    parent_grant_id: str,
    revoked_at: datetime,
) -> None:
    """Recursively revoke descendant grants."""
    result = await db_execute(
        session,
        select(DelegationGrant).where(DelegationGrant.parent_grant_id == parent_grant_id),
    )
    descendants = result.scalars().all()
    for descendant in descendants:
        if descendant.revoked:
            continue
        descendant.revoked = True
        descendant.revoked_at = revoked_at
        session.add(descendant)
        await _revoke_descendants(session, descendant.grant_id, revoked_at)


def _walk_parent_chain(
    grant_index: dict[str, dict[str, Any]],
    revoked_grants: set[str],
    start_grant: dict[str, Any],
    tenant_id: str | None,
    max_depth: int,
) -> LineageValidationResult | None:
    """Walk the parent chain of a delegation grant, validating each hop.

    Returns a ``LineageValidationResult`` with ``valid=False`` when a
    constraint violation is detected.  Returns ``None`` when the full
    parent chain is valid so the caller can build the success result.

    Args:
        grant_index: Mapping of grant_id to grant dict.
        revoked_grants: Set of revoked grant IDs.
        start_grant: The candidate grant to walk from.
        tenant_id: Tenant scope constraint (may be None).
        max_depth: Maximum allowed delegation depth.

    Returns:
        A failure result, or None when the chain is fully valid.
    """
    lineage: list[str] = [start_grant["grant_id"]]
    current = start_grant
    depth = 0

    while current.get("parent_grant_id"):
        depth += 1
        if depth > max_depth:
            return _lineage_failure(
                lineage,
                "Delegation depth exceeded configured maximum",
                {"max_depth": max_depth},
            )

        parent_id = current["parent_grant_id"]
        parent = grant_index.get(parent_id)
        failure = _parent_chain_failure(
            parent=parent,
            parent_id=parent_id,
            current=current,
            lineage=lineage,
            revoked_grants=revoked_grants,
            tenant_id=tenant_id,
        )
        if failure is not None:
            return failure

        lineage.append(parent["grant_id"])
        current = parent

    return None


def _lineage_failure(
    lineage: list[str],
    reason: str,
    witness: dict[str, Any],
) -> LineageValidationResult:
    """Create a standardized invalid lineage result."""
    return LineageValidationResult(
        valid=False,
        reason=reason,
        chain=lineage,
        witness=witness,
    )


def _parent_chain_failure(
    *,
    parent: dict[str, Any] | None,
    parent_id: str,
    current: dict[str, Any],
    lineage: list[str],
    revoked_grants: set[str],
    tenant_id: str | None,
) -> LineageValidationResult | None:
    """Return the first parent-chain validation failure, if any."""
    if parent is None:
        return _lineage_failure(
            lineage,
            "Delegation lineage broken: parent grant missing",
            {"missing_parent": parent_id},
        )
    if parent["grant_id"] in revoked_grants or parent.get("revoked", False):
        return _lineage_failure(
            lineage,
            "Delegation lineage includes revoked grant",
            {"revoked_parent": parent["grant_id"]},
        )
    if tenant_id and parent.get("tenant_id") != tenant_id:
        return _lineage_failure(
            lineage,
            "Delegation lineage crosses tenant boundary",
            {"parent_tenant": parent.get("tenant_id")},
        )
    if not _is_subset(current.get("allowed_actions", []), parent.get("allowed_actions", [])):
        return _lineage_failure(
            lineage,
            "Delegation actions violate attenuation",
            {
                "child_actions": current.get("allowed_actions", []),
                "parent_actions": parent.get("allowed_actions", []),
            },
        )
    if _scope_subset(current.get("resource_scope", "*"), parent.get("resource_scope", "*")):
        return None
    return _lineage_failure(
        lineage,
        "Delegation scope violates attenuation",
        {
            "child_scope": current.get("resource_scope"),
            "parent_scope": parent.get("resource_scope"),
        },
    )


def validate_lineage_chain(
    *,
    principal: str,
    action: str,
    resource: str,
    tenant_id: str | None,
    grants: list[dict[str, Any]],
    revocations: list[dict[str, Any]],
    required_delegation_ref: str | None,
    max_depth: int = DEFAULT_MAX_DELEGATION_DEPTH,
) -> LineageValidationResult:
    """Validate delegation chain from in-memory grant/revocation facts."""
    revoked_grants = {record["grant_id"] for record in revocations}
    grant_index = {record["grant_id"]: record for record in grants}

    if required_delegation_ref:
        candidate_grants = [grant_index.get(required_delegation_ref)]
    else:
        candidate_grants = [g for g in grants if g["delegate"] == principal]

    for candidate in candidate_grants:
        if not candidate:
            continue
        if candidate["grant_id"] in revoked_grants or candidate.get("revoked", False):
            continue
        if tenant_id and candidate.get("tenant_id") != tenant_id:
            continue
        if not _actions_contain(
            action,
            candidate.get("allowed_actions", []),
        ):
            continue
        if not _resource_scope_matches(
            candidate.get("resource_scope", "*"),
            resource,
        ):
            continue

        failure = _walk_parent_chain(
            grant_index,
            revoked_grants,
            candidate,
            tenant_id,
            max_depth,
        )
        if failure is not None:
            return failure

        lineage = [candidate["grant_id"]]
        current = candidate
        while current.get("parent_grant_id"):
            parent_id = current["parent_grant_id"]
            current = grant_index[parent_id]
            lineage.append(current["grant_id"])

        return LineageValidationResult(
            valid=True,
            reason="Delegation lineage validated",
            chain=lineage,
            witness={"root_grant": lineage[-1]},
        )

    return LineageValidationResult(
        valid=False,
        reason="No active delegation grant authorizes action",
        chain=[],
        witness={
            "principal": principal,
            "action": action,
            "resource": resource,
            "required_ref": required_delegation_ref,
        },
    )


async def fetch_active_grants(
    session: AsyncSession,
    *,
    principal: str,
    at_time: datetime,
    tenant_id: str | None,
) -> list[DelegationGrant]:
    """Fetch active grants for principal at given timestamp."""
    query = (
        select(DelegationGrant)
        .where(DelegationGrant.delegate == principal)
        .where(col(DelegationGrant.revoked) == false())
        .where(DelegationGrant.expires_at > at_time)
    )
    if tenant_id:
        query = query.where(DelegationGrant.tenant_id == tenant_id)

    result = await db_execute(session, query)
    return cast(list[DelegationGrant], result.scalars().all())


async def fetch_active_revocations(
    session: AsyncSession,
    *,
    tenant_id: str | None,
) -> list[DelegationRevocation]:
    """Fetch revocations scoped to tenant when provided."""
    query = select(DelegationRevocation)
    if tenant_id:
        query = query.where(col(DelegationRevocation.tenant_id) == tenant_id)
    result = await db_execute(session, query)
    return cast(list[DelegationRevocation], result.scalars().all())
