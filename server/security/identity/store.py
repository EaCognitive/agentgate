"""Persistence helpers for principal, role, and risk records."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import cast

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from server.models import (
    IdentityLink,
    IdentityPrincipal,
    PrincipalRiskLevel,
    RiskProfile,
    RoleBinding,
    User,
)
from server.utils.db import execute as db_execute

from .roles import default_risk_for_role, normalize_role


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _principal_id_for_user(user: User) -> str:
    if user.principal_id:
        return user.principal_id
    if user.id is not None:
        return f"user:{user.id}"
    return f"user:email:{user.email}"


async def _upsert_principal(
    session: AsyncSession,
    *,
    user: User,
    principal_id: str,
    provider: str,
    provider_subject: str | None,
    tenant_id: str,
) -> None:
    result = await db_execute(
        session,
        select(IdentityPrincipal).where(IdentityPrincipal.principal_id == principal_id),
    )
    principal = result.scalar_one_or_none()
    now = _utc_now()

    if principal is None:
        principal = IdentityPrincipal(
            principal_id=principal_id,
            principal_type="human_user",
            subject_id=user.email,
            tenant_id=tenant_id,
            provider=provider,
            provider_subject=provider_subject,
            display_name=user.name,
            created_at=now,
            updated_at=now,
        )
        session.add(principal)
        return

    principal.subject_id = user.email
    principal.tenant_id = tenant_id
    principal.provider = provider
    principal.provider_subject = provider_subject
    principal.display_name = user.name
    principal.updated_at = now
    session.add(principal)


async def _upsert_identity_link(
    session: AsyncSession,
    *,
    user: User,
    provider: str,
    provider_subject: str | None,
    tenant_id: str,
    principal_id: str,
) -> None:
    if not provider_subject:
        return

    result = await db_execute(
        session,
        select(IdentityLink).where(
            IdentityLink.provider == provider,
            IdentityLink.provider_subject == provider_subject,
            IdentityLink.tenant_id == tenant_id,
        ),
    )
    link = result.scalar_one_or_none()
    now = _utc_now()

    if link is None:
        link = IdentityLink(
            provider=provider,
            provider_subject=provider_subject,
            principal_id=principal_id,
            tenant_id=tenant_id,
            user_id=user.id,
            created_at=now,
            last_seen_at=now,
        )
        session.add(link)
        return

    link.principal_id = principal_id
    link.user_id = user.id
    link.last_seen_at = now
    session.add(link)


async def _ensure_role_bindings(
    session: AsyncSession,
    *,
    principal_id: str,
    tenant_id: str,
    roles: list[str],
) -> None:
    now = _utc_now()
    normalized_roles = [normalize_role(role) for role in roles if role]
    for role in normalized_roles:
        result = await db_execute(
            session,
            select(RoleBinding).where(
                RoleBinding.principal_id == principal_id,
                RoleBinding.role == role,
                RoleBinding.scope_type == "tenant",
                RoleBinding.scope_id == tenant_id,
            ),
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            session.add(
                RoleBinding(
                    principal_id=principal_id,
                    role=role,
                    scope_type="tenant",
                    scope_id=tenant_id,
                    source="identity_sync",
                    created_at=now,
                )
            )


async def _ensure_risk_profile(
    session: AsyncSession,
    *,
    principal_id: str,
    role: str,
) -> str:
    result = await db_execute(
        session,
        select(RiskProfile).where(RiskProfile.principal_id == principal_id),
    )
    profile = result.scalar_one_or_none()
    default_risk = default_risk_for_role(role)
    now = _utc_now()

    if profile is None:
        session.add(
            RiskProfile(
                principal_id=principal_id,
                principal_type="human_user",
                risk_level=default_risk,
                reason="default_role_baseline",
                reviewed_by="system",
                created_at=now,
                updated_at=now,
            )
        )
        return default_risk

    if profile.risk_level not in {level.value for level in PrincipalRiskLevel}:
        profile.risk_level = default_risk
        profile.reason = "normalized_invalid_risk_level"
    profile.updated_at = now
    session.add(profile)
    return cast(str, profile.risk_level)


async def ensure_user_identity_records(
    session: AsyncSession,
    *,
    user: User,
    provider: str,
    provider_subject: str | None,
    tenant_id: str,
    roles: list[str],
) -> tuple[str, str]:
    """Ensure principal/link/role/risk records exist for a user."""
    principal_id = _principal_id_for_user(user)
    user.principal_id = principal_id
    user.identity_provider = provider
    user.provider_subject = provider_subject
    user.tenant_id = tenant_id
    session.add(user)

    await _upsert_principal(
        session,
        user=user,
        principal_id=principal_id,
        provider=provider,
        provider_subject=provider_subject,
        tenant_id=tenant_id,
    )
    await _upsert_identity_link(
        session,
        user=user,
        provider=provider,
        provider_subject=provider_subject,
        tenant_id=tenant_id,
        principal_id=principal_id,
    )
    await _ensure_role_bindings(
        session,
        principal_id=principal_id,
        tenant_id=tenant_id,
        roles=roles or [user.role],
    )
    risk_level = await _ensure_risk_profile(
        session,
        principal_id=principal_id,
        role=user.role,
    )
    return principal_id, risk_level


async def get_principal_risk(
    session: AsyncSession,
    *,
    principal_id: str | None,
    fallback_role: str,
) -> str:
    """Resolve principal baseline risk, falling back to role-derived defaults."""
    if not principal_id:
        return default_risk_for_role(fallback_role)
    result = await db_execute(
        session,
        select(RiskProfile).where(RiskProfile.principal_id == principal_id),
    )
    profile = result.scalar_one_or_none()
    if profile is None:
        return default_risk_for_role(fallback_role)
    return cast(str, profile.risk_level)


async def get_roles_for_principal(
    session: AsyncSession,
    *,
    principal_id: str | None,
    tenant_id: str,
    fallback_role: str,
) -> list[str]:
    """Resolve scoped roles for a principal with fallback to current user role."""
    if not principal_id:
        return [normalize_role(fallback_role)]

    result = await db_execute(
        session,
        select(RoleBinding).where(
            RoleBinding.principal_id == principal_id,
            RoleBinding.scope_type == "tenant",
            RoleBinding.scope_id == tenant_id,
        ),
    )
    roles = [normalize_role(binding.role) for binding in result.scalars().all()]
    if roles:
        return sorted(set(roles))
    return [normalize_role(fallback_role)]


def generate_decision_id(prefix: str = "dec") -> str:
    """Generate deterministic-length decision identifiers."""
    return f"{prefix}_{uuid.uuid4().hex[:24]}"
