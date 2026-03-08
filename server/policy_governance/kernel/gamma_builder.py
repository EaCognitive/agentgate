"""Gamma builder for formal admissibility evaluation.

Builds canonical trusted knowledge base facts from persisted state:
- Active delegation grants and revocations
- Active policy set
- Required obligations (MFA/approval/confirm)
- Environment and tenancy constraints
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, cast

from sqlalchemy import true
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from server.models.formal_security_schemas import DelegationGrant, DelegationRevocation
from server.models.security_policy_schemas import SecurityPolicy
from server.utils.db import execute as db_execute
from .delegation_lineage import fetch_active_grants, fetch_active_revocations
from .formal_models import AlphaContext, GammaKnowledgeBase


@dataclass(slots=True)
class GammaBuildResult:
    """Builder output including materialized gamma model and source metadata."""

    gamma: GammaKnowledgeBase
    source_counts: dict[str, int]


class GammaBuilder:
    """Construct deterministic `Gamma` from active database state."""

    def __init__(self, session: AsyncSession):
        self._session = session

    @property
    def session(self) -> AsyncSession:
        """Return the active database session."""
        return self._session

    async def build(self, alpha: AlphaContext) -> GammaBuildResult:
        """Build canonical `Gamma` for a specific alpha context."""
        grants = await fetch_active_grants(
            self._session,
            principal=alpha.principal,
            at_time=alpha.time.replace(tzinfo=None),
            tenant_id=alpha.tenant_id,
        )
        revocations = await fetch_active_revocations(
            self._session,
            tenant_id=alpha.tenant_id,
        )
        policies = await self._load_active_policies()

        guardrails_module = import_module("server.mcp.guardrails")
        load_guardrails = getattr(guardrails_module, "load_guardrails")
        guardrails = load_guardrails()
        obligations = self._build_obligations(guardrails)
        environment = {
            "guardrails_version": guardrails.version,
            "blocked_operations": sorted(guardrails.blocked_operations),
            "approval_required_operations": sorted(guardrails.require_approval),
            "hardcoded_blocked": sorted(list(guardrails.blocked_operations)),
        }

        grant_payload = [self._grant_to_fact(record) for record in grants]
        revocation_payload = [self._revocation_to_fact(record) for record in revocations]
        policy_payload = [self._policy_to_fact(record) for record in policies]

        facts = [
            *self._grant_predicates(grant_payload),
            *self._revocation_predicates(revocation_payload),
            *self._policy_predicates(policy_payload),
            *self._obligation_predicates(obligations),
        ]

        gamma = GammaKnowledgeBase(
            principal=alpha.principal,
            tenant_id=alpha.tenant_id,
            facts=facts,
            active_grants=grant_payload,
            active_revocations=revocation_payload,
            policies=policy_payload,
            obligations=obligations,
            environment=environment,
        )

        # Inject honey-token canary facts into gamma
        gamma = await self._inject_honey_tokens(gamma)

        gamma.compute_gamma_hash()

        return GammaBuildResult(
            gamma=gamma,
            source_counts={
                "grants": len(grants),
                "revocations": len(revocations),
                "policies": len(policies),
                "facts": len(gamma.facts),
            },
        )

    async def _inject_honey_tokens(
        self,
        gamma: GammaKnowledgeBase,
    ) -> GammaKnowledgeBase:
        """Inject honey-token canary facts into gamma knowledge base."""
        try:
            deception_injector = import_module(
                "server.policy_governance.kernel.deception_injector"
            )
            inject_into_gamma = getattr(deception_injector, "inject_into_gamma")
            load_honey_tokens = getattr(deception_injector, "load_honey_tokens")
            tokens = await load_honey_tokens(self._session)
            if tokens:
                return inject_into_gamma(gamma, tokens)
        except (AttributeError, ImportError, OSError, RuntimeError, ValueError):
            pass
        return gamma

    async def _load_active_policies(self) -> list[SecurityPolicy]:
        """Load active policy set from persistent storage."""
        result = await db_execute(
            self._session,
            select(SecurityPolicy).where(col(SecurityPolicy.is_active) == true()),
        )
        return cast(list[SecurityPolicy], result.scalars().all())

    @staticmethod
    def _build_obligations(guardrails: Any) -> list[dict[str, Any]]:
        """Build required obligations consumed by theorem evaluation."""
        obligations: list[dict[str, Any]] = []

        for operation in sorted(guardrails.require_approval):
            obligations.append(
                {
                    "type": "approval_required",
                    "operation": operation,
                    "required": True,
                }
            )

        obligations.extend(
            [
                {"type": "mfa_required", "operation": "block_ip_temp", "required": True},
                {"type": "mfa_required", "operation": "revoke_token", "required": True},
                {"type": "mfa_required", "operation": "apply_policy", "required": True},
                {"type": "preview_confirm_required", "required": True},
            ]
        )

        return obligations

    @staticmethod
    def _grant_to_fact(grant: DelegationGrant) -> dict[str, Any]:
        """Normalize delegation grant row into canonical fact object."""
        return {
            "grant_id": grant.grant_id,
            "principal": grant.principal,
            "delegate": grant.delegate,
            "tenant_id": grant.tenant_id,
            "parent_grant_id": grant.parent_grant_id,
            "hop_index": grant.hop_index,
            "allowed_actions": sorted(grant.allowed_actions),
            "resource_scope": grant.resource_scope,
            "obligations": grant.obligations,
            "context_constraints": grant.context_constraints,
            "expires_at": grant.expires_at.isoformat(),
            "revoked": grant.revoked,
        }

    @staticmethod
    def _revocation_to_fact(revocation: DelegationRevocation) -> dict[str, Any]:
        """Normalize delegation revocation row into canonical fact object."""
        return {
            "revocation_id": revocation.revocation_id,
            "grant_id": revocation.grant_id,
            "tenant_id": revocation.tenant_id,
            "transitive": revocation.transitive,
            "revoked_at": revocation.revoked_at.isoformat(),
        }

    @staticmethod
    def _policy_to_fact(policy: SecurityPolicy) -> dict[str, Any]:
        """Normalize policy row into canonical fact object."""
        return {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "origin": policy.origin,
            "locked": policy.locked,
            "is_active": policy.is_active,
            "policy_json": policy.policy_json,
        }

    @staticmethod
    def _grant_predicates(grants: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "predicate": "grant_active",
                "args": {
                    "grant_id": record["grant_id"],
                    "delegate": record["delegate"],
                    "principal": record["principal"],
                    "tenant_id": record["tenant_id"],
                },
            }
            for record in grants
        ]

    @staticmethod
    def _revocation_predicates(revocations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "predicate": "grant_revoked",
                "args": {
                    "grant_id": record["grant_id"],
                    "tenant_id": record["tenant_id"],
                },
            }
            for record in revocations
        ]

    @staticmethod
    def _policy_predicates(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "predicate": "policy_active",
                "args": {
                    "policy_id": record["policy_id"],
                    "version": record["version"],
                },
            }
            for record in policies
        ]

    @staticmethod
    def _obligation_predicates(obligations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "predicate": "obligation",
                "args": record,
            }
            for record in obligations
        ]
