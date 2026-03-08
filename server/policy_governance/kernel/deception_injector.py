"""Semantic honey-token injection and deception trigger detection.

Manages canary tools and resources injected into the Gamma knowledge base.
When an agent targets a canary resource, the system logs a deception trigger
and applies graduated trust degradation to the agent's delegation chain.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from sqlalchemy import false
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from server.models.formal_security_schemas import (
    DeceptionTriggerRecord,
    DelegationGrant,
    HoneyTokenRecord,
)
from server.utils.db import commit as db_commit
from server.utils.db import execute as db_execute
from .delegation_lineage import revoke_delegation_grant
from .formal_models import (
    AlphaContext,
    GammaKnowledgeBase,
    sha256_hex,
)

logger = logging.getLogger(__name__)

HONEY_RESOURCE_PREFIX = "honey://"
DEFAULT_TRAP_SALT = "agentgate-honey-trap-salt"
SEVERITY_LEVELS = {
    "FLAG_ONLY": 1,
    "DOWNGRADE_TRUST": 2,
    "SUSPEND_GRANTS": 3,
}


class HoneyTokenType(str, Enum):
    """Types of honey tokens that can be deployed."""

    TOOL = "TOOL"
    RESOURCE = "RESOURCE"
    CREDENTIAL = "CREDENTIAL"
    DATA_STORE = "DATA_STORE"


class TrustDegradation(str, Enum):
    """Graduated trust degradation levels applied on deception trigger."""

    FLAG_ONLY = "flag_only"
    DOWNGRADE_TRUST = "downgrade_trust"
    SUSPEND_GRANTS = "suspend_grants"


@dataclass
class HoneyToken:
    """Represents a honey token canary in the deception framework.

    Attributes:
        token_id: Unique identifier for this honey token.
        name: Human-readable name for the token.
        token_type: Type of honey token (tool, resource, credential, data_store).
        description: Purpose and context of this honey token.
        resource_pattern: Pattern to match resources (e.g., "honey://secrets/*").
        trap_hash: SHA-256 hash of token_id + salt for detection without exposure.
        is_active: Whether this token is currently active.
    """

    token_id: str
    name: str
    token_type: HoneyTokenType
    description: str
    resource_pattern: str
    trap_hash: str
    is_active: bool = True


@dataclass
class DeceptionTrigger:
    """Records when an agent triggers a honey token detection.

    Attributes:
        trigger_id: Unique identifier for this trigger event.
        token_id: ID of the honey token that was triggered.
        principal: Identity of the agent that triggered the token.
        action: Action attempted on the honey token.
        resource: Resource path that matched the honey token pattern.
        delegation_chain_ids: List of delegation grant IDs in the chain.
        severity: Severity level (1-3) of the trigger.
        trust_action: Description of trust action taken.
        evidence_chain_id: Optional ID of evidence chain record.
        created_at: Timestamp of trigger detection.
    """

    trigger_id: str
    token_id: str
    principal: str
    action: str
    resource: str
    delegation_chain_ids: list[str]
    severity: int
    trust_action: str
    evidence_chain_id: str | None
    created_at: datetime


def _get_trap_salt() -> str:
    """Get trap salt from environment or return default.

    Returns:
        Salt value for trap hash computation.
    """
    return os.getenv("AGENTGATE_HONEY_SALT", DEFAULT_TRAP_SALT)


def _compute_trap_hash(token_id: str, salt: str = "") -> str:
    """Compute SHA-256 hash of token_id + salt for secure detection.

    Args:
        token_id: The honey token identifier.
        salt: Salt value for hash computation. Defaults to env var salt.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    actual_salt = salt or _get_trap_salt()
    return sha256_hex(f"{token_id}:{actual_salt}")


async def load_honey_tokens(session: AsyncSession) -> list[HoneyToken]:
    """Load all active honey tokens from the database.

    Args:
        session: Active database session.

    Returns:
        List of active HoneyToken instances.
    """
    stmt = select(HoneyTokenRecord).where(col(HoneyTokenRecord.is_active).is_(True))
    result = await db_execute(session, stmt)
    records = result.scalars().all()

    tokens = []
    for record in records:
        token = HoneyToken(
            token_id=record.token_id,
            name=record.name,
            token_type=HoneyTokenType(record.token_type),
            description=record.description or "",
            resource_pattern=record.resource_pattern,
            trap_hash=record.trap_hash,
            is_active=record.is_active,
        )
        tokens.append(token)

    logger.info("Loaded %d active honey tokens from database", len(tokens))
    return tokens


async def create_honey_token(
    session: AsyncSession,
    *,
    name: str,
    token_type: HoneyTokenType,
    resource_pattern: str,
    description: str = "",
    created_by: str = "system",
) -> HoneyToken:
    """Create and persist a new honey token to the database.

    Args:
        session: Active database session.
        name: Human-readable name for the token.
        token_type: Type of honey token to create.
        resource_pattern: Pattern to match resources against.
        description: Optional description of the token purpose.
        created_by: Principal that created this token.

    Returns:
        Newly created HoneyToken instance.
    """
    token_id = f"ht_{uuid4().hex}"
    trap_hash = _compute_trap_hash(token_id)

    record = HoneyTokenRecord(
        token_id=token_id,
        name=name,
        token_type=token_type.value,
        description=description,
        resource_pattern=resource_pattern,
        trap_hash=trap_hash,
        is_active=True,
        created_by=created_by,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )

    session.add(record)
    await db_commit(session)

    logger.info(
        "Created honey token '%s' (type=%s, pattern=%s)",
        name,
        token_type.value,
        resource_pattern,
    )

    return HoneyToken(
        token_id=token_id,
        name=name,
        token_type=token_type,
        description=description,
        resource_pattern=resource_pattern,
        trap_hash=trap_hash,
        is_active=True,
    )


async def deactivate_honey_token(session: AsyncSession, token_id: str) -> bool:
    """Deactivate a honey token by setting is_active to False.

    Args:
        session: Active database session.
        token_id: ID of the token to deactivate.

    Returns:
        True if token was deactivated, False if not found.
    """
    stmt = select(HoneyTokenRecord).where(col(HoneyTokenRecord.token_id) == token_id)
    result = await db_execute(session, stmt)
    record = result.scalar_one_or_none()

    if not record:
        logger.warning("Honey token %s not found for deactivation", token_id)
        return False

    record.is_active = False
    await db_commit(session)

    logger.info("Deactivated honey token %s", token_id)
    return True


def inject_into_gamma(gamma: GammaKnowledgeBase, tokens: list[HoneyToken]) -> GammaKnowledgeBase:
    """Inject honey tokens as fake grants/facts into Gamma knowledge base.

    Creates a new GammaKnowledgeBase instance with injected honey token facts.
    Does not mutate the original gamma instance.

    Args:
        gamma: Original gamma knowledge base.
        tokens: List of honey tokens to inject.

    Returns:
        New GammaKnowledgeBase with injected honey token facts.
    """
    if not tokens:
        return gamma

    new_facts = list(gamma.facts)
    new_grants = list(gamma.active_grants)

    for token in tokens:
        if not token.is_active:
            continue

        honey_resource = f"{HONEY_RESOURCE_PREFIX}{token.resource_pattern}"
        fact = {
            "predicate": "grant_active",
            "args": [
                token.token_id,
                gamma.principal,
                honey_resource,
            ],
        }
        new_facts.append(fact)

        grant = {
            "grant_id": token.token_id,
            "delegate": gamma.principal,
            "resource_scope": token.resource_pattern,
            "allowed_actions": ["*"],
        }
        new_grants.append(grant)

        logger.debug(
            "Injected honey token %s into gamma for %s",
            token.name,
            gamma.principal,
        )

    new_gamma = GammaKnowledgeBase(
        principal=gamma.principal,
        tenant_id=gamma.tenant_id,
        facts=new_facts,
        active_grants=new_grants,
        active_revocations=list(gamma.active_revocations),
        policies=list(gamma.policies),
        obligations=list(gamma.obligations),
        environment=dict(gamma.environment),
    )
    new_gamma.compute_gamma_hash()
    return new_gamma


def check_action_against_tokens(
    _action: str, resource: str, tokens: list[HoneyToken]
) -> HoneyToken | None:
    """Check if an action on a resource matches any honey token pattern.

    Matches using three strategies:
    1. Exact match: resource == token.resource_pattern
    2. Prefix match: resource starts with HONEY_RESOURCE_PREFIX
    3. Glob match: fnmatch pattern matching

    Args:
        _action: Action being attempted (currently unused in matching).
        resource: Resource path being accessed.
        tokens: List of active honey tokens.

    Returns:
        Matching HoneyToken if detected, None otherwise.
    """
    for token in tokens:
        if not token.is_active:
            continue

        if resource == token.resource_pattern:
            logger.warning(
                "Honey token triggered (exact): %s (pattern=%s, resource=%s)",
                token.name,
                token.resource_pattern,
                resource,
            )
            return token

        if resource.startswith(HONEY_RESOURCE_PREFIX):
            if fnmatch.fnmatch(resource, f"{HONEY_RESOURCE_PREFIX}*"):
                logger.warning(
                    "Honey token triggered (prefix): %s (pattern=%s, resource=%s)",
                    token.name,
                    token.resource_pattern,
                    resource,
                )
                return token

        if fnmatch.fnmatch(resource, token.resource_pattern):
            logger.warning(
                "Honey token triggered (glob): %s (pattern=%s, resource=%s)",
                token.name,
                token.resource_pattern,
                resource,
            )
            return token

    return None


def determine_severity(token: HoneyToken, alpha: AlphaContext) -> int:
    """Determine severity level based on token type and action context.

    Args:
        token: The honey token that was triggered.
        alpha: Request context containing action and resource details.

    Returns:
        Severity level (1-3).
    """
    if token.token_type == HoneyTokenType.CREDENTIAL:
        return 3

    if token.token_type == HoneyTokenType.DATA_STORE and "delete" in alpha.action.lower():
        return 3

    if token.token_type == HoneyTokenType.TOOL:
        return 2

    if token.token_type == HoneyTokenType.RESOURCE:
        return 1

    return 2


async def record_deception_trigger(
    session: AsyncSession,
    *,
    token: HoneyToken,
    alpha: AlphaContext,
    delegation_chain_ids: list[str] | None = None,
    trust_action: TrustDegradation = TrustDegradation.FLAG_ONLY,
) -> DeceptionTrigger:
    """Record a deception trigger event in the database.

    Args:
        session: Active database session.
        token: The honey token that was triggered.
        alpha: Request context for the trigger.
        delegation_chain_ids: Optional list of delegation grant IDs.
        trust_action: Trust degradation action to apply.

    Returns:
        DeceptionTrigger instance with trigger details.
    """
    trigger_id = f"dt_{uuid4().hex}"
    delegation_chain = delegation_chain_ids or []
    severity = SEVERITY_LEVELS.get(trust_action.name, 1)

    trigger_record = DeceptionTriggerRecord(
        trigger_id=trigger_id,
        token_id=token.token_id,
        principal=alpha.principal,
        action=alpha.action,
        resource=alpha.resource,
        delegation_chain_ids=delegation_chain,
        severity=severity,
        trust_action=trust_action.value,
        evidence_chain_id=None,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    session.add(trigger_record)
    await db_commit(session)

    logger.warning(
        "Recorded deception trigger %s for principal %s on token %s (severity=%s)",
        trigger_id,
        alpha.principal,
        token.name,
        severity,
    )

    return DeceptionTrigger(
        trigger_id=trigger_id,
        token_id=token.token_id,
        principal=alpha.principal,
        action=alpha.action,
        resource=alpha.resource,
        delegation_chain_ids=delegation_chain,
        severity=severity,
        trust_action=trust_action.value,
        evidence_chain_id=None,
        created_at=trigger_record.created_at,
    )


async def apply_trust_degradation(
    session: AsyncSession, trigger: DeceptionTrigger, level: TrustDegradation
) -> None:
    """Apply graduated trust degradation based on trigger severity.

    Three graduated response levels:
    1. FLAG_ONLY: Log only, no action beyond trigger record.
    2. DOWNGRADE_TRUST: Mark grants with trust_degraded flag in obligations.
    3. SUSPEND_GRANTS: Revoke all active grants for principal.

    Args:
        session: Active database session.
        trigger: The deception trigger event.
        level: Degradation level to apply.
    """
    if level == TrustDegradation.FLAG_ONLY:
        logger.info(
            "Trust degradation FLAG_ONLY for trigger %s: principal=%s",
            trigger.trigger_id,
            trigger.principal,
        )
        return

    if level == TrustDegradation.DOWNGRADE_TRUST:
        stmt = select(DelegationGrant).where(
            col(DelegationGrant.delegate) == trigger.principal,
            col(DelegationGrant.revoked) == false(),
        )
        result = await db_execute(session, stmt)
        grants = result.scalars().all()

        affected = 0
        for grant in grants:
            obligations = dict(grant.obligations or {})
            obligations["trust_degraded"] = True
            obligations["degraded_at"] = datetime.now(timezone.utc).isoformat()
            obligations["trigger_id"] = trigger.trigger_id
            grant.obligations = obligations
            session.add(grant)
            affected += 1

        await db_commit(session)

        logger.warning(
            "Trust degradation DOWNGRADE_TRUST for trigger %s: principal=%s, "
            "grants_affected=%s",
            trigger.trigger_id,
            trigger.principal,
            affected,
        )
        return

    if level == TrustDegradation.SUSPEND_GRANTS:
        stmt = select(DelegationGrant).where(
            col(DelegationGrant.delegate) == trigger.principal,
            col(DelegationGrant.revoked) == false(),
        )
        result = await db_execute(session, stmt)
        grants = result.scalars().all()

        revoked = 0
        for grant in grants:
            try:
                await revoke_delegation_grant(
                    session,
                    grant_id=grant.grant_id,
                    tenant_id=grant.tenant_id,
                    reason="Deception trigger: honey-token accessed",
                    revoked_by_user_id=None,
                    transitive=True,
                )
                revoked += 1
            except (RuntimeError, TypeError, ValueError) as error:
                logger.error(
                    "Failed to revoke grant %s: %s",
                    grant.grant_id,
                    error,
                    exc_info=True,
                )

        logger.critical(
            "Trust degradation SUSPEND_GRANTS for trigger %s: principal=%s, "
            "grants_revoked=%s",
            trigger.trigger_id,
            trigger.principal,
            revoked,
        )
        return


async def get_triggers(
    session: AsyncSession, *, principal: str | None = None
) -> list[DeceptionTrigger]:
    """Retrieve deception trigger records from the database.

    Args:
        session: Active database session.
        principal: Optional filter by principal identity.

    Returns:
        List of DeceptionTrigger instances.
    """
    stmt = select(DeceptionTriggerRecord)
    if principal:
        stmt = stmt.where(col(DeceptionTriggerRecord.principal) == principal)

    result = await db_execute(session, stmt)
    records = result.scalars().all()

    triggers = []
    for record in records:
        trigger = DeceptionTrigger(
            trigger_id=record.trigger_id,
            token_id=record.token_id,
            principal=record.principal,
            action=record.action,
            resource=record.resource,
            delegation_chain_ids=record.delegation_chain_ids or [],
            severity=record.severity,
            trust_action=record.trust_action,
            evidence_chain_id=record.evidence_chain_id,
            created_at=record.created_at,
        )
        triggers.append(trigger)

    return triggers


async def list_honey_tokens(session: AsyncSession) -> list[HoneyToken]:
    """List all active honey tokens from the database.

    Args:
        session: Active database session.

    Returns:
        List of active HoneyToken instances.
    """
    return await load_honey_tokens(session)
