"""Distributed certificate consensus and transparency log for decision certificates.

This module implements a certificate transparency log and optional N-of-M co-signing
from independent SafetyNodes. When enabled, it enforces quorum-based verification
where multiple nodes must agree on admissibility decisions before they are finalized.

Architecture:
- TransparencyLog: Immutable append-only log of all certificates
- SafetyNode: External verification node with co-signing capability
- ConsensusConfig: Configuration for quorum thresholds and node registry
- Global Revocation: Distributed revocation when nodes disagree

In single-node mode (consensus disabled), only the transparency log is active.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from server.models.formal_security_schemas import (
    CoSignatureRecord,
    GlobalRevocationRecord,
    SafetyNodeRecord,
    TransparencyLogRecord,
)
from server.utils.db import commit as db_commit
from server.utils.db import execute as db_execute
from .formal_models import (
    AlphaContext,
    DecisionCertificate,
    GammaKnowledgeBase,
)


logger = logging.getLogger(__name__)

HTTP_TIMEOUT_SECONDS = 5.0
DEFAULT_QUORUM = 1
DEFAULT_TIMEOUT_MS = 5000
NODE_ID_PREFIX = "node_"
NODE_ID_LENGTH = 12
_CONSENSUS_CONFIG_CACHE: "ConsensusConfig | None" = None


def utc_now() -> datetime:
    """Return current UTC created_at as timezone-naive database value."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class SafetyNode:
    """External safety verification node for co-signing certificates."""

    node_id: str
    endpoint_url: str
    public_key_pem: str
    is_local: bool = False
    trust_score: float = 1.0
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CoSignature:
    """Co-signature from a safety node on a decision certificate."""

    node_id: str
    decision_id: str
    signature: str
    verified_at: datetime
    re_evaluation_result: str


@dataclass
class ConsensusConfig:
    """Configuration for distributed consensus verification."""

    enabled: bool = False
    quorum_threshold: int = DEFAULT_QUORUM
    nodes: list[SafetyNode] = field(default_factory=list)
    verification_timeout_ms: int = DEFAULT_TIMEOUT_MS


@dataclass
class ConsensusResult:
    """Result of consensus verification across safety nodes."""

    decision_id: str
    quorum_reached: bool
    signatures_collected: int
    required: int
    co_signatures: list[CoSignature]
    global_revocation: bool = False
    revocation_reason: str | None = None


@dataclass
class TransparencyLogEntry:
    """Entry in the certificate transparency log."""

    log_index: int
    decision_id: str
    certificate_hash: str
    alpha_hash: str
    gamma_hash: str
    result: str
    node_id: str
    created_at: datetime
    node_signatures: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class TransparencyLogVerification:
    """Result of transparency log integrity verification."""

    valid: bool
    checked_entries: int
    failure_reason: str | None = None
    failed_index: int | None = None


class _ConsensusConfigState:
    """Module-level singleton state for consensus configuration cache."""

    config: ConsensusConfig | None = None

    @classmethod
    def get(cls) -> ConsensusConfig | None:
        """Return the cached consensus configuration."""
        return cls.config

    @classmethod
    def set(cls, config: ConsensusConfig) -> None:
        """Store the cached consensus configuration."""
        cls.config = config
        globals()["_CONSENSUS_CONFIG_CACHE"] = config

    @classmethod
    def reset(cls) -> None:
        """Reset the cached consensus configuration."""
        cls.config = None
        globals()["_CONSENSUS_CONFIG_CACHE"] = None


def _load_consensus_config() -> ConsensusConfig:
    """Load consensus configuration from environment variables.

    Environment Variables:
        AGENTGATE_CONSENSUS_ENABLED: Enable distributed consensus
            (default: false).
        AGENTGATE_CONSENSUS_QUORUM: Minimum signatures required
            (default: 1).
        AGENTGATE_CONSENSUS_TIMEOUT_MS: HTTP timeout for co-signing
            (default: 5000).

    Returns:
        ConsensusConfig with loaded settings.
    """
    cached_config = globals().get("_CONSENSUS_CONFIG_CACHE")
    if cached_config is None:
        _ConsensusConfigState.config = None
    else:
        _ConsensusConfigState.set(cached_config)
        return cached_config

    cached_config = _ConsensusConfigState.get()
    if cached_config is not None:
        return cached_config

    enabled_str = os.getenv("AGENTGATE_CONSENSUS_ENABLED", "false").lower()
    enabled = enabled_str in ("true", "1", "yes", "on")

    quorum_str = os.getenv("AGENTGATE_CONSENSUS_QUORUM", str(DEFAULT_QUORUM))
    try:
        quorum = int(quorum_str)
    except ValueError:
        logger.warning(
            "Invalid AGENTGATE_CONSENSUS_QUORUM value: %s, using default %d",
            quorum_str,
            DEFAULT_QUORUM,
        )
        quorum = DEFAULT_QUORUM

    timeout_str = os.getenv(
        "AGENTGATE_CONSENSUS_TIMEOUT_MS",
        str(DEFAULT_TIMEOUT_MS),
    )
    try:
        timeout_ms = int(timeout_str)
    except ValueError:
        logger.warning(
            "Invalid AGENTGATE_CONSENSUS_TIMEOUT_MS value: %s, using default %d",
            timeout_str,
            DEFAULT_TIMEOUT_MS,
        )
        timeout_ms = DEFAULT_TIMEOUT_MS

    config = ConsensusConfig(
        enabled=enabled,
        quorum_threshold=quorum,
        nodes=[],
        verification_timeout_ms=timeout_ms,
    )
    _ConsensusConfigState.set(config)
    return config


async def append_to_transparency_log(
    session: AsyncSession,
    certificate: DecisionCertificate,
    *,
    alpha_hash: str,
    gamma_hash: str,
    node_id: str = "local",
) -> TransparencyLogEntry:
    """Append a decision certificate to the transparency log.

    Args:
        session: Database session
        certificate: Decision certificate to log
        alpha_hash: Hash of alpha context
        gamma_hash: Hash of gamma knowledge base
        node_id: Identifier of the node creating this entry

    Returns:
        TransparencyLogEntry dataclass with assigned log index
    """
    stmt = (
        select(TransparencyLogRecord).order_by(col(TransparencyLogRecord.log_index).desc()).limit(1)
    )
    result = await db_execute(session, stmt)
    last_entry = result.scalars().first()

    next_index = 0 if last_entry is None else last_entry.log_index + 1

    record = TransparencyLogRecord(
        log_index=next_index,
        decision_id=str(certificate.decision_id),
        certificate_hash=certificate.certificate_hash,
        alpha_hash=alpha_hash,
        gamma_hash=gamma_hash,
        result=certificate.result.value,
        node_id=node_id,
    )

    session.add(record)
    await db_commit(session)

    return TransparencyLogEntry(
        log_index=record.log_index,
        decision_id=record.decision_id,
        certificate_hash=record.certificate_hash,
        alpha_hash=record.alpha_hash,
        gamma_hash=record.gamma_hash,
        result=record.result,
        node_id=record.node_id,
        created_at=record.created_at,
        node_signatures=[],
    )


async def request_co_signature(
    node: SafetyNode,
    certificate: DecisionCertificate,
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
    *,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> CoSignature | None:
    """Request co-signature from an external safety node.

    Args:
        node: Safety node to request signature from
        certificate: Decision certificate to verify
        alpha: Action context
        gamma: Knowledge base context
        timeout_ms: HTTP request timeout in milliseconds

    Returns:
        CoSignature if successful, None on timeout or error
    """
    url = f"{node.endpoint_url.rstrip('/')}/security/safety-nodes/co-sign"
    timeout_seconds = timeout_ms / 1000.0

    payload = {
        "certificate": certificate.model_dump(mode="json"),
        "alpha": alpha.model_dump(mode="json"),
        "gamma": gamma.model_dump(mode="json"),
    }

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()

            data = response.json()
            return CoSignature(
                node_id=node.node_id,
                decision_id=str(certificate.decision_id),
                signature=data.get("signature", ""),
                verified_at=datetime.now(timezone.utc),
                re_evaluation_result=data.get("result", "INADMISSIBLE"),
            )

    except httpx.TimeoutException:
        logger.warning("Co-signature request to %s timed out after %dms", node.node_id, timeout_ms)
        return None

    except httpx.HTTPError as exc:
        logger.error("Co-signature request to %s failed: %s", node.node_id, exc)
        return None

    except (RuntimeError, TypeError, ValueError) as exc:
        logger.error("Unexpected error requesting co-signature from %s: %s", node.node_id, exc)
        return None


async def collect_quorum(
    session: AsyncSession,
    certificate: DecisionCertificate,
    alpha: AlphaContext,
    gamma: GammaKnowledgeBase,
    config: ConsensusConfig,
) -> ConsensusResult:
    """Collect co-signatures from safety nodes and verify quorum.

    Args:
        session: Database session
        certificate: Decision certificate to verify
        alpha: Action context
        gamma: Knowledge base context
        config: Consensus configuration with nodes and thresholds

    Returns:
        ConsensusResult with quorum status and collected signatures
    """
    non_local_nodes = [node for node in config.nodes if not node.is_local]

    if not non_local_nodes:
        return ConsensusResult(
            decision_id=str(certificate.decision_id),
            quorum_reached=True,
            signatures_collected=0,
            required=config.quorum_threshold,
            co_signatures=[],
        )

    tasks = [
        request_co_signature(
            node,
            certificate,
            alpha,
            gamma,
            timeout_ms=config.verification_timeout_ms,
        )
        for node in non_local_nodes
    ]

    results = await asyncio.gather(*tasks)
    signatures = [sig for sig in results if sig is not None]

    inadmissible_nodes = [sig for sig in signatures if sig.re_evaluation_result == "INADMISSIBLE"]

    global_revocation = False
    revocation_reason = None

    if inadmissible_nodes:
        global_revocation = True
        node_ids = ", ".join(sig.node_id for sig in inadmissible_nodes)
        revocation_reason = f"Certificate rejected by {len(inadmissible_nodes)} node(s): {node_ids}"

    for sig in signatures:
        record = CoSignatureRecord(
            cosig_id=f"cosig_{uuid.uuid4().hex[:16]}",
            node_id=sig.node_id,
            decision_id=sig.decision_id,
            signature=sig.signature,
            re_evaluation_result=sig.re_evaluation_result,
        )
        session.add(record)

    await db_commit(session)

    quorum_reached = len(signatures) >= config.quorum_threshold

    return ConsensusResult(
        decision_id=str(certificate.decision_id),
        quorum_reached=quorum_reached,
        signatures_collected=len(signatures),
        required=config.quorum_threshold,
        co_signatures=signatures,
        global_revocation=global_revocation,
        revocation_reason=revocation_reason,
    )


async def broadcast_global_revocation(
    session: AsyncSession,
    decision_id: str,
    reason: str,
    config: ConsensusConfig,
) -> dict[str, Any]:
    """Broadcast global revocation to all safety nodes.

    Args:
        session: Database session
        decision_id: ID of decision being revoked
        reason: Reason for revocation
        config: Consensus configuration with node registry

    Returns:
        Summary dict with revocation details
    """
    revoked_at = utc_now()
    record = GlobalRevocationRecord(
        revocation_id=f"rev_{uuid.uuid4().hex[:16]}",
        decision_id=decision_id,
        reason=reason,
        initiated_by_node_id="local",
        revoked_at=revoked_at,
    )
    session.add(record)
    await db_commit(session)

    notification_payload = {
        "decision_id": decision_id,
        "reason": reason,
        "revoked_at": revoked_at.isoformat(),
    }

    for node in config.nodes:
        if node.is_local:
            continue

        url = f"{node.endpoint_url.rstrip('/')}/security/safety-nodes/revocation"
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
                await client.post(url, json=notification_payload)
        except (httpx.HTTPError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("Failed to notify node %s of revocation: %s", node.node_id, exc)

    return {
        "decision_id": decision_id,
        "reason": reason,
        "revoked_at": revoked_at.isoformat(),
        "notified_nodes": len([n for n in config.nodes if not n.is_local]),
    }


async def verify_transparency_log(
    session: AsyncSession,
    *,
    start_index: int = 0,
    end_index: int | None = None,
) -> TransparencyLogVerification:
    """Verify integrity of transparency log entries.

    Args:
        session: Database session
        start_index: Starting log index for verification
        end_index: Ending log index (inclusive), or None for all entries

    Returns:
        TransparencyLogVerification with validation results
    """
    stmt = select(TransparencyLogRecord).where(col(TransparencyLogRecord.log_index) >= start_index)

    if end_index is not None:
        stmt = stmt.where(col(TransparencyLogRecord.log_index) <= end_index)

    stmt = stmt.order_by(col(TransparencyLogRecord.log_index))

    result = await db_execute(session, stmt)
    entries = result.scalars().all()

    if not entries:
        return TransparencyLogVerification(
            valid=True,
            checked_entries=0,
        )

    expected_index = start_index
    for entry in entries:
        if entry.log_index != expected_index:
            return TransparencyLogVerification(
                valid=False,
                checked_entries=expected_index - start_index,
                failure_reason=(
                    f"Index gap detected: expected {expected_index}, found {entry.log_index}"
                ),
                failed_index=expected_index,
            )

        if len(entry.certificate_hash) != 64:
            return TransparencyLogVerification(
                valid=False,
                checked_entries=expected_index - start_index + 1,
                failure_reason=f"Invalid certificate hash length at index {entry.log_index}",
                failed_index=entry.log_index,
            )

        expected_index += 1

    return TransparencyLogVerification(
        valid=True,
        checked_entries=len(entries),
    )


async def register_safety_node(
    session: AsyncSession,
    *,
    endpoint_url: str,
    public_key_pem: str,
    is_local: bool = False,
) -> SafetyNode:
    """Register a new safety node for consensus verification.

    Args:
        session: Database session
        endpoint_url: HTTP endpoint for co-signing requests
        public_key_pem: Public key in PEM format for signature verification
        is_local: Whether this is a local node (won't be contacted)

    Returns:
        SafetyNode dataclass with generated node_id
    """
    node_id = f"{NODE_ID_PREFIX}{uuid.uuid4().hex[:NODE_ID_LENGTH]}"

    record = SafetyNodeRecord(
        node_id=node_id,
        endpoint_url=endpoint_url,
        public_key_pem=public_key_pem,
        is_local=is_local,
        trust_score=1.0,
        registered_at=utc_now(),
    )

    session.add(record)
    await db_commit(session)

    return SafetyNode(
        node_id=record.node_id,
        endpoint_url=record.endpoint_url,
        public_key_pem=record.public_key_pem,
        is_local=record.is_local,
        trust_score=record.trust_score,
        registered_at=record.registered_at,
    )


async def remove_safety_node(session: AsyncSession, node_id: str) -> bool:
    """Remove a safety node from the registry.

    Args:
        session: Database session
        node_id: ID of node to remove

    Returns:
        True if node was found and deleted, False otherwise
    """
    stmt = select(SafetyNodeRecord).where(col(SafetyNodeRecord.node_id) == node_id)
    result = await db_execute(session, stmt)
    record = result.scalars().first()

    if record is None:
        return False

    await session.delete(record)
    await db_commit(session)
    return True


async def get_transparency_log(
    session: AsyncSession,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[TransparencyLogEntry]:
    """Retrieve transparency log entries with pagination.

    Args:
        session: Database session
        limit: Maximum number of entries to return
        offset: Number of entries to skip

    Returns:
        List of TransparencyLogEntry dataclasses
    """
    stmt = (
        select(TransparencyLogRecord)
        .order_by(desc(col(TransparencyLogRecord.log_index)))
        .limit(limit)
        .offset(offset)
    )

    result = await db_execute(session, stmt)
    records = result.scalars().all()

    return [
        TransparencyLogEntry(
            log_index=record.log_index,
            decision_id=record.decision_id,
            certificate_hash=record.certificate_hash,
            alpha_hash=record.alpha_hash,
            gamma_hash=record.gamma_hash,
            result=record.result,
            node_id=record.node_id,
            created_at=record.created_at,
            node_signatures=[],
        )
        for record in records
    ]


async def get_safety_nodes(session: AsyncSession) -> list[SafetyNode]:
    """Retrieve all registered safety nodes.

    Args:
        session: Database session

    Returns:
        List of SafetyNode dataclasses
    """
    stmt = select(SafetyNodeRecord).order_by(col(SafetyNodeRecord.registered_at))
    result = await db_execute(session, stmt)
    records = result.scalars().all()

    return [
        SafetyNode(
            node_id=record.node_id,
            endpoint_url=record.endpoint_url,
            public_key_pem=record.public_key_pem,
            is_local=record.is_local,
            trust_score=record.trust_score,
            registered_at=record.registered_at,
        )
        for record in records
    ]


async def get_global_revocations(session: AsyncSession) -> list[dict[str, Any]]:
    """Retrieve all global revocation records.

    Args:
        session: Database session

    Returns:
        List of revocation records as dictionaries
    """
    stmt = select(GlobalRevocationRecord).order_by(col(GlobalRevocationRecord.revoked_at).desc())
    result = await db_execute(session, stmt)
    records = result.scalars().all()

    return [
        {
            "revocation_id": record.revocation_id,
            "decision_id": record.decision_id,
            "reason": record.reason,
            "revoked_at": record.revoked_at.isoformat(),
            "initiated_by_node_id": record.initiated_by_node_id,
            "acknowledged_by": record.acknowledged_by,
        }
        for record in records
    ]


async def check_certificate_revoked(
    session: AsyncSession,
    decision_id: str,
) -> bool:
    """Check if a decision certificate has been globally revoked.

    Args:
        session: Database session
        decision_id: ID of decision to check

    Returns:
        True if certificate is revoked, False otherwise
    """
    stmt = select(GlobalRevocationRecord).where(
        col(GlobalRevocationRecord.decision_id) == decision_id
    )
    result = await db_execute(session, stmt)
    record = result.scalars().first()
    return record is not None
