"""Session-scoped PII token lifecycle service."""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_
from sqlalchemy import delete as sqla_delete
from sqlalchemy.sql.functions import count as sql_count
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from ea_agentgate.security.encryption import AESGCMEncryption, DecryptionError
from ea_agentgate.security.integrity import HMACIntegrity
from server.models import (
    AIValidationFailure,
    EncryptionKeyRecord,
    PIIAIConversationToken,
    PIIAuditEntry,
    PIIEventType,
    PIIHumanMapping,
    PIISession,
    User,
)
from server.utils.db import (
    commit as db_commit,
    execute as db_execute,
    flush as db_flush,
)

LOGGER = logging.getLogger(__name__)
TOKEN_PATTERN = re.compile(r"<[A-Z][A-Z0-9_]*_\d+>")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _derive_key_bytes(env_var: str, fallback_seed: str) -> bytes:
    """Derive a stable 256-bit key from env/input seed."""
    configured = os.getenv(env_var)
    if configured:
        candidate = configured.strip()
        if candidate.startswith("base64:"):
            try:
                decoded = base64.b64decode(candidate.split(":", 1)[1], validate=True)
                return hashlib.sha256(decoded).digest()
            except (ValueError, binascii.Error):
                LOGGER.warning("Invalid base64 value for %s; using hashed raw value", env_var)
        return hashlib.sha256(candidate.encode("utf-8")).digest()

    if os.getenv("AGENTGATE_ENV", "development").lower() == "production":
        LOGGER.warning("%s is not configured; using derived fallback seed", env_var)
    return hashlib.sha256(fallback_seed.encode("utf-8")).digest()


_ENCRYPTION_PROVIDER = AESGCMEncryption(
    _derive_key_bytes(
        "PII_VAULT_ENCRYPTION_KEY",
        os.getenv("SECRET_KEY", "agentgate-pii-fallback-encryption"),
    ),
)
_INTEGRITY_PROVIDER = HMACIntegrity(
    _derive_key_bytes(
        "PII_VAULT_INTEGRITY_KEY",
        os.getenv("SECRET_KEY", "agentgate-pii-fallback-integrity"),
    ),
)


class UnknownTokenError(Exception):
    """Raised when a response contains tokens not mapped in the scoped vault."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        super().__init__(f"Unknown tokens: {', '.join(tokens)}")


class TokenIntegrityError(Exception):
    """Raised when stored token data cannot be decrypted or integrity-verified."""

    def __init__(self, token: str, reason: str) -> None:
        self.token = token
        self.reason = reason
        super().__init__(f"Token resolution failed for {token}: {reason}")


@dataclass
class RedactionItem:
    """Single token mapping returned from redaction."""

    token: str
    pii_type: str
    score: float


@dataclass
class RedactionResult:
    """Redaction output payload."""

    redacted_text: str
    mappings: list[RedactionItem]
    pii_count: int


@dataclass
class RestorationItem:
    """Single token restoration status."""

    token: str
    pii_type: str
    restored: bool
    reason: str | None = None


@dataclass
class RestorationResult:
    """Restoration output payload."""

    restored_text: str
    restorations: list[RestorationItem]
    unknown_tokens: list[str]
    rehydrated: bool


def _normalize_pii_type(pii_type: str) -> str:
    normalized = re.sub(r"[^A-Z0-9]+", "_", pii_type.strip().upper())
    normalized = normalized.strip("_")
    return normalized or "PII"


def _normalized_value_hash(value: str) -> str:
    normalized = " ".join(value.strip().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def ensure_session_active(
    session: AsyncSession,
    session_id: str,
) -> PIISession:
    """Validate session existence and active status."""
    result = await db_execute(
        session,
        select(PIISession).where(PIISession.session_id == session_id),
    )
    pii_session = result.scalar_one_or_none()
    now = _utc_now()
    if (
        pii_session is None
        or not pii_session.is_active
        or (pii_session.expires_at is not None and pii_session.expires_at <= now)
    ):
        raise LookupError("Session not found or inactive")
    return pii_session


async def ensure_active_key_record(
    session: AsyncSession,
    current_user: User | None = None,
) -> EncryptionKeyRecord:
    """Ensure an active encryption key metadata record exists."""
    result = await db_execute(
        session,
        select(EncryptionKeyRecord).where(EncryptionKeyRecord.is_active),
    )
    active_keys = result.scalars().all()
    for key in active_keys:
        if key.key_id == _ENCRYPTION_PROVIDER.key_id:
            return key
        key.is_active = False
        key.rotated_at = _utc_now()
        session.add(key)

    key_record = EncryptionKeyRecord(
        key_id=_ENCRYPTION_PROVIDER.key_id,
        algorithm="AES-256-GCM",
        created_by=current_user.id if current_user and current_user.id else None,
        is_active=True,
    )
    session.add(key_record)
    await db_flush(session)
    return key_record


async def _get_or_create_human_mapping(
    session: AsyncSession,
    *,
    session_id: str,
    current_user: User,
    pii_type: str,
    original_value: str,
    expires_at: datetime | None,
) -> PIIHumanMapping:
    value_hash = _normalized_value_hash(original_value)
    stmt = select(PIIHumanMapping).where(
        PIIHumanMapping.session_id == session_id,
        PIIHumanMapping.normalized_value_hash == value_hash,
    )
    if current_user.id is not None:
        stmt = stmt.where(PIIHumanMapping.owner_user_id == current_user.id)
    else:
        stmt = stmt.where(PIIHumanMapping.owner_user_email == current_user.email)
    result = await db_execute(session, stmt)
    existing = result.scalar_one_or_none()
    if existing is not None:
        return existing

    key_record = await ensure_active_key_record(session, current_user=current_user)
    ciphertext = _ENCRYPTION_PROVIDER.encrypt(original_value)
    integrity_hash = _INTEGRITY_PROVIDER.sign(original_value)
    mapping = PIIHumanMapping(
        session_id=session_id,
        owner_user_id=current_user.id,
        owner_user_email=current_user.email,
        pii_type=pii_type,
        normalized_value_hash=value_hash,
        ciphertext=ciphertext,
        encryption_key_id=key_record.key_id,
        integrity_hash=integrity_hash,
        expires_at=expires_at,
    )
    session.add(mapping)
    await db_flush(session)
    return mapping


async def _next_token(
    session: AsyncSession,
    *,
    session_id: str,
    pii_type: str,
) -> str:
    count_result = await db_execute(
        session,
        select(sql_count(col(PIIAIConversationToken.id))).where(
            PIIAIConversationToken.session_id == session_id,
            PIIAIConversationToken.pii_type == pii_type,
        ),
    )
    next_index = int(count_result.scalar() or 0) + 1
    while True:
        candidate = f"<{pii_type}_{next_index}>"
        exists_result = await db_execute(
            session,
            select(PIIAIConversationToken).where(
                PIIAIConversationToken.session_id == session_id,
                PIIAIConversationToken.token == candidate,
            ),
        )
        if exists_result.scalar_one_or_none() is None:
            return candidate
        next_index += 1


async def _get_or_create_ai_token(
    session: AsyncSession,
    *,
    session_id: str,
    current_user: User,
    pii_type: str,
    human_mapping: PIIHumanMapping,
    expires_at: datetime | None,
) -> PIIAIConversationToken:
    if human_mapping.id is None:
        raise RuntimeError("PII human mapping ID missing after flush")
    mapping_id = human_mapping.id
    stmt = select(PIIAIConversationToken).where(
        PIIAIConversationToken.session_id == session_id,
        PIIAIConversationToken.human_mapping_id == mapping_id,
    )
    if current_user.id is not None:
        stmt = stmt.where(PIIAIConversationToken.owner_user_id == current_user.id)
    else:
        stmt = stmt.where(PIIAIConversationToken.owner_user_email == current_user.email)
    result = await db_execute(session, stmt)
    existing = result.scalar_one_or_none()
    if existing is not None:
        return existing

    token = await _next_token(session, session_id=session_id, pii_type=pii_type)
    token_row = PIIAIConversationToken(
        session_id=session_id,
        owner_user_id=current_user.id,
        owner_user_email=current_user.email,
        token=token,
        pii_type=pii_type,
        human_mapping_id=mapping_id,
        expires_at=expires_at,
    )
    session.add(token_row)
    await db_flush(session)
    return token_row


def _make_audit_entry(
    *,
    event_type: PIIEventType,
    current_user: User,
    session_id: str,
    token: str | None = None,
    pii_type: str | None = None,
    success: bool = True,
    error_message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> PIIAuditEntry:
    return PIIAuditEntry(
        event_id=str(uuid.uuid4()),
        event_type=event_type.value,
        user_id=str(current_user.id) if current_user.id is not None else current_user.email,
        session_id=session_id,
        placeholder=token,
        pii_type=pii_type,
        data_classification="confidential",
        success=success,
        error_message=error_message,
        encryption_key_id=_ENCRYPTION_PROVIDER.key_id,
        metadata_json=metadata,
    )


def _record_validation_failure(
    session: AsyncSession,
    *,
    current_user: User,
    session_id: str,
    failure_type: str,
    reason: str,
    payload: dict[str, Any] | None = None,
) -> None:
    failure = AIValidationFailure(
        failure_id=f"vf_{uuid.uuid4().hex[:24]}",
        related_session_id=session_id,
        owner_user_id=current_user.id,
        owner_user_email=current_user.email,
        failure_type=failure_type,
        reason=reason,
        payload=payload,
        status="open",
    )
    session.add(failure)


async def redact_text(
    session: AsyncSession,
    *,
    text: str,
    detections: list[dict[str, Any]],
    session_id: str,
    current_user: User,
    expires_at: datetime | None = None,
) -> RedactionResult:
    """Redact text into scoped synthetic tokens and persist two-table mappings."""
    pii_session = await ensure_session_active(session, session_id)

    redacted_text = text
    mappings: list[RedactionItem] = []

    for detection in sorted(detections, key=lambda item: item["start"], reverse=True):
        pii_type = _normalize_pii_type(str(detection["type"]))
        original_value = str(detection["value"])
        human_mapping = await _get_or_create_human_mapping(
            session,
            session_id=session_id,
            current_user=current_user,
            pii_type=pii_type,
            original_value=original_value,
            expires_at=expires_at,
        )
        token_mapping = await _get_or_create_ai_token(
            session,
            session_id=session_id,
            current_user=current_user,
            pii_type=pii_type,
            human_mapping=human_mapping,
            expires_at=expires_at,
        )

        redacted_text = (
            redacted_text[: detection["start"]]
            + token_mapping.token
            + redacted_text[detection["end"] :]
        )
        mappings.append(
            RedactionItem(
                token=token_mapping.token,
                pii_type=pii_type,
                score=float(detection.get("score", 0.0)),
            )
        )
        session.add(
            _make_audit_entry(
                event_type=PIIEventType.PII_STORE,
                current_user=current_user,
                session_id=session_id,
                token=token_mapping.token,
                pii_type=pii_type,
                metadata={"action": "redact"},
            )
        )

    pii_session.store_count += len(mappings)
    pii_session.last_activity_at = _utc_now()
    session.add(pii_session)

    return RedactionResult(
        redacted_text=redacted_text,
        mappings=mappings,
        pii_count=len(mappings),
    )


async def _resolve_plaintext(
    session: AsyncSession,
    *,
    token_row: PIIAIConversationToken,
    session_id: str,
    current_user: User,
) -> str:
    human_result = await db_execute(
        session,
        select(PIIHumanMapping).where(PIIHumanMapping.id == token_row.human_mapping_id),
    )
    human_mapping = human_result.scalar_one_or_none()
    if human_mapping is None:
        raise TokenIntegrityError(token_row.token, "Human mapping missing")

    try:
        plaintext = _ENCRYPTION_PROVIDER.decrypt(human_mapping.ciphertext)
    except DecryptionError as exc:
        raise TokenIntegrityError(token_row.token, f"Decryption failed: {exc}") from exc

    if not _INTEGRITY_PROVIDER.verify(plaintext, human_mapping.integrity_hash):
        raise TokenIntegrityError(token_row.token, "Integrity verification failed")

    now = _utc_now()
    token_row.access_count += 1
    token_row.last_accessed_at = now
    human_mapping.access_count += 1
    human_mapping.last_accessed_at = now
    session.add(token_row)
    session.add(human_mapping)
    session.add(
        _make_audit_entry(
            event_type=PIIEventType.PII_RETRIEVE,
            current_user=current_user,
            session_id=session_id,
            token=token_row.token,
            pii_type=token_row.pii_type,
            metadata={"action": "restore"},
        )
    )
    return plaintext


async def restore_text(
    session: AsyncSession,
    *,
    redacted_text: str,
    session_id: str,
    current_user: User,
    unknown_token_policy: str,
) -> RestorationResult:
    """Restore scoped tokens to original values."""
    pii_session = await ensure_session_active(session, session_id)
    unique_tokens = list(dict.fromkeys(TOKEN_PATTERN.findall(redacted_text)))
    if not unique_tokens:
        return RestorationResult(
            restored_text=redacted_text,
            restorations=[],
            unknown_tokens=[],
            rehydrated=False,
        )

    token_filters = [PIIAIConversationToken.token == token for token in unique_tokens]
    stmt = select(PIIAIConversationToken).where(PIIAIConversationToken.session_id == session_id)
    stmt = stmt.where(or_(*token_filters))
    if current_user.id is not None:
        stmt = stmt.where(PIIAIConversationToken.owner_user_id == current_user.id)
    else:
        stmt = stmt.where(PIIAIConversationToken.owner_user_email == current_user.email)
    token_result = await db_execute(session, stmt)
    rows = token_result.scalars().all()
    token_map = {row.token: row for row in rows}

    unknown_tokens = [token for token in unique_tokens if token not in token_map]
    if unknown_tokens and unknown_token_policy == "fail_closed":
        _record_validation_failure(
            session,
            current_user=current_user,
            session_id=session_id,
            failure_type="unknown_token",
            reason="Response contained tokens that are not mapped in scoped vault",
            payload={"unknown_tokens": unknown_tokens, "text": redacted_text},
        )
        session.add(
            _make_audit_entry(
                event_type=PIIEventType.PII_INTEGRITY_FAILURE,
                current_user=current_user,
                session_id=session_id,
                success=False,
                error_message="Unknown token encountered during restore",
                metadata={"unknown_tokens": unknown_tokens},
            )
        )
        raise UnknownTokenError(unknown_tokens)

    restored_text = redacted_text
    restorations: list[RestorationItem] = []
    for token in sorted(unique_tokens, key=len, reverse=True):
        token_row = token_map.get(token)
        if token_row is None:
            restorations.append(
                RestorationItem(
                    token=token,
                    pii_type="unknown",
                    restored=False,
                    reason="No scoped token mapping found",
                )
            )
            continue
        try:
            plaintext = await _resolve_plaintext(
                session,
                token_row=token_row,
                session_id=session_id,
                current_user=current_user,
            )
        except TokenIntegrityError as exc:
            _record_validation_failure(
                session,
                current_user=current_user,
                session_id=session_id,
                failure_type="token_integrity_error",
                reason=exc.reason,
                payload={"token": token},
            )
            session.add(
                _make_audit_entry(
                    event_type=PIIEventType.PII_INTEGRITY_FAILURE,
                    current_user=current_user,
                    session_id=session_id,
                    token=token,
                    pii_type=token_row.pii_type,
                    success=False,
                    error_message=exc.reason,
                )
            )
            raise

        restored_text = restored_text.replace(token, plaintext)
        restorations.append(
            RestorationItem(
                token=token,
                pii_type=token_row.pii_type,
                restored=True,
            )
        )

    pii_session.retrieve_count += sum(1 for item in restorations if item.restored)
    pii_session.last_activity_at = _utc_now()
    session.add(pii_session)

    return RestorationResult(
        restored_text=restored_text,
        restorations=restorations,
        unknown_tokens=unknown_tokens,
        rehydrated=any(item.restored for item in restorations),
    )


async def clear_session_mappings(
    session: AsyncSession,
    *,
    session_id: str,
) -> dict[str, int]:
    """Delete human and AI mapping rows for a given session."""
    ai_count_result = await db_execute(
        session,
        select(sql_count(col(PIIAIConversationToken.id))).where(
            PIIAIConversationToken.session_id == session_id
        ),
    )
    ai_count = int(ai_count_result.scalar() or 0)
    human_count_result = await db_execute(
        session,
        select(sql_count(col(PIIHumanMapping.id))).where(PIIHumanMapping.session_id == session_id),
    )
    human_count = int(human_count_result.scalar() or 0)

    await db_execute(
        session,
        sqla_delete(PIIAIConversationToken).where(
            col(PIIAIConversationToken.session_id) == session_id
        ),
    )
    await db_execute(
        session,
        sqla_delete(PIIHumanMapping).where(col(PIIHumanMapping.session_id) == session_id),
    )
    return {"ai_tokens_deleted": ai_count, "human_mappings_deleted": human_count}


async def get_vault_stats(
    session: AsyncSession,
    *,
    current_user: User,
    scoped: bool,
) -> dict[str, Any]:
    """Return vault statistics with optional user scoping."""
    human_stmt = select(PIIHumanMapping)
    token_stmt = select(PIIAIConversationToken)
    if scoped and current_user.role != "admin":
        if current_user.id is not None:
            human_stmt = human_stmt.where(PIIHumanMapping.owner_user_id == current_user.id)
            token_stmt = token_stmt.where(PIIAIConversationToken.owner_user_id == current_user.id)
        else:
            human_stmt = human_stmt.where(PIIHumanMapping.owner_user_email == current_user.email)
            token_stmt = token_stmt.where(
                PIIAIConversationToken.owner_user_email == current_user.email
            )

    human_result = await db_execute(session, human_stmt)
    token_result = await db_execute(session, token_stmt)
    human_rows = human_result.scalars().all()
    token_rows = token_result.scalars().all()

    by_type: dict[str, int] = {}
    total_accesses = 0
    for row in human_rows:
        by_type[row.pii_type] = by_type.get(row.pii_type, 0) + 1
        total_accesses += row.access_count

    return {
        "total_items": len(human_rows),
        "total_tokens": len(token_rows),
        "by_type": by_type,
        "total_accesses": total_accesses,
        "encryption_key_id": _ENCRYPTION_PROVIDER.key_id,
    }


async def persist(session: AsyncSession) -> None:
    """Commit staged PII lifecycle mutations."""
    await db_commit(session)
