"""PII Vault management routes for SOC 2 / HIPAA compliance.

Implements:
- C-03: Async database patterns for improved concurrency and performance
- C-04: Offloads CPU-bound NLP tasks (Presidio+spaCy) to threadpool
- O-01: Lazy initialization of NLP model to avoid blocking startup

@author Erick | Founding Principal AI Architect
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, StrictFloat, StrictStr
from sqlmodel import col, select
from sqlalchemy import desc, true
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import emit_audit_event
from ..metrics import (
    record_pii_redact_call,
    record_pii_restore_call,
    record_pii_restore_denied,
    record_pii_restore_integrity_fail,
)
from ..models import (
    User,
    PIIAuditEntry,
    PIISession,
    PIISessionCreate,
    PIISessionRead,
    UserPIIPermissions,
    UserPIIPermissionCreate,
    UserPIIPermissionRead,
    EncryptionKeyRecord,
    EncryptionKeyRecordRead,
    PIIPermission,
    PIIEventType,
    get_session,
)
from ..utils.db import (
    execute as db_execute,
    commit as db_commit,
    refresh as db_refresh,
    get as db_get,
    delete as db_delete,
)
from ..policy_governance.kernel import pii_token_service
from ..policy_governance.kernel.runtime_settings import (
    get_scoped_reads_enabled,
    get_unknown_token_policy,
)
from .auth import get_current_user, require_admin
from .pii_nlp import _MultilingualAnalyzerManager, SUPPORTED_ENTITIES, _analyze_text
from .pii_utils import require_pii_permission

router = APIRouter(prefix="/pii", tags=["pii"])
PII_TEXT_MAX_CHARS = int(os.getenv("PII_TEXT_MAX_CHARS", "50000"))


def _is_admin(user: User) -> bool:
    return user.role == "admin"


# =============================================================================
# PII Session Management
# =============================================================================


@router.get("/sessions", response_model=list[PIISessionRead])
async def list_pii_sessions(
    *,
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    user_id: str | None = None,
    is_active: bool | None = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    """
    List PII sessions.

    Required permission: pii:audit_read
    """
    scoped_reads_enabled = await get_scoped_reads_enabled(session)
    query = select(PIISession).order_by(desc(col(PIISession.created_at)))

    if scoped_reads_enabled and not _is_admin(current_user):
        if user_id and user_id != current_user.email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scoped reads enabled: session list is restricted to current user",
            )
        query = query.where(PIISession.user_id == current_user.email)
    elif user_id:
        query = query.where(PIISession.user_id == user_id)
    if is_active is not None:
        query = query.where(PIISession.is_active == is_active)

    query = query.offset(offset).limit(limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@router.post("/sessions", response_model=PIISessionRead)
async def create_pii_session(
    data: PIISessionCreate,
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_STORE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Create a new PII session.

    Required permission: pii:store
    """
    requested_user_id = data.user_id
    if not _is_admin(current_user) and requested_user_id != current_user.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session owner must match authenticated user",
        )

    pii_session = PIISession(
        session_id=data.session_id,
        user_id=requested_user_id,
        agent_id=data.agent_id,
        purpose=data.purpose,
        expires_at=data.expires_at,
        tenant_id=current_user.tenant_id or "default",
        principal_id=current_user.principal_id,
        channel_id=data.channel_id,
        conversation_id=data.conversation_id,
        obligation_profile=data.obligation_profile,
        authorized_viewers=data.authorized_viewers or [requested_user_id],
    )
    session.add(pii_session)
    await db_commit(session)
    await db_refresh(session, pii_session)

    # Audit log
    session.add(
        PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type=PIIEventType.PII_STORE.value,
            user_id=requested_user_id,
            session_id=data.session_id,
            success=True,
            metadata_json={
                "action": "session_created",
                "purpose": data.purpose,
            },
        )
    )
    await db_commit(session)

    return pii_session


@router.delete("/sessions/{session_id}")
async def clear_pii_session(
    session_id: str,
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_CLEAR_SESSION))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Clear/deactivate a PII session.

    Required permission: pii:clear_session
    """
    result = await db_execute(
        session, select(PIISession).where(PIISession.session_id == session_id)
    )
    pii_session = result.scalars().first()

    if not pii_session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )
    if not _is_admin(current_user) and pii_session.user_id != current_user.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session access denied",
        )
    if not _is_admin(current_user) and pii_session.authorized_viewers:
        if current_user.email not in set(pii_session.authorized_viewers):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not an authorized viewer for this scoped PII session",
            )

    pii_session.is_active = False
    session.add(pii_session)
    purge_counts = await pii_token_service.clear_session_mappings(
        session,
        session_id=session_id,
    )

    # Audit log
    session.add(
        PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type=PIIEventType.PII_CLEAR_SESSION.value,
            user_id=current_user.email,
            session_id=session_id,
            success=True,
            metadata_json={
                "cleared_by": current_user.email,
                **purge_counts,
            },
        )
    )
    await db_commit(session)

    return {
        "message": "Session cleared",
        "session_id": session_id,
        **purge_counts,
    }


# =============================================================================
# Permission Management
# =============================================================================


@router.get("/permissions", response_model=list[UserPIIPermissionRead])
async def list_user_permissions(
    _current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    user_id: int | None = None,
):
    """
    List PII permissions.

    Required: Admin role
    """
    query = select(UserPIIPermissions)

    if user_id:
        query = query.where(UserPIIPermissions.user_id == user_id)

    result = await db_execute(session, query)
    return result.scalars().all()


@router.get("/permissions/available")
async def list_available_permissions(
    _current_user: Annotated[User, Depends(get_current_user)],
):
    """List all available PII permissions."""
    return {"permissions": [{"value": p.value, "name": p.name} for p in PIIPermission]}


@router.post("/permissions", response_model=UserPIIPermissionRead)
async def grant_permission(
    data: UserPIIPermissionCreate,
    current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Grant a PII permission to a user.

    Required: Admin role
    """
    # Verify permission is valid
    try:
        PIIPermission(data.permission)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission: {data.permission}",
        ) from exc

    # Check if already granted
    result = await db_execute(
        session,
        select(UserPIIPermissions).where(
            UserPIIPermissions.user_id == data.user_id,
            UserPIIPermissions.permission == data.permission,
        ),
    )
    existing = result.scalars().first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Permission already granted",
        )

    permission = UserPIIPermissions(
        user_id=data.user_id,
        permission=data.permission,
        granted_by=current_user.id,
        reason=data.reason,
        expires_at=data.expires_at,
    )
    session.add(permission)

    # Audit log
    await emit_audit_event(
        session,
        event_type="pii_permission_grant",
        actor=current_user.email,
        result="success",
        details={
            "target_user_id": data.user_id,
            "permission": data.permission,
            "reason": data.reason,
        },
    )
    await db_commit(session)
    await db_refresh(session, permission)

    return permission


@router.delete("/permissions/{permission_id}")
async def revoke_permission(
    permission_id: int,
    current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Revoke a PII permission.

    Required: Admin role
    """
    permission = await db_get(session, UserPIIPermissions, permission_id)

    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found",
        )

    # Audit log
    await emit_audit_event(
        session,
        event_type="pii_permission_revoke",
        actor=current_user.email,
        result="success",
        details={
            "target_user_id": permission.user_id,
            "permission": permission.permission,
        },
    )

    await db_delete(session, permission)
    await db_commit(session)

    return {"message": "Permission revoked"}


# =============================================================================
# Encryption Key Management
# =============================================================================


@router.get("/keys", response_model=list[EncryptionKeyRecordRead])
async def list_encryption_keys(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.KEY_VIEW))],
    session: Annotated[AsyncSession, Depends(get_session)],
    is_active: bool | None = None,
):
    """
    List encryption key metadata (not the keys themselves).

    Required permission: key:view
    """
    query = select(EncryptionKeyRecord).order_by(desc(col(EncryptionKeyRecord.created_at)))

    if is_active is not None:
        query = query.where(EncryptionKeyRecord.is_active == is_active)

    result = await db_execute(session, query)
    return result.scalars().all()


@router.post("/keys/rotate")
async def rotate_encryption_key(
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.KEY_ROTATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Trigger encryption key rotation.

    This endpoint records the rotation event. The actual key rotation
    should be handled by the security module.

    Required permission: key:rotate
    """
    # Deactivate current active key
    active_query = select(EncryptionKeyRecord).filter(col(EncryptionKeyRecord.is_active) == true())
    result = await db_execute(session, active_query)
    active_keys = result.scalars().all()

    for key in active_keys:
        key.is_active = False
        key.rotated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        session.add(key)

    # Create new key record
    new_key = EncryptionKeyRecord(
        key_id=str(uuid.uuid4()),
        algorithm="AES-256-GCM",
        created_by=current_user.id,
    )
    session.add(new_key)

    # Audit log
    session.add(
        PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type=PIIEventType.KEY_ROTATION.value,
            user_id=current_user.email,
            success=True,
            metadata_json={
                "new_key_id": new_key.key_id,
                "rotated_keys": [k.key_id for k in active_keys],
            },
        )
    )
    await db_commit(session)
    await db_refresh(session, new_key)

    return {
        "message": "Key rotation initiated",
        "new_key_id": new_key.key_id,
        "rotated_keys_count": len(active_keys),
    }


# =============================================================================
# PII Detection & Redaction API (Presidio NLP Engine)
# =============================================================================


class PIIDetectRequest(BaseModel):
    """Typed request model for PII detection."""

    text: StrictStr = Field(min_length=1, max_length=PII_TEXT_MAX_CHARS)
    score_threshold: StrictFloat = Field(default=0.4, ge=0.0, le=1.0)
    language: StrictStr | None = Field(
        default=None,
        min_length=2,
        max_length=16,
        pattern=r"^[a-z]{2}(?:-[A-Z]{2})?$",
    )


class PIIRedactRequest(BaseModel):
    """Typed request model for PII redaction."""

    session_id: StrictStr = Field(min_length=1, max_length=255)
    text: StrictStr = Field(min_length=1, max_length=PII_TEXT_MAX_CHARS)
    score_threshold: StrictFloat = Field(default=0.4, ge=0.0, le=1.0)
    language: StrictStr | None = Field(
        default=None,
        min_length=2,
        max_length=16,
        pattern=r"^[a-z]{2}(?:-[A-Z]{2})?$",
    )


class PIIRestoreRequest(BaseModel):
    """Typed request model for PII restoration."""

    session_id: StrictStr = Field(min_length=1, max_length=255)
    text: StrictStr = Field(min_length=1, max_length=PII_TEXT_MAX_CHARS)


async def _ensure_session_for_request(
    session: AsyncSession,
    *,
    session_id: str,
    current_user: User,
    request: Request | None = None,
) -> PIISession:
    """Ensure a session exists and is active for redaction/restoration."""
    try:
        pii_session = await pii_token_service.ensure_session_active(session, session_id)
    except LookupError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or inactive",
        ) from None
    if not _is_admin(current_user) and pii_session.user_id != current_user.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session access denied",
        )
    if (
        pii_session.principal_id
        and current_user.principal_id
        and pii_session.principal_id != current_user.principal_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Principal mismatch for scoped PII session",
        )
    if request is not None:
        channel_id = request.headers.get("x-channel-id")
        conversation_id = request.headers.get("x-conversation-id")
        agent_id = request.headers.get("x-agent-id")
        if pii_session.channel_id and channel_id and pii_session.channel_id != channel_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Channel binding mismatch for scoped PII session",
            )
        if (
            pii_session.conversation_id
            and conversation_id
            and pii_session.conversation_id != conversation_id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Conversation binding mismatch for scoped PII session",
            )
        if pii_session.agent_id and agent_id and pii_session.agent_id != agent_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Agent binding mismatch for scoped PII session",
            )
    return pii_session


@router.post("/detect")
async def detect_pii_in_text(
    data: PIIDetectRequest,
    _current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Detect PII in text using multilingual NLP-based analysis (Microsoft Presidio + spaCy).

    Runs a multilingual model (xx_ent_wiki_sm) for 89+ language entity detection,
    plus the default English engine for regex-based recognizers (SSN, email, credit card, etc.).
    Optionally auto-detects input language and runs a language-specific model if available.

    Request body:
        {"text": "Hello, my name is John Smith", "score_threshold": 0.4, "language": "en"}
    Returns: List of detected PII with types, positions, confidence scores, and language metadata.
    """
    text = data.text
    score_threshold = data.score_threshold
    language = data.language

    # Run multilingual NLP analysis in threadpool (C-04: offload CPU-bound work)
    results, meta = await _analyze_text(text, score_threshold=score_threshold, language=language)

    detections = []
    for r in results:
        detections.append(
            {
                "type": r.entity_type,
                "value": text[r.start : r.end],
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 2),
            }
        )

    return {
        "original_text": text,
        "detections": detections,
        "pii_found": len(detections) > 0,
        "engine": "presidio+spacy",
        "model": "multilingual",
        "nlp_initialized": _MultilingualAnalyzerManager.is_initialized(),
        "detected_language": meta.get("detected_language"),
        "effective_language": meta.get("effective_language"),
        "engines_used": meta.get("engines_used", []),
    }


@router.post("/redact")
async def redact_pii_in_text(
    data: PIIRedactRequest,
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_STORE))],
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
):
    """
    Detect and redact PII using NLP, storing mappings in secure vault.

    Uses Microsoft Presidio with spaCy NLP model for detection.
    Each PII item is replaced with a unique token and stored in an
    encrypted vault for authorized retrieval.

    Request body: {
        "session_id": "session_abc123",
        "text": "Hello, my name is John Smith",
        "score_threshold": 0.4
    }
    Returns: Redacted text with tokens and mapping info.
    Requires PII_STORE permission and session ownership scope for non-admin users.
    """
    text = data.text
    score_threshold = data.score_threshold
    language = data.language
    pii_session = await _ensure_session_for_request(
        session,
        session_id=data.session_id,
        current_user=current_user,
        request=request,
    )
    record_pii_redact_call()

    # Run multilingual NLP analysis in threadpool (C-04: offload CPU-bound work)
    results, _meta = await _analyze_text(
        text,
        score_threshold=score_threshold,
        language=language,
    )

    # Build detections from Presidio results
    detections = [
        {
            "type": r.entity_type,
            "value": text[r.start : r.end],
            "start": r.start,
            "end": r.end,
            "score": r.score,
        }
        for r in results
    ]
    result = await pii_token_service.redact_text(
        session,
        text=text,
        detections=detections,
        session_id=pii_session.session_id,
        current_user=current_user,
        expires_at=pii_session.expires_at,
    )
    await pii_token_service.persist(session)

    return {
        "original_text": text,
        "redacted_text": result.redacted_text,
        "mappings": [
            {"token": item.token, "type": item.pii_type, "score": round(item.score, 2)}
            for item in result.mappings
        ],
        "pii_count": result.pii_count,
        "engine": "presidio+spacy",
        "session_id": pii_session.session_id,
        "rehydration_mode": "scoped_backend_restore",
        "scoped": True,
    }


@router.post("/restore")
async def restore_pii_in_text(
    data: PIIRestoreRequest,
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_RETRIEVE))],
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
):
    """
    Restore original PII values from redacted text.

    Request body: {"session_id": "session_abc123", "text": "Hello, <PERSON_1>"}
    Returns: Restored text with original values.

    Requires PII_RETRIEVE permission. All access is logged for compliance.
    """
    record_pii_restore_call()
    try:
        await _ensure_session_for_request(
            session,
            session_id=data.session_id,
            current_user=current_user,
            request=request,
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            record_pii_restore_denied()
        raise
    unknown_token_policy = await get_unknown_token_policy(session)

    try:
        restore_result = await pii_token_service.restore_text(
            session,
            redacted_text=data.text,
            session_id=data.session_id,
            current_user=current_user,
            unknown_token_policy=unknown_token_policy,
        )
    except pii_token_service.UnknownTokenError as exc:
        await pii_token_service.persist(session)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "unknown_token",
                "message": "Restore failed because response includes unmapped token(s)",
                "unknown_tokens": exc.tokens,
            },
        ) from exc
    except pii_token_service.TokenIntegrityError as exc:
        record_pii_restore_integrity_fail()
        await pii_token_service.persist(session)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "token_integrity_failure",
                "message": exc.reason,
                "token": exc.token,
            },
        ) from exc

    await pii_token_service.persist(session)

    return {
        "redacted_text": data.text,
        "restored_text": restore_result.restored_text,
        "restorations": [
            {
                "token": item.token,
                "type": item.pii_type,
                "restored": item.restored,
                "reason": item.reason,
            }
            for item in restore_result.restorations
        ],
        "unknown_tokens": restore_result.unknown_tokens,
        "rehydrated": restore_result.rehydrated,
        "session_id": data.session_id,
        "rehydration_mode": "scoped_backend_restore",
        "scoped": True,
    }


@router.get("/vault/stats")
async def get_vault_stats(
    current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Get statistics about the PII vault.

    Returns count of stored items, types, and access patterns.
    """
    stats = await pii_token_service.get_vault_stats(
        session,
        current_user=current_user,
        scoped=True,
    )

    return {
        **stats,
        "engine": "presidio+spacy",
        "supported_entities": SUPPORTED_ENTITIES,
        "multilingual_status": _MultilingualAnalyzerManager.get_status(),
    }


@router.get("/nlp/status")
async def get_nlp_status(
    _current_user: Annotated[User, Depends(require_pii_permission(PIIPermission.PII_AUDIT_READ))],
):
    """
    Diagnostic endpoint for the multilingual NLP pipeline.

    Returns information about loaded engines, configured languages,
    auto-detection status, and any initialization errors.
    Requires PII_AUDIT_READ permission.
    """
    return _MultilingualAnalyzerManager.get_status()
