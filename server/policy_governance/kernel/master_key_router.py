"""FastAPI router endpoints for Master Key management.

Provides REST API for master key operations including:
- Status checking
- Key verification
- Bypass token generation
- Key file management
"""

from __future__ import annotations

import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select

from server.audit import emit_audit_event
from server.models import get_session
from server.policy_governance.kernel.master_key import (
    PROTECTED_OPERATIONS,
    MasterKeyFile,
    MasterKeyRecord,
    hash_master_key,
    verify_master_key,
    _BYPASS_TOKENS,
)
from server.utils.db import commit as db_commit, execute as db_execute


router = APIRouter(prefix="/security/master-key", tags=["master-key"])


# =============================================================================
# Request/Response Models
# =============================================================================


class MasterKeyVerification(SQLModel):
    """Request to verify master key for a protected operation."""

    master_key: str = Field(min_length=32, max_length=128)
    operation: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)


class BypassTokenRequest(SQLModel):
    """Request to generate a time-limited bypass token."""

    master_key: str = Field(min_length=32, max_length=128)
    operations: list[str]
    ttl_seconds: int = Field(default=300, ge=60, le=3600)


class BypassTokenResponse(SQLModel):
    """Response with bypass token for automation."""

    token: str
    expires_at: datetime
    allowed_operations: list[str]
    message: str


class KeyFileSetupRequest(SQLModel):
    """Request to generate a new master key file."""

    passphrase: str = Field(min_length=16, max_length=128)
    passphrase_confirm: str = Field(min_length=16, max_length=128)


class KeyFileSetupResponse(SQLModel):
    """Response after generating master key file."""

    success: bool
    key_file_path: str
    key_prefix: str
    fingerprint: str
    backup_codes: list[str]
    critical_warnings: list[str]


class KeyFileUnlockRequest(SQLModel):
    """Request to unlock the master key for an operation."""

    passphrase: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)


# =============================================================================
# Status and Verification Endpoints
# =============================================================================


@router.get("/status")
async def get_master_key_status(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Check if master key is configured."""
    result = await db_execute(session, select(MasterKeyRecord).limit(1))
    record = result.scalar_one_or_none()

    if not record:
        return {
            "configured": False,
            "message": "Master key not configured. Complete setup to generate.",
        }

    return {
        "configured": True,
        "key_prefix": record.key_prefix,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
        "rotation_count": record.rotation_count,
        "passkey_recovery_enabled": record.passkey_recovery_enabled,
        "recovery_email_set": record.recovery_email is not None,
    }


@router.post("/verify")
async def verify_key_for_operation(
    verification: MasterKeyVerification,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Verify master key before performing a protected operation.

    This endpoint should be called before ANY protected operation.
    It returns a one-time verification token valid for 60 seconds.
    """
    if verification.operation not in PROTECTED_OPERATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown protected operation: {verification.operation}",
        )

    is_valid, error = await verify_master_key(verification.master_key, session)
    if not is_valid:
        await emit_audit_event(
            session,
            event_type="master_key_verification_failed",
            actor="system",
            result="failed",
            details={"operation": verification.operation, "error": error},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error,
        )

    # Generate one-time verification token
    verification_token = secrets.token_urlsafe(32)
    expires_at = time.time() + 60

    _BYPASS_TOKENS[verification_token] = {
        "operations": [verification.operation],
        "expires_at": expires_at,
        "reason": verification.reason,
    }

    await emit_audit_event(
        session,
        event_type="master_key_verified",
        actor="admin",
        result="success",
        details={
            "operation": verification.operation,
            "reason": verification.reason,
        },
    )
    await db_commit(session)

    return {
        "verified": True,
        "verification_token": verification_token,
        "expires_in_seconds": 60,
        "operation": verification.operation,
        "warning": "This token allows ONE execution of the protected operation.",
    }


@router.post("/generate-bypass-token", response_model=BypassTokenResponse)
async def generate_bypass_token(
    request: BypassTokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> BypassTokenResponse:
    """Generate a time-limited bypass token for automation.

    Use this for CI/CD or automation that needs to perform protected
    operations without interactive master key entry.

    The token is strictly time-limited and operation-scoped.
    """
    # Validate all operations
    invalid_ops = [op for op in request.operations if op not in PROTECTED_OPERATIONS]
    if invalid_ops:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown operations: {invalid_ops}",
        )

    # Verify master key
    is_valid, error = await verify_master_key(request.master_key, session)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error,
        )

    # Generate bypass token
    token = secrets.token_urlsafe(48)
    expires_at_ts = time.time() + request.ttl_seconds
    expires_at = datetime.fromtimestamp(expires_at_ts, tz=timezone.utc)

    _BYPASS_TOKENS[token] = {
        "operations": request.operations,
        "expires_at": expires_at_ts,
    }

    await emit_audit_event(
        session,
        event_type="bypass_token_generated",
        actor="admin",
        result="success",
        details={
            "operations": request.operations,
            "ttl_seconds": request.ttl_seconds,
        },
    )
    await db_commit(session)

    return BypassTokenResponse(
        token=token,
        expires_at=expires_at,
        allowed_operations=request.operations,
        message="Store securely. This token allows protected operations without master key.",
    )


@router.get("/protected-operations")
async def list_protected_operations() -> dict:
    """List all operations that require master key authorization."""
    return {
        "protected_operations": sorted(PROTECTED_OPERATIONS),
        "description": (
            "These operations ALWAYS require Master Security Key verification. "
            "This includes destructive database operations, security configuration "
            "changes, and bulk data exports. Even admin users and AI agents "
            "cannot bypass this requirement."
        ),
    }


# =============================================================================
# Key File Endpoints
# =============================================================================


@router.get("/key-file/status")
async def get_key_file_status() -> dict:
    """Check if master key file exists and get its metadata."""
    key_file = MasterKeyFile()

    if not key_file.exists():
        return {
            "exists": False,
            "file_path": str(key_file.file_path),
            "message": "Master key file not found. Run /key-file/generate to create.",
        }

    info = key_file.get_info() or {}
    return {
        "exists": True,
        "file_path": info.get("file_path", str(key_file.file_path)),
        "version": info.get("version"),
        "key_prefix": info.get("key_prefix"),
        "created_at": info.get("created_at"),
        "fingerprint": info.get("fingerprint"),
        "message": "Master key file found. Use passphrase to unlock for operations.",
    }


@router.post("/key-file/generate", response_model=KeyFileSetupResponse)
async def generate_key_file(
    request: KeyFileSetupRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> KeyFileSetupResponse:
    """Generate a new encrypted master key file.

    IMPORTANT: This can only be done ONCE. The backup codes are shown ONLY ONCE.
    Store them securely - they cannot be recovered.

    The passphrase must be at least 16 characters and is used to encrypt the
    key file with AES-256-GCM.
    """
    # Validate passphrase confirmation
    if request.passphrase != request.passphrase_confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passphrases do not match",
        )

    key_file = MasterKeyFile()

    if key_file.exists():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Master key file already exists at {key_file.file_path}. "
                "Delete it manually if you need to regenerate."
            ),
        )

    try:
        master_key, backup_codes = key_file.generate_and_save(request.passphrase)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cannot write key file: {exc}",
        ) from exc

    # Store hash in database for verification
    key_hash = hash_master_key(master_key)
    record = MasterKeyRecord(
        key_hash=key_hash,
        key_prefix=master_key[:16],
        backup_codes_hash=hashlib.sha512("|".join(backup_codes).encode()).hexdigest(),
    )
    session.add(record)
    await db_commit(session)

    await emit_audit_event(
        session,
        event_type="master_key_file_generated",
        actor="system",
        result="success",
        details={"key_prefix": master_key[:16], "file_path": str(key_file.file_path)},
    )
    await db_commit(session)

    return KeyFileSetupResponse(
        success=True,
        key_file_path=str(key_file.file_path),
        key_prefix=master_key[:16],
        fingerprint=hashlib.sha256(master_key.encode()).hexdigest()[:16],
        backup_codes=backup_codes,
        critical_warnings=[
            "STORE THESE BACKUP CODES SECURELY - THEY WILL NOT BE SHOWN AGAIN!",
            "The master key file is encrypted with your passphrase.",
            "Without the passphrase OR backup codes, protected operations CANNOT be performed.",
            "Consider storing a backup of the key file in a secure offline location.",
            f"Key file location: {key_file.file_path}",
        ],
    )


@router.post("/key-file/unlock")
async def unlock_key_file_for_operation(
    request: KeyFileUnlockRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Unlock the master key file to authorize a protected operation.

    This decrypts the key file using the passphrase and generates a
    one-time verification token valid for 60 seconds.
    """
    if request.operation not in PROTECTED_OPERATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown protected operation: {request.operation}",
        )

    key_file = MasterKeyFile()

    if not key_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Master key file not found at {key_file.file_path}",
        )

    try:
        master_key = key_file.load_and_decrypt(request.passphrase)
    except ValueError as exc:
        await emit_audit_event(
            session,
            event_type="master_key_unlock_failed",
            actor="system",
            result="failed",
            details={"operation": request.operation, "error": str(exc)},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    # Verify against database hash
    is_valid, error = await verify_master_key(master_key, session)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error,
        )

    # Generate one-time verification token
    verification_token = secrets.token_urlsafe(32)
    expires_at = time.time() + 60

    _BYPASS_TOKENS[verification_token] = {
        "operations": [request.operation],
        "expires_at": expires_at,
        "reason": request.reason,
    }

    await emit_audit_event(
        session,
        event_type="master_key_file_unlocked",
        actor="admin",
        result="success",
        details={"operation": request.operation, "reason": request.reason},
    )
    await db_commit(session)

    return {
        "unlocked": True,
        "verification_token": verification_token,
        "expires_in_seconds": 60,
        "operation": request.operation,
        "warning": "This token allows ONE execution of the protected operation.",
    }


__all__ = [
    "router",
    "MasterKeyVerification",
    "BypassTokenRequest",
    "BypassTokenResponse",
    "KeyFileSetupRequest",
    "KeyFileSetupResponse",
    "KeyFileUnlockRequest",
]
