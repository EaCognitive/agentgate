"""MFA (Multi-Factor Authentication) routes.

Implements TOTP-based two-factor authentication endpoints including:
- Enable/disable 2FA
- Verify 2FA codes
- Backup code regeneration
- MFA status checking
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .auth_utils import verify_password
from .auth import get_current_user
from ..audit import emit_audit_event
from ..models import (
    User,
    get_session,
)
from ..utils.mfa import (
    generate_totp_secret,
    generate_qr_code,
    verify_totp_code,
    generate_backup_codes,
    hash_backup_code,
)
from ..utils.db import (
    commit as db_commit,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class Verify2FARequest(BaseModel):
    """Request body for 2FA verification."""

    code: str = Field(min_length=1, max_length=64)


class PasswordConfirmationRequest(BaseModel):
    """Request body for password-confirmed MFA actions."""

    password: str = Field(min_length=1, max_length=512)


@router.get("/mfa/status")
async def get_mfa_status(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Get MFA status for current user."""
    backup_codes_remaining = len(current_user.backup_codes or [])
    return {
        "enabled": current_user.totp_enabled,
        "method": "totp" if current_user.totp_enabled else None,
        "last_verified": None,
        "backup_codes_remaining": backup_codes_remaining,
    }


@router.post("/enable-2fa")
async def enable_2fa(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Enable 2FA for the current user.

    Generates TOTP secret and QR code.
    Returns secret and backup codes (shown only once).

    Returns:
        Dictionary containing:
        - secret: TOTP secret (for manual entry)
        - qr_code: Base64-encoded QR code image
        - backup_codes: List of backup codes (save these securely)
        - message: Instructions for next steps
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled",
        )

    # Check if MFA setup was already initiated (but not verified)
    if current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup already initiated. Please verify or disable first.",
        )

    # Generate TOTP secret
    secret = generate_totp_secret()
    qr_code = generate_qr_code(current_user.email, secret)

    # Generate backup codes
    backup_codes_plain = generate_backup_codes(count=8)
    backup_codes_hashed = [hash_backup_code(code) for code in backup_codes_plain]

    # Store in database (not enabled yet - requires verification)
    current_user.totp_secret = secret
    current_user.backup_codes = backup_codes_hashed
    session.add(current_user)
    await db_commit(session)

    # Audit log
    await emit_audit_event(
        session,
        event_type="2fa_init",
        actor=current_user.email,
        result="success",
    )
    await db_commit(session)

    # Return secret and codes (only time they're shown)
    return {
        "secret": secret,
        "qr_code": qr_code,
        "backup_codes": backup_codes_plain,
        "message": "Scan QR code with Google Authenticator, then verify to enable 2FA",
    }


@router.post("/verify-2fa")
async def verify_and_enable_2fa(
    body: Verify2FARequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Verify TOTP code and enable 2FA.

    Must be called after enable-2fa to activate 2FA.

    Args:
        code: 6-digit TOTP code from authenticator app

    Returns:
        Dictionary with status and success message
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled",
        )

    if current_user.totp_secret is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not initialized. Call /auth/enable-2fa first",
        )

    # Verify code
    if not verify_totp_code(current_user.totp_secret, body.code):
        # Audit failed verification
        await emit_audit_event(
            session,
            event_type="2fa_verify",
            actor=current_user.email,
            result="failed",
            details={"reason": "invalid_code"},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    # Enable 2FA
    current_user.totp_enabled = True
    session.add(current_user)
    await db_commit(session)

    # Audit log
    await emit_audit_event(
        session,
        event_type="2fa_enabled",
        actor=current_user.email,
        result="success",
    )
    await db_commit(session)

    return {"status": "enabled", "message": "2FA enabled successfully"}


@router.post("/disable-2fa")
async def disable_2fa(
    body: PasswordConfirmationRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Disable 2FA (requires password confirmation).

    Args:
        password: User's password for verification

    Returns:
        Dictionary with status and success message
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled",
        )

    # Verify password
    if not await verify_password(body.password, current_user.hashed_password):
        # Audit failed attempt
        await emit_audit_event(
            session,
            event_type="2fa_disable",
            actor=current_user.email,
            result="failed",
            details={"reason": "incorrect_password"},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )

    # Disable 2FA
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    session.add(current_user)
    await db_commit(session)

    # Audit log
    await emit_audit_event(
        session,
        event_type="2fa_disabled",
        actor=current_user.email,
        result="success",
    )
    await db_commit(session)

    return {"status": "disabled", "message": "2FA disabled successfully"}


@router.post("/regenerate-backup-codes")
async def regenerate_backup_codes(
    body: PasswordConfirmationRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Regenerate backup codes (requires password).

    Args:
        password: User's password for verification

    Returns:
        Dictionary containing:
        - backup_codes: List of new backup codes (save these securely)
        - message: Warning to save codes securely
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled",
        )

    # Verify password
    if not await verify_password(body.password, current_user.hashed_password):
        # Audit failed attempt
        await emit_audit_event(
            session,
            event_type="backup_codes_regenerate",
            actor=current_user.email,
            result="failed",
            details={"reason": "incorrect_password"},
        )
        await db_commit(session)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )

    # Generate new backup codes
    backup_codes_plain = generate_backup_codes(count=8)
    backup_codes_hashed = [hash_backup_code(code) for code in backup_codes_plain]

    current_user.backup_codes = backup_codes_hashed
    session.add(current_user)
    await db_commit(session)

    # Audit log
    await emit_audit_event(
        session,
        event_type="backup_codes_regenerated",
        actor=current_user.email,
        result="success",
    )
    await db_commit(session)

    return {
        "backup_codes": backup_codes_plain,
        "message": "Save these codes securely. They will not be shown again.",
    }
