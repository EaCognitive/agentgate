"""Device Authorization Flow for MCP and CLI authentication.

Implements RFC 8628 Device Authorization Grant for scenarios where
the client cannot open a browser directly (e.g., CLI tools, MCP servers).

Flow:
1. Client calls POST /api/auth/device/code to get device_code + user_code
2. Browser opens dashboard login with device code
3. User logs in normally, dashboard calls /authorize endpoint
4. Client polls POST /api/auth/device/token until authorized
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, SQLModel, Field

from ..audit import emit_audit_event
from ..models import User, get_session
from ..utils.db import execute as db_execute, commit as db_commit
from .auth_helpers import complete_login
from .auth import get_current_user

router = APIRouter(prefix="/auth/device", tags=["device-auth"])

# In-memory store for device codes (use Redis in production)
_device_codes: dict[str, Any] = {}

# Configuration
DEVICE_CODE_EXPIRE_SECONDS = int(os.getenv("DEVICE_CODE_EXPIRE_SECONDS", "300"))
POLLING_INTERVAL_SECONDS = int(os.getenv("DEVICE_POLLING_INTERVAL", "5"))


def _get_dashboard_url() -> str:
    """Get the dashboard URL for device authorization."""
    return os.getenv("AGENTGATE_DASHBOARD_URL", "http://localhost:3000")


def _generate_user_code() -> str:
    """Generate a user-friendly 8-character code (e.g., ABCD-1234)."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Excludes ambiguous chars
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"{part1}-{part2}"


class DeviceCodeRequest(SQLModel):
    """Request to initiate device authorization."""

    client_id: str = Field(default="mcp-client", max_length=64)
    scope: str = Field(default="full_access", max_length=256)


class DeviceCodeResponse(SQLModel):
    """Response containing device and user codes."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
    message: str


@router.post("/code", response_model=DeviceCodeResponse)
async def request_device_code(
    request: DeviceCodeRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DeviceCodeResponse:
    """Request a device code for authorization.

    The client should open verification_uri_complete in a browser,
    then poll the /token endpoint until authorization is complete.
    """
    device_code = secrets.token_urlsafe(32)
    user_code = _generate_user_code()
    dashboard_url = _get_dashboard_url()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=DEVICE_CODE_EXPIRE_SECONDS)

    _device_codes[device_code] = {
        "user_code": user_code,
        "client_id": request.client_id,
        "scope": request.scope,
        "expires_at": expires_at,
        "authorized": False,
        "user_id": None,
        "denied": False,
    }

    # Index by user_code for web UI lookup
    _device_codes[f"user:{user_code}"] = device_code

    await emit_audit_event(
        session,
        event_type="device_code_requested",
        actor="anonymous",
        result="success",
        details={"client_id": request.client_id, "user_code": user_code},
    )
    await db_commit(session)

    # Dashboard login URL with device code parameter
    verification_uri = f"{dashboard_url}/login"
    verification_uri_complete = f"{dashboard_url}/login?device_code={user_code}"

    return DeviceCodeResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        expires_in=DEVICE_CODE_EXPIRE_SECONDS,
        interval=POLLING_INTERVAL_SECONDS,
        message=f"Open browser to authorize. Code: {user_code}",
    )


class DeviceTokenRequest(SQLModel):
    """Request to exchange device code for tokens."""

    device_code: str
    grant_type: str = Field(default="urn:ietf:params:oauth:grant-type:device_code")


@router.post("/token")
async def poll_device_token(
    request: DeviceTokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Poll for device authorization status.

    Returns tokens if authorized, or an error indicating the current status.
    Client should poll at the interval specified in the device code response.
    """
    device_data = _device_codes.get(request.device_code)

    if not device_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_grant", "error_description": "Invalid device code"},
        )

    now = datetime.now(timezone.utc)
    if device_data["expires_at"] < now:
        # Clean up expired code
        user_code = device_data["user_code"]
        _device_codes.pop(request.device_code, None)
        _device_codes.pop(f"user:{user_code}", None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "expired_token", "error_description": "Device code expired"},
        )

    if device_data["denied"]:
        user_code = device_data["user_code"]
        _device_codes.pop(request.device_code, None)
        _device_codes.pop(f"user:{user_code}", None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "access_denied", "error_description": "User denied authorization"},
        )

    if not device_data["authorized"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "authorization_pending",
                "error_description": "Waiting for user authorization",
            },
        )

    # Authorization complete - issue tokens
    user_id = device_data["user_id"]
    result = await db_execute(session, select(User).where(User.id == user_id))
    user_record = result.scalar_one_or_none()

    if not user_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_grant", "error_description": "User not found"},
        )

    # Complete login and get tokens
    login_result = await complete_login(
        user=user_record,
        session=session,
        user_agent="MCP Device Authorization",
        ip_address=None,
    )

    # Clean up used device code
    user_code = device_data["user_code"]
    _device_codes.pop(request.device_code, None)
    _device_codes.pop(f"user:{user_code}", None)

    return {
        "access_token": login_result.access_token,
        "refresh_token": login_result.refresh_token,
        "token_type": "bearer",
        "expires_in": login_result.expires_in,
        "user": {
            "id": user_record.id,
            "email": user_record.email,
            "name": user_record.name,
            "role": user_record.role,
        },
    }


class AuthorizeDeviceRequest(SQLModel):
    """Request from dashboard to authorize a device."""

    user_code: str


@router.post("/authorize")
async def authorize_device(
    request: AuthorizeDeviceRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """Authorize a device code (called from dashboard after user login).

    This endpoint is called by the dashboard when a user logs in
    with a device_code parameter in the URL.
    """
    # Get device code from user code
    device_code = _device_codes.get(f"user:{request.user_code}")
    if not device_code or not isinstance(device_code, str):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired device code",
        )

    device_data = _device_codes.get(device_code)
    if not device_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device code not found",
        )

    now = datetime.now(timezone.utc)
    if device_data["expires_at"] < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code expired",
        )

    # Mark as authorized
    device_data["authorized"] = True
    device_data["user_id"] = current_user.id

    await emit_audit_event(
        session,
        event_type="device_authorized",
        actor=current_user.email,
        result="success",
        details={"user_code": request.user_code, "client_id": device_data["client_id"]},
    )
    await db_commit(session)

    return {"status": "authorized", "message": "Device authorized successfully"}


@router.post("/deny")
async def deny_device(
    request: AuthorizeDeviceRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """Deny a device authorization request."""
    device_code = _device_codes.get(f"user:{request.user_code}")
    if not device_code or not isinstance(device_code, str):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid or expired device code",
        )

    device_data = _device_codes.get(device_code)
    if not device_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device code not found",
        )

    device_data["denied"] = True

    await emit_audit_event(
        session,
        event_type="device_denied",
        actor=current_user.email,
        result="success",
        details={"user_code": request.user_code},
    )
    await db_commit(session)

    return {"status": "denied", "message": "Device authorization denied"}


@router.get("/status/{user_code}")
async def get_device_status(user_code: str) -> dict[str, Any]:
    """Check the status of a device authorization (for dashboard UI)."""
    device_code = _device_codes.get(f"user:{user_code}")
    if not device_code or not isinstance(device_code, str):
        return {"valid": False, "message": "Invalid or expired code"}

    device_data = _device_codes.get(device_code)
    if not device_data:
        return {"valid": False, "message": "Device code not found"}

    now = datetime.now(timezone.utc)
    if device_data["expires_at"] < now:
        return {"valid": False, "message": "Code expired"}

    remaining = int((device_data["expires_at"] - now).total_seconds())

    return {
        "valid": True,
        "client_id": device_data["client_id"],
        "scope": device_data["scope"],
        "expires_in": remaining,
        "authorized": device_data["authorized"],
        "denied": device_data["denied"],
    }
