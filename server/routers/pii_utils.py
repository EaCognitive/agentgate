"""PII Utility functions and dependencies for AgentGate.

Contains shared permission checkers and dependencies used across PII modules.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.metrics import record_pii_restore_denied
from ..models import (
    User,
    UserPIIPermissions,
    PIIPermission,
    get_session,
)
from ..utils.db import (
    execute as db_execute,
)
from .auth import get_current_user


async def check_pii_permission(
    user: User,
    permission: PIIPermission,
    db_session: AsyncSession,
) -> bool:
    """Check if user has a specific PII permission."""
    # Admins have all permissions
    if user.role == "admin":
        return True

    # Check explicit permission grant
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    result = await db_execute(
        db_session,
        select(UserPIIPermissions).where(
            UserPIIPermissions.user_id == user.id,
            UserPIIPermissions.permission == permission.value,
        ),
    )
    perm = result.scalars().first()

    if perm is None:
        if permission == PIIPermission.PII_RETRIEVE:
            record_pii_restore_denied()
        return False

    # Check expiration
    # Strip timezone info for safe comparison with naive datetime
    if perm.expires_at:
        expires = perm.expires_at
        if expires.tzinfo is not None:
            expires = expires.replace(tzinfo=None)
        if expires < now:
            if permission == PIIPermission.PII_RETRIEVE:
                record_pii_restore_denied()
            return False

    return True


def require_pii_permission(permission: PIIPermission):
    """Dependency to require a PII permission."""

    async def checker(
        current_user: Annotated[User, Depends(get_current_user)],
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> User:
        """Verify the current user holds the required PII permission."""
        if not await check_pii_permission(current_user, permission, session):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission {permission.value} required",
            )
        return current_user

    return checker
