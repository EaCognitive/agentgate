"""User management routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, SQLModel, Field, col

from ..models import User, UserCreate, UserRead, Permission, get_session
from ..security.identity import normalize_role, validate_role
from ..utils.db import execute as db_execute, commit as db_commit, refresh as db_refresh
from .auth import get_password_hash, require_permission

router = APIRouter(prefix="/users", tags=["users"])


class UserCreateRequest(UserCreate):
    """Request model for user creation with role assignment."""

    role: str = Field(default="viewer", max_length=50)


class UserUpdateRequest(SQLModel):
    """Request model for updating user fields including email, name, role, and status."""

    email: str | None = None
    name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


@router.get("", response_model=list[UserRead])
async def list_users(
    current_user: Annotated[User, Depends(require_permission(Permission.USER_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
):
    """List users."""
    _ = current_user
    result = await db_execute(
        session,
        select(User).order_by(col(User.created_at).desc()).offset(offset).limit(limit),
    )
    return result.scalars().all()


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: int,
    current_user: Annotated[User, Depends(require_permission(Permission.USER_READ))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get a user by ID."""
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Cannot access other user's profile"
        )

    result = await db_execute(session, select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user)


@router.post("", response_model=UserRead)
async def create_user(
    user_in: UserCreateRequest,
    current_user: Annotated[User, Depends(require_permission(Permission.USER_CREATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a user."""
    _ = current_user
    try:
        canonical_role = validate_role(user_in.role)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    result = await db_execute(session, select(User).where(User.email == user_in.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    user = User(
        email=user_in.email,
        name=user_in.name,
        role=canonical_role,
        hashed_password=await get_password_hash(user_in.password),
        is_active=True,
    )
    session.add(user)
    await db_commit(session)
    await db_refresh(session, user)
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: int,
    user_in: UserUpdateRequest,
    current_user: Annotated[User, Depends(require_permission(Permission.USER_UPDATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Update user details."""
    _ = current_user
    result = await db_execute(session, select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user_in.email and user_in.email != user.email:
        # Prevent email collision
        result = await db_execute(session, select(User).where(User.email == user_in.email))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")
        user.email = user_in.email

    if user_in.name is not None:
        user.name = user_in.name
    if user_in.role is not None:
        try:
            user.role = validate_role(user_in.role)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
    if user_in.is_active is not None:
        user.is_active = user_in.is_active
    if user_in.password:
        user.hashed_password = await get_password_hash(user_in.password)

    session.add(user)
    await db_commit(session)
    await db_refresh(session, user)
    user.role = normalize_role(user.role)
    return UserRead.model_validate(user)


@router.delete("/{user_id}", response_model=UserRead)
async def deactivate_user(
    user_id: int,
    current_user: Annotated[User, Depends(require_permission(Permission.USER_DELETE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Deactivate a user (soft delete)."""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate yourself"
        )

    result = await db_execute(session, select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = False
    session.add(user)
    await db_commit(session)
    await db_refresh(session, user)
    return UserRead.model_validate(user)
