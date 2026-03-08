"""Authentication routes.

Implements C-03 from the architectural audit: async database patterns
with AsyncSession and proper await statements for all database operations.
"""

import importlib
import os
import secrets
from typing import Annotated, Any, cast

import bcrypt
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, select, SQLModel

from . import auth_utils
from .auth_utils import ALGORITHM, _verify_mfa, get_password_hash, get_secret_key, verify_password
from .auth_helpers import complete_login
from .result_utils import result_one_or_none
from ..audit import emit_audit_event
from ..models import (
    AuthorizationContext,
    PolicyDecisionRecord,
    ActionSensitivityLevel,
    RuntimeThreatLevel,
    SessionAssuranceLevel,
    User,
    UserRead,
    get_session,
    ROLE_PERMISSIONS,
    Permission,
)
from ..security.identity import (
    ensure_user_identity_records,
    evaluate_mcp_privilege,
    extract_scopes_from_claims,
    get_principal_risk,
    get_roles_for_principal,
    local_password_auth_allowed,
    mcp_privileged_roles,
    mcp_required_scopes,
    normalize_assurance_level,
    normalize_role,
    provider_capabilities,
    validate_provider_token,
    validate_role,
)
from ..security.identity.policy import evaluate_policy_decision
from ..security.identity.store import generate_decision_id
from ..utils.captcha import (
    verify_hcaptcha,
    requires_captcha,
    increment_failed_login,
    reset_failed_login,
)
from ..utils.db import (
    execute as db_execute,
    commit as db_commit,
    refresh as db_refresh,
)

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


def _testing_enabled() -> bool:
    """Return whether auth routes should use relaxed testing limits."""
    environment = os.getenv("AGENTGATE_ENV", "development").strip().lower()
    testing_flag = os.getenv("TESTING", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return environment == "test" or testing_flag


def _resolve_auth_rate_limit(*_: Any, **__: Any) -> str:
    """Resolve auth route rate limits at request time."""
    if _testing_enabled():
        return "10000/minute"
    return "5/minute"


def _resolve_normal_rate_limit(*_: Any, **__: Any) -> str:
    """Resolve normal (non-strict) auth-adjacent route limits at request time."""
    if _testing_enabled():
        return "10000/minute"
    return "10/minute"


def rate_limit_normal(*args: Any, **kwargs: Any) -> str:
    """Expose the normal auth rate-limit callback for related routers."""
    return _resolve_normal_rate_limit(*args, **kwargs)


# Pre-computed dummy hash for constant-time login.
# When a user is not found, we still run bcrypt.checkpw
# against this hash so the response time is
# indistinguishable from a valid-user lookup, preventing
# username enumeration via timing side-channel.
_DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()).decode("utf-8")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
)
create_access_token = auth_utils.create_access_token


def _credentials_exception() -> HTTPException:
    """Build a standardized credentials exception."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _decode_bearer_claims(
    token: str,
) -> dict[str, Any]:
    """Decode JWT bearer token and enforce subject claim."""
    try:
        payload = jwt.decode(
            token,
            get_secret_key(),
            algorithms=[ALGORITHM],
        )
    except InvalidTokenError as exc:
        raise _credentials_exception() from exc

    email_value = payload.get("sub")
    if email_value is None:
        raise _credentials_exception()
    return payload


async def get_current_auth_claims(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> dict[str, Any]:
    """Resolve the authenticated bearer token claims."""
    return _decode_bearer_claims(token)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    """Dependency to get the current authenticated user."""
    payload = _decode_bearer_claims(token)
    email_value = payload.get("sub")
    if email_value is None:
        raise _credentials_exception()
    email: str = str(email_value)

    result = await db_execute(
        session,
        select(User).where(User.email == email),
    )
    user = result_one_or_none(result)
    if user is None:
        raise _credentials_exception()
    # Normalize legacy role alias on authenticated access.
    normalized = normalize_role(user.role)
    if user.role != normalized:
        user.role = normalized
        session.add(user)
        await db_commit(session)
    return cast(User, user)


def has_permission(
    user: User,
    permission: Permission,
) -> bool:
    """Check if user has a permission based on role."""
    role_perms = ROLE_PERMISSIONS.get(
        normalize_role(user.role),
        [],
    )
    return permission in role_perms


def require_permission(permission: Permission):
    """Dependency that requires a specific permission."""

    async def permission_checker(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        """Verify the current user holds the required permission."""
        if not has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(f"Permission required: {permission.value}"),
            )
        return current_user

    return permission_checker


async def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Dependency requiring admin role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# ------------------------------------------------------------------
# Request / response models for core auth endpoints
# ------------------------------------------------------------------


class LoginRequest(SQLModel):
    """Request schema for login."""

    email: str
    password: str
    totp_code: str | None = None
    captcha_token: str | None = None


class ProviderTokenExchangeRequest(SQLModel):
    """Request schema for provider-token exchange."""

    provider_token: str
    provider_hint: str | None = None
    channel_id: str | None = None
    agent_id: str | None = None
    trace_id: str | None = None


class AuthContextRequest(SQLModel):
    """Optional request payload for contextual risk hints."""

    action: str = "session:read"
    resource: str = "auth://context"
    action_sensitivity: str = ActionSensitivityLevel.S1.value
    runtime_threat: str = RuntimeThreatLevel.T0.value


class MCPAccessResponse(SQLModel):
    """Response payload for MCP privilege checks."""

    allowed: bool
    reason: str | None = None
    role: str
    privileged_roles: list[str] = Field(
        default_factory=list,
    )
    required_scopes: list[str] = Field(
        default_factory=list,
    )
    presented_scopes: list[str] = Field(
        default_factory=list,
    )


def _select_canonical_roles(
    claim_roles: list[str],
    fallback_role: str,
) -> list[str]:
    """Select canonical roles from claims list."""
    selected: list[str] = []
    for role in claim_roles:
        try:
            selected.append(validate_role(role))
        except ValueError:
            continue
    if not selected:
        selected = [validate_role(fallback_role)]
    return sorted(set(selected))


# ------------------------------------------------------------------
# Core authentication endpoints
# ------------------------------------------------------------------


@router.get("/providers")
async def get_auth_providers() -> dict[str, Any]:
    """Return active identity provider capabilities."""
    return provider_capabilities()


@router.post("/exchange")
@limiter.limit(_resolve_auth_rate_limit)
async def exchange_provider_token(
    request: Request,
    payload: ProviderTokenExchangeRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Exchange external provider token for AgentGate tokens."""
    claims = await validate_provider_token(
        payload.provider_token,
        provider_hint=payload.provider_hint,
    )

    result = await db_execute(
        session,
        select(User).where(User.email == claims.email),
    )
    user = result_one_or_none(result)
    canonical_roles: list[str]

    if user is None:
        provisional_role = claims.roles[0] if claims.roles else "viewer"
        canonical_roles = _select_canonical_roles(
            [provisional_role],
            "viewer",
        )
        user = User(
            email=claims.email,
            name=claims.name,
            role=canonical_roles[0],
            hashed_password=await get_password_hash(
                secrets.token_urlsafe(48),
            ),
            identity_provider=claims.provider,
            provider_subject=claims.subject,
            tenant_id=claims.tenant_id,
            is_active=True,
        )
        session.add(user)
        await db_commit(session)
        await db_refresh(session, user)
    else:
        canonical_roles = _select_canonical_roles(
            claims.roles,
            user.role,
        )
        user.role = canonical_roles[0]
        if claims.name and not user.name:
            user.name = claims.name
        user.identity_provider = claims.provider
        user.provider_subject = claims.subject
        user.tenant_id = claims.tenant_id
        session.add(user)
        await db_commit(session)
        await db_refresh(session, user)

    _principal_id, principal_risk = await ensure_user_identity_records(
        session,
        user=user,
        provider=claims.provider,
        provider_subject=claims.subject,
        tenant_id=claims.tenant_id,
        roles=canonical_roles,
    )
    await db_commit(session)

    return await complete_login(
        user=user,
        session=session,
        user_agent=request.headers.get("user-agent"),
        ip_address=(request.client.host if request.client else None),
        auth_method=(f"provider_exchange:{claims.provider}"),
        provider=claims.provider,
        provider_subject=claims.subject,
        tenant_id=claims.tenant_id,
        roles=canonical_roles,
        scopes=claims.scopes,
        session_assurance=(claims.session_assurance or SessionAssuranceLevel.A1.value),
        principal_risk=principal_risk,
    )


@router.post("/login")
@limiter.limit(_resolve_auth_rate_limit)
async def login(
    request: Request,
    credentials: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Login with email/password, optional 2FA, and CAPTCHA."""
    if not local_password_auth_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Local password login is disabled. "
                "Use provider token exchange via "
                "/api/auth/exchange."
            ),
        )

    # Check if CAPTCHA required for this email
    if await requires_captcha(
        credentials.email,
        session,
    ):
        if not credentials.captcha_token:
            await increment_failed_login(
                credentials.email,
                session,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "captcha_required",
                    "message": ("Please complete CAPTCHA verification"),
                },
            )

        client_ip = request.client.host if request.client else None
        if not await verify_hcaptcha(
            credentials.captcha_token,
            client_ip,
        ):
            await increment_failed_login(
                credentials.email,
                session,
            )
            raise HTTPException(
                status_code=(status.HTTP_400_BAD_REQUEST),
                detail="Invalid CAPTCHA",
            )

    result = await db_execute(
        session,
        select(User).where(
            User.email == credentials.email,
        ),
    )
    user = result_one_or_none(result)

    # Always run bcrypt verification to prevent timing
    # side-channel attacks. If user is not found, verify
    # against a dummy hash so response time is
    # indistinguishable from a valid-user lookup.
    hash_to_check = user.hashed_password if user else _DUMMY_BCRYPT_HASH
    password_valid = await verify_password(
        credentials.password,
        hash_to_check,
    )

    if not user or not password_valid:
        await increment_failed_login(
            credentials.email,
            session,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Check if MFA is enabled
    if user.totp_enabled:
        if credentials.totp_code is None:
            return {
                "mfa_required": True,
                "message": "2FA code required",
            }

        if not credentials.totp_code.strip() or not await _verify_mfa(
            user,
            credentials.totp_code,
            session,
        ):
            await emit_audit_event(
                session,
                event_type="login",
                actor=user.email,
                result="failed",
                details={"reason": "invalid_2fa_code"},
            )
            await db_commit(session)
            raise HTTPException(
                status_code=(status.HTTP_401_UNAUTHORIZED),
                detail="Invalid 2FA code",
            )

    # Reset failed login counter on successful login
    await reset_failed_login(credentials.email, session)

    # Complete login (tokens, session, audit log)
    user_agent = request.headers.get("user-agent")
    return await complete_login(
        user=user,
        session=session,
        user_agent=user_agent,
        ip_address=(request.client.host if request.client else None),
        auth_method="password",
        provider="local",
        provider_subject=user.email,
        tenant_id=user.tenant_id or "default",
        roles=[normalize_role(user.role)],
        session_assurance=(SessionAssuranceLevel.A1.value),
    )


@router.get(
    "/context",
    response_model=AuthorizationContext,
)
async def get_auth_context(
    current_user: Annotated[User, Depends(get_current_user)],
    auth_claims: Annotated[
        dict[str, Any],
        Depends(get_current_auth_claims),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Return canonical authorization context."""
    tenant_id = current_user.tenant_id or "default"
    roles = await get_roles_for_principal(
        session,
        principal_id=current_user.principal_id,
        tenant_id=tenant_id,
        fallback_role=current_user.role,
    )
    principal_risk = await get_principal_risk(
        session,
        principal_id=current_user.principal_id,
        fallback_role=current_user.role,
    )
    claim_scopes = sorted(
        extract_scopes_from_claims(auth_claims),
    )

    return AuthorizationContext(
        subject_id=current_user.email,
        principal_type="human_user",
        tenant_id=tenant_id,
        roles=roles,
        scopes=sorted(
            set([f"tenant:{tenant_id}", *claim_scopes]),
        ),
        principal_risk=principal_risk,
        session_assurance=normalize_assurance_level(
            str(
                auth_claims.get(
                    "session_assurance",
                    SessionAssuranceLevel.A1.value,
                )
            )
        ),
        provider=(current_user.identity_provider or "local"),
        provider_subject=current_user.provider_subject,
    )


@router.post("/context/evaluate")
async def evaluate_auth_context(
    payload: AuthContextRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    auth_claims: Annotated[
        dict[str, Any],
        Depends(get_current_auth_claims),
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Evaluate context against risk policy and persist."""
    tenant_id = current_user.tenant_id or "default"
    roles = await get_roles_for_principal(
        session,
        principal_id=current_user.principal_id,
        tenant_id=tenant_id,
        fallback_role=current_user.role,
    )
    principal_risk = await get_principal_risk(
        session,
        principal_id=current_user.principal_id,
        fallback_role=current_user.role,
    )
    claim_scopes = sorted(
        extract_scopes_from_claims(auth_claims),
    )
    context = AuthorizationContext(
        subject_id=current_user.email,
        principal_type="human_user",
        tenant_id=tenant_id,
        roles=roles,
        scopes=sorted(
            set([f"tenant:{tenant_id}", *claim_scopes]),
        ),
        principal_risk=principal_risk,
        session_assurance=normalize_assurance_level(
            str(
                auth_claims.get(
                    "session_assurance",
                    SessionAssuranceLevel.A1.value,
                )
            )
        ),
        provider=(current_user.identity_provider or "local"),
        provider_subject=current_user.provider_subject,
    )
    decision = evaluate_policy_decision(
        context=context,
        action=payload.action,
        resource=payload.resource,
        action_sensitivity=payload.action_sensitivity,
        runtime_threat=payload.runtime_threat,
    )
    decision_id = generate_decision_id()
    decision.decision_id = decision_id
    principal_id = current_user.principal_id or f"user:{current_user.id}"
    session.add(
        PolicyDecisionRecord(
            decision_id=decision_id,
            principal_id=principal_id,
            tenant_id=tenant_id,
            action=payload.action,
            resource=payload.resource,
            allowed=decision.allowed,
            reason=decision.reason,
            effective_risk=decision.effective_risk,
            required_assurance=(decision.required_assurance),
            session_assurance=(decision.session_assurance),
            required_step_up=decision.required_step_up,
            required_approval=(decision.required_approval),
            obligations_json=decision.obligations,
            trace_id=None,
        )
    )
    await db_commit(session)
    return decision.model_dump()


@router.get("/me", response_model=UserRead)
def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Get current user info."""
    return current_user


@router.get(
    "/mcp-access",
    response_model=MCPAccessResponse,
)
async def get_mcp_access(
    current_user: Annotated[User, Depends(get_current_user)],
    auth_claims: Annotated[
        dict[str, Any],
        Depends(get_current_auth_claims),
    ],
) -> MCPAccessResponse:
    """Return MCP-privileged access evaluation."""
    presented_scopes = sorted(
        extract_scopes_from_claims(auth_claims),
    )
    allowed, reason = evaluate_mcp_privilege(
        role=current_user.role,
        claims=auth_claims,
        environment=os.getenv(
            "AGENTGATE_ENV",
            "development",
        ),
    )
    return MCPAccessResponse(
        allowed=allowed,
        reason=reason or None,
        role=normalize_role(current_user.role),
        privileged_roles=sorted(
            mcp_privileged_roles(),
        ),
        required_scopes=sorted(
            mcp_required_scopes(),
        ),
        presented_scopes=presented_scopes,
    )


_registration_router = importlib.import_module("server.routers.auth_registration").router

router.include_router(_registration_router)
