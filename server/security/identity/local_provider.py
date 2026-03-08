"""Local JWT provider adapter."""

from __future__ import annotations

from typing import Any

import jwt
from jwt import InvalidTokenError

from server.routers.auth_utils import ALGORITHM, get_secret_key

from .adapter import IdentityProviderAdapter, ProviderClaims


class LocalProviderAdapter(IdentityProviderAdapter):
    """Adapter validating local AgentGate-issued JWT tokens."""

    provider_name = "local"

    @property
    def capabilities(self) -> dict[str, bool]:
        """Return supported authentication capabilities for local JWT."""
        return {
            "password_login": True,
            "token_exchange": True,
            "mfa": True,
            "sso": False,
            "step_up": False,
        }

    async def validate_token(self, token: str) -> ProviderClaims:
        """Decode a local JWT and extract normalized provider claims."""
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                get_secret_key(),
                algorithms=[ALGORITHM],
            )
        except InvalidTokenError as exc:
            raise PermissionError(f"Invalid local token: {exc}") from exc

        subject = str(payload.get("sub") or "").strip()
        email = str(payload.get("email") or subject).strip()
        if not subject or not email:
            raise PermissionError("Local token is missing subject/email")

        role = payload.get("role")
        roles_claim = payload.get("roles")
        roles: list[str] = []
        if isinstance(roles_claim, list):
            roles = [str(item).strip().lower() for item in roles_claim if str(item).strip()]
        elif role:
            roles = [str(role).strip().lower()]

        scopes_claim = payload.get("scopes")
        scopes: list[str] = []
        if isinstance(scopes_claim, list):
            scopes = [str(item).strip() for item in scopes_claim if str(item).strip()]

        session_assurance = str(payload.get("session_assurance") or "A1")
        tenant_id = str(payload.get("tenant_id") or "default")

        return ProviderClaims(
            provider=self.provider_name,
            subject=subject,
            email=email,
            name=payload.get("name"),
            tenant_id=tenant_id,
            roles=roles,
            scopes=scopes,
            session_assurance=session_assurance,
            raw_claims=payload,
        )
