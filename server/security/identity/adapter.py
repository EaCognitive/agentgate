"""Identity provider adapter contracts and claims model."""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
from typing import Any

from pydantic import BaseModel, Field

from .oidc import decode_oidc_token, extract_claims


class ProviderClaims(BaseModel):
    """Normalized claim set returned by provider adapters."""

    provider: str
    subject: str
    email: str
    name: str | None = None
    tenant_id: str = "default"
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    session_assurance: str = "A1"
    raw_claims: dict[str, Any] = Field(default_factory=dict)


class IdentityProviderAdapter(ABC):
    """Adapter interface for provider token validation and claim extraction."""

    provider_name: str = "unknown"

    @property
    @abstractmethod
    def capabilities(self) -> dict[str, bool]:
        """Return capability flags exposed by the provider implementation."""

    @abstractmethod
    async def validate_token(self, token: str) -> ProviderClaims:
        """Validate an external token and return normalized claims."""

    def describe(self) -> dict[str, Any]:
        """Return provider metadata for discovery endpoints."""
        return {
            "provider": self.provider_name,
            "capabilities": self.capabilities,
        }


class OIDCProviderAdapter(IdentityProviderAdapter):
    """Shared OIDC-backed provider adapter with env-configured JWKS settings."""

    jwks_env_var: str = ""
    issuer_env_var: str = ""
    audience_env_var: str = ""

    @property
    def capabilities(self) -> dict[str, bool]:
        """Return supported authentication capabilities for OIDC providers."""
        return {
            "password_login": False,
            "token_exchange": True,
            "mfa": True,
            "sso": True,
            "step_up": True,
        }

    def _read_optional_env(self, env_var: str) -> str | None:
        """Read a trimmed env var value and normalize blank strings to None."""
        value = os.getenv(env_var, "").strip()
        return value or None

    def _jwks_url(self) -> str:
        """Return the configured JWKS URL or raise a descriptive error."""
        configured = self._read_optional_env(self.jwks_env_var)
        if configured:
            return configured
        raise RuntimeError(
            f"{self.jwks_env_var} is required when IDENTITY_PROVIDER_MODE={self.provider_name}"
        )

    def _issuer(self) -> str | None:
        """Return the configured issuer value, if any."""
        return self._read_optional_env(self.issuer_env_var)

    def _audience(self) -> str | None:
        """Return the configured audience value, if any."""
        return self._read_optional_env(self.audience_env_var)

    async def validate_token(self, token: str) -> ProviderClaims:
        """Decode and validate a token using the configured OIDC JWKS endpoint."""
        payload = await decode_oidc_token(
            token=token,
            jwks_url=self._jwks_url(),
            issuer=self._issuer(),
            audience=self._audience(),
        )
        normalized = extract_claims(payload, provider=self.provider_name)
        return ProviderClaims(
            provider=self.provider_name,
            subject=normalized["subject"],
            email=normalized["email"],
            name=normalized["name"],
            tenant_id=normalized["tenant_id"],
            roles=normalized["roles"],
            scopes=normalized["scopes"],
            session_assurance=normalized["session_assurance"],
            raw_claims=payload,
        )
