"""Identity provider mode resolution and token validation service."""

from __future__ import annotations

import os
from functools import lru_cache

from .adapter import IdentityProviderAdapter, ProviderClaims
from .custom_oidc_provider import CustomOIDCProviderAdapter
from .descope_provider import DescopeProviderAdapter
from .local_provider import LocalProviderAdapter


SUPPORTED_PROVIDER_MODES = frozenset({"local", "descope", "custom_oidc", "hybrid_migration"})


def get_identity_provider_mode() -> str:
    """Return configured identity provider mode."""
    mode = os.getenv("IDENTITY_PROVIDER_MODE", "local").strip().lower()
    if mode not in SUPPORTED_PROVIDER_MODES:
        raise RuntimeError(
            "IDENTITY_PROVIDER_MODE must be one of: " + ", ".join(sorted(SUPPORTED_PROVIDER_MODES))
        )
    return mode


def local_password_auth_allowed() -> bool:
    """Return True when local username/password authentication is allowed."""
    mode = get_identity_provider_mode()
    if mode in {"local", "hybrid_migration"}:
        return True
    override = os.getenv("ALLOW_LOCAL_PASSWORD_AUTH", "").strip().lower()
    return override in {"1", "true", "yes", "on"}


@lru_cache(maxsize=8)
def _adapter_for_provider(provider: str) -> IdentityProviderAdapter:
    if provider == "local":
        return LocalProviderAdapter()
    if provider == "descope":
        return DescopeProviderAdapter()
    if provider == "custom_oidc":
        return CustomOIDCProviderAdapter()
    raise RuntimeError(f"Unsupported provider: {provider}")


def provider_capabilities() -> dict[str, object]:
    """Return provider mode and capability metadata."""
    mode = get_identity_provider_mode()
    providers: list[str]
    if mode == "hybrid_migration":
        providers = ["local", "descope", "custom_oidc"]
    else:
        providers = [mode]
    return {
        "mode": mode,
        "providers": [_adapter_for_provider(provider).describe() for provider in providers],
        "local_password_auth_allowed": local_password_auth_allowed(),
    }


def validate_provider_runtime(environment: str) -> None:
    """Validate provider configuration for the current environment."""
    mode = get_identity_provider_mode()
    if environment != "production":
        return

    if mode == "descope":
        if not os.getenv("DESCOPE_JWKS_URL", "").strip():
            raise RuntimeError(
                "DESCOPE_JWKS_URL is required in production when IDENTITY_PROVIDER_MODE=descope"
            )
    if mode == "custom_oidc":
        if not os.getenv("OIDC_JWKS_URL", "").strip():
            raise RuntimeError(
                "OIDC_JWKS_URL is required in production when IDENTITY_PROVIDER_MODE=custom_oidc"
            )
    if mode == "local":
        override = os.getenv("ALLOW_PRODUCTION_LOCAL_AUTH", "").strip().lower()
        if override not in {"1", "true", "yes", "on"}:
            raise RuntimeError(
                "Production local auth is disabled by default. "
                "Set IDENTITY_PROVIDER_MODE=descope/custom_oidc or explicitly allow "
                "local mode with ALLOW_PRODUCTION_LOCAL_AUTH=true."
            )


async def validate_provider_token(
    provider_token: str,
    *,
    provider_hint: str | None = None,
) -> ProviderClaims:
    """Validate an external provider token against configured provider mode."""
    mode = get_identity_provider_mode()
    if provider_hint:
        hint = provider_hint.strip().lower()
    else:
        hint = None

    if mode == "local":
        adapter = _adapter_for_provider("local")
        return await adapter.validate_token(provider_token)

    if mode in {"descope", "custom_oidc"}:
        adapter = _adapter_for_provider(mode if hint is None else hint)
        if adapter.provider_name != mode:
            raise PermissionError(
                f"Provider hint '{adapter.provider_name}' is not allowed in mode '{mode}'"
            )
        return await adapter.validate_token(provider_token)

    # Hybrid migration mode supports explicit hint or trial sequence.
    trial_order = [hint] if hint else ["descope", "custom_oidc", "local"]
    errors: list[str] = []
    for provider_name in trial_order:
        if provider_name is None:
            continue
        try:
            adapter = _adapter_for_provider(provider_name)
            return await adapter.validate_token(provider_token)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            errors.append(f"{provider_name}: {exc}")
            continue

    raise PermissionError("Unable to validate provider token in hybrid mode. " + "; ".join(errors))
