"""Generic OIDC provider adapter for bring-your-own identity systems."""

from __future__ import annotations

from .adapter import OIDCProviderAdapter


class CustomOIDCProviderAdapter(OIDCProviderAdapter):
    """Adapter validating tokens from generic OpenID Connect providers."""

    provider_name = "custom_oidc"
    jwks_env_var = "OIDC_JWKS_URL"
    issuer_env_var = "OIDC_ISSUER"
    audience_env_var = "OIDC_AUDIENCE"
