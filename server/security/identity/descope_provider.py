"""Descope-backed identity provider adapter."""

from __future__ import annotations

from .adapter import OIDCProviderAdapter


class DescopeProviderAdapter(OIDCProviderAdapter):
    """Adapter validating Descope-issued tokens through JWKS verification."""

    provider_name = "descope"
    jwks_env_var = "DESCOPE_JWKS_URL"
    issuer_env_var = "DESCOPE_ISSUER"
    audience_env_var = "DESCOPE_AUDIENCE"
