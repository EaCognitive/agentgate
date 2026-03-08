"""OIDC token verification helpers used by provider adapters."""

from __future__ import annotations

import asyncio
from typing import Any, cast

import jwt
from jwt import InvalidTokenError, PyJWKClient


def _infer_session_assurance(payload: dict[str, Any]) -> str:
    """Infer session assurance from standard OIDC claims."""
    acr = str(payload.get("acr") or "").lower()
    amr = payload.get("amr")
    amr_values: list[str] = []
    if isinstance(amr, list):
        amr_values = [str(item).lower() for item in amr]

    if "phishing-resistant" in acr or "passkey" in acr:
        return "A3"
    if any(item in {"mfa", "otp", "totp", "hwk", "passkey"} for item in amr_values):
        return "A2"
    return "A1"


async def decode_oidc_token(
    *,
    token: str,
    jwks_url: str,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict[str, Any]:
    """Validate and decode an OIDC JWT using remote JWKS."""
    jwk_client = PyJWKClient(jwks_url)

    def _decode() -> dict[str, Any]:
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": bool(audience),
            "verify_iss": bool(issuer),
        }
        return jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=audience,
            issuer=issuer,
            options=cast(Any, options),
        )

    try:
        return await asyncio.to_thread(_decode)
    except InvalidTokenError as exc:
        raise PermissionError(f"Invalid OIDC token: {exc}") from exc


def extract_claims(
    payload: dict[str, Any],
    *,
    provider: str,
) -> dict[str, Any]:
    """Normalize claims from OIDC payload."""
    subject = str(payload.get("sub") or "").strip()
    email = str(payload.get("email") or payload.get("upn") or "").strip()
    if not email and "preferred_username" in payload:
        email = str(payload["preferred_username"]).strip()

    if not subject:
        raise PermissionError(f"{provider} token is missing subject claim")
    if not email:
        raise PermissionError(f"{provider} token is missing email claim")

    roles: list[str] = []
    raw_roles = payload.get("roles")
    if isinstance(raw_roles, list):
        roles = [str(item).strip().lower() for item in raw_roles if str(item).strip()]
    elif isinstance(payload.get("role"), str):
        roles = [str(payload["role"]).strip().lower()]

    scopes: list[str] = []
    raw_scope = payload.get("scope")
    if isinstance(raw_scope, str):
        scopes = [part.strip() for part in raw_scope.split(" ") if part.strip()]
    elif isinstance(payload.get("scp"), list):
        scopes = [str(item).strip() for item in payload["scp"] if str(item).strip()]

    tenant_id = str(
        payload.get("tenant_id")
        or payload.get("tenant")
        or payload.get("org_id")
        or payload.get("organization")
        or "default"
    )

    return {
        "subject": subject,
        "email": email,
        "name": payload.get("name"),
        "tenant_id": tenant_id,
        "roles": roles,
        "scopes": scopes,
        "session_assurance": _infer_session_assurance(payload),
    }
