"""Signed preview-token generation and verification for destructive MCP tools.

Implements a two-step confirm flow:
1. Call tool with confirm=False -> preview + signed token (5-min TTL)
2. Call tool with confirm=True + token -> verify signature, expiry, params

Prevents direct confirm=True bypass and replay of expired tokens.
"""

from __future__ import annotations

import hashlib
from importlib import import_module
import json
import logging
import time

from ea_agentgate.security.integrity import HMACIntegrity

logger = logging.getLogger(__name__)

TOKEN_TTL_SECONDS = 300  # 5 minutes


def _get_integrity() -> HMACIntegrity:
    """Get HMAC integrity instance using the app secret key.

    Returns:
        HMACIntegrity instance for token signing.
    """
    auth_utils = import_module("server.routers.auth_utils")
    get_secret_key = getattr(auth_utils, "get_secret_key")

    key_bytes = get_secret_key().encode("utf-8")[:32].ljust(32, b"\x00")
    return HMACIntegrity(key_bytes)


def _params_hash(action: str, params: dict) -> str:
    """Compute deterministic hash of action + parameters.

    Args:
        action: Tool action name.
        params: Action parameters to bind into the token.

    Returns:
        Hex digest binding the token to specific parameters.
    """
    canonical = json.dumps({"action": action, **params}, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def generate_preview_token(action: str, params: dict) -> str:
    """Generate a signed preview token for a destructive action.

    Args:
        action: Tool action name (e.g. "block_ip_temp").
        params: Parameters that this token authorizes.

    Returns:
        Signed token string encoding action, params hash, and expiry.
    """
    integrity = _get_integrity()
    expiry = time.time() + TOKEN_TTL_SECONDS
    ph = _params_hash(action, params)
    payload = f"{action}|{ph}|{expiry}"
    signature = integrity.sign(payload)
    return f"{payload}|{signature}"


def verify_preview_token(
    token: str,
    action: str,
    params: dict,
) -> tuple[bool, str]:
    """Verify a preview token's signature, expiry, and param binding.

    Args:
        token: The preview token to verify.
        action: Expected action name.
        params: Expected parameters (must match token binding).

    Returns:
        Tuple of (is_valid, error_message). error_message is empty
        if valid.
    """
    error = ""
    parts = token.split("|")
    if len(parts) != 4:
        return (False, "Malformed token")

    token_action, token_ph, expiry_str, signature = parts

    try:
        expiry = float(expiry_str)
    except ValueError:
        error = "Invalid expiry in token"
    else:
        if time.time() > expiry:
            error = "Token has expired"
        elif token_action != action:
            error = f"Action mismatch: expected {action}"
        else:
            expected_ph = _params_hash(action, params)
            if token_ph != expected_ph:
                error = "Parameter mismatch: token was issued for different params"
            else:
                integrity = _get_integrity()
                payload = f"{token_action}|{token_ph}|{expiry_str}"
                if not integrity.verify(payload, signature):
                    error = "Invalid token signature"

    if error:
        return (False, error)
    return (True, "")
