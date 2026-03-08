"""Formal models and canonical encoding for proof-carrying security decisions.

Domain types (AlphaContext, GammaKnowledgeBase, DecisionCertificate, etc.)
live in ``ea_agentgate.formal.models`` and are re-exported here so that all
existing ``from .formal_models import X`` statements across the server
kernel continue to work unchanged.

This module additionally provides ``load_private_key()`` and its helper
``_derive_private_key_seed()`` which depend on the server-only
``server.utils.secret_loader`` and therefore cannot move to the SDK
package.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from ea_agentgate.formal.models import (
    FORMAL_PUBLIC_EXPORTS,
    HEX_64_LEN,
    AlphaContext,
    DecisionCertificate,
    DecisionResult,
    GammaKnowledgeBase,
    ProofType,
    canonical_json,
    export_public_key_pem,
    generate_uuid7,
    normalize_action,
    normalize_resource,
    sha256_hex,
    theorem_hash_for_expression,
    utc_now,
)
from server.utils.secret_loader import get_runtime_secret

_FORMAL_MODEL_EXPORT_BINDINGS = (
    HEX_64_LEN,
    AlphaContext,
    DecisionCertificate,
    DecisionResult,
    GammaKnowledgeBase,
    ProofType,
    canonical_json,
    export_public_key_pem,
    generate_uuid7,
    normalize_action,
    normalize_resource,
    sha256_hex,
    theorem_hash_for_expression,
    utc_now,
)


def _derive_private_key_seed() -> bytes:
    """Derive private-key seed from keyring/environment with deterministic fallback.

    In production, either AGENTGATE_DECISION_SIGNING_KEY (base64-encoded
    32-byte seed) or SECRET_KEY must be explicitly set.  Falling back to a
    hardcoded constant in production would allow certificate forgery.
    """
    encoded_seed = (get_runtime_secret("AGENTGATE_DECISION_SIGNING_KEY", "") or "").strip()
    if encoded_seed:
        try:
            candidate = base64.b64decode(encoded_seed)
            if len(candidate) == 32:
                return candidate
        except (ValueError, TypeError):
            pass

    fallback_secret = get_runtime_secret("SECRET_KEY", "") or ""
    if fallback_secret:
        return hashlib.sha256(fallback_secret.encode("utf-8")).digest()

    # No signing key available -- block production, allow development
    env = os.getenv("AGENTGATE_ENV", "development")
    if env == "production":
        raise RuntimeError(
            "AGENTGATE_DECISION_SIGNING_KEY or SECRET_KEY must "
            "be set in production. Refusing to use hardcoded "
            "fallback for certificate signing."
        )
    return hashlib.sha256(b"agentgate-development-signing-key").digest()


def load_private_key() -> Ed25519PrivateKey:
    """Load decision-signing private key for certificate generation."""
    seed = _derive_private_key_seed()
    return Ed25519PrivateKey.from_private_bytes(seed)


__all__ = [
    *FORMAL_PUBLIC_EXPORTS,
    "load_private_key",
]
