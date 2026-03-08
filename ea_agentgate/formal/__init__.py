"""Formal verification domain types for proof-carrying security.

Re-exports all public symbols from :mod:`ea_agentgate.formal.models` so
callers can write::

    from ea_agentgate.formal import AlphaContext, DecisionCertificate
"""

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

_EXPORTED_FORMAL_MEMBERS = (
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

__all__ = FORMAL_PUBLIC_EXPORTS
