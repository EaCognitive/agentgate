"""Pure domain types for proof-carrying security decisions.

This module contains the canonical data models and utility functions for
formal admissibility evaluation. It depends only on stdlib, pydantic,
and cryptography -- no server imports -- so that ``ea_agentgate/`` can be
distributed and tested independently of the server package.

Types:
    AlphaContext: normalized action input context.
    GammaKnowledgeBase: trusted fact context used for theorem evaluation.
    DecisionCertificate: signed proof artifact for allow/block decisions.
    DecisionResult / ProofType: enum classifiers.

All hashes and signatures use deterministic canonical JSON serialization.
"""

from __future__ import annotations

import base64
from binascii import Error as BinasciiError
import hashlib
import json
import secrets
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator


HEX_64_LEN = 64


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def canonical_json(value: Any) -> str:
    """Serialize a value with deterministic canonical JSON encoding."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def sha256_hex(value: str | bytes) -> str:
    """Return SHA-256 hash for text/bytes payloads."""
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def normalize_action(action: str) -> str:
    """Normalize an action identifier into canonical lowercase form."""
    normalized = action.strip().lower()
    return normalized if normalized else "__empty_action__"


def normalize_resource(resource: str) -> str:
    """Normalize a resource identifier into canonical form."""
    normalized = resource.strip()
    return normalized if "://" in normalized else normalized.lower()


def generate_uuid7() -> uuid.UUID:
    """Generate UUIDv7-compatible identifier.

    Python 3.10 does not include built-in uuid7 support. This
    implementation follows RFC 9562 field layout and preserves
    millisecond time ordering.
    """
    timestamp_ms = int(time.time() * 1000)
    if timestamp_ms >= (1 << 48):
        raise ValueError("timestamp overflow for UUIDv7")

    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    uuid_int = 0
    uuid_int |= (timestamp_ms & ((1 << 48) - 1)) << 80
    uuid_int |= 0x7 << 76  # version
    uuid_int |= (rand_a & ((1 << 12) - 1)) << 64
    uuid_int |= 0x2 << 62  # variant 10xx
    uuid_int |= rand_b

    return uuid.UUID(int=uuid_int)


def theorem_hash_for_expression(expression: str) -> str:
    """Create deterministic hash for theorem expression text."""
    return sha256_hex(expression.strip())


def export_public_key_pem(public_key: Ed25519PublicKey) -> str:
    """Export public key in PEM format for offline verification."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


class DecisionResult(str, Enum):
    """Admissibility result for the theorem evaluation."""

    ADMISSIBLE = "ADMISSIBLE"
    INADMISSIBLE = "INADMISSIBLE"


class ProofType(str, Enum):
    """Proof artifact class attached to a decision certificate."""

    CONSTRUCTIVE_TRACE = "CONSTRUCTIVE_TRACE"
    UNSAT_CORE = "UNSAT_CORE"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"


class AlphaContext(BaseModel):
    """Canonical action context ``alpha`` for theorem evaluation."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    principal: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    time: datetime
    context_hash: str = Field(min_length=HEX_64_LEN, max_length=HEX_64_LEN)
    delegation_ref: str | None = None
    tenant_id: str | None = None
    runtime_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action", mode="before")
    @classmethod
    def _normalize_action(cls, value: Any) -> str:
        return normalize_action(str(value))

    @field_validator("resource")
    @classmethod
    def _normalize_resource(cls, value: str) -> str:
        return normalize_resource(value)

    @field_validator("context_hash")
    @classmethod
    def _validate_context_hash(cls, value: str) -> str:
        if len(value) != HEX_64_LEN:
            raise ValueError("context_hash must be a 64-character hex digest")
        int(value, 16)
        return value

    @field_validator("time")
    @classmethod
    def _validate_time_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @classmethod
    def from_runtime(
        cls,
        *,
        principal: str,
        action: str,
        resource: str,
        runtime_context: dict[str, Any] | None = None,
        delegation_ref: str | None = None,
        tenant_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> "AlphaContext":
        """Construct AlphaContext with deterministic context hash."""
        context_payload = runtime_context or {}
        return cls(
            principal=principal,
            action=action,
            resource=resource,
            time=timestamp or utc_now(),
            context_hash=sha256_hex(canonical_json(context_payload)),
            delegation_ref=delegation_ref,
            tenant_id=tenant_id,
            runtime_context=context_payload,
        )

    @property
    def alpha_hash(self) -> str:
        """Return deterministic hash of canonical alpha context."""
        payload = self.model_dump(mode="json")
        return sha256_hex(canonical_json(payload))


class GammaKnowledgeBase(BaseModel):
    """Trusted knowledge base ``Gamma`` for theorem evaluation."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    generated_at: datetime = Field(default_factory=utc_now)
    principal: str = Field(min_length=1)
    tenant_id: str | None = None
    facts: list[dict[str, Any]] = Field(default_factory=list)
    active_grants: list[dict[str, Any]] = Field(default_factory=list)
    active_revocations: list[dict[str, Any]] = Field(default_factory=list)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    obligations: list[dict[str, Any]] = Field(default_factory=list)
    environment: dict[str, Any] = Field(default_factory=dict)
    gamma_hash: str | None = None

    def compute_gamma_hash(self) -> str:
        """Compute and store deterministic gamma hash."""
        payload = self.model_dump(mode="json")
        payload["gamma_hash"] = None
        digest = sha256_hex(canonical_json(payload))
        object.__setattr__(self, "gamma_hash", digest)
        return digest


class DecisionCertificate(BaseModel):
    """Signed decision certificate with theorem and proof payload."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    decision_id: uuid.UUID = Field(default_factory=generate_uuid7)
    theorem_hash: str = Field(min_length=HEX_64_LEN, max_length=HEX_64_LEN)
    result: DecisionResult
    proof_type: ProofType
    proof_payload: dict[str, Any]
    alpha_hash: str = Field(min_length=HEX_64_LEN, max_length=HEX_64_LEN)
    gamma_hash: str = Field(min_length=HEX_64_LEN, max_length=HEX_64_LEN)
    solver_version: str = Field(default="formal-solver/v1")
    created_at: datetime = Field(default_factory=utc_now)
    signature: str | None = None

    @field_validator("theorem_hash", "alpha_hash", "gamma_hash")
    @classmethod
    def _validate_hex_hash(cls, value: str) -> str:
        if len(value) != HEX_64_LEN:
            raise ValueError("hash fields must be 64-character hex digests")
        int(value, 16)
        return value

    def unsigned_payload(self) -> bytes:
        """Return canonical unsigned certificate payload bytes."""
        payload = self.model_dump(mode="json")
        payload["signature"] = None
        return canonical_json(payload).encode("utf-8")

    @property
    def certificate_hash(self) -> str:
        """Return deterministic hash of unsigned certificate."""
        return sha256_hex(self.unsigned_payload())

    def sign(self, private_key: Ed25519PrivateKey) -> "DecisionCertificate":
        """Sign certificate payload with Ed25519 key."""
        signed = private_key.sign(self.unsigned_payload())
        self.signature = base64.urlsafe_b64encode(signed).decode("ascii")
        return self

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Verify certificate signature."""
        if not self.signature:
            return False
        try:
            signature_bytes = base64.urlsafe_b64decode(self.signature.encode("ascii"))
            public_key.verify(signature_bytes, self.unsigned_payload())
            return True
        except (BinasciiError, InvalidSignature, TypeError, ValueError):
            return False


FORMAL_PUBLIC_EXPORTS = (
    "HEX_64_LEN",
    "AlphaContext",
    "DecisionCertificate",
    "DecisionResult",
    "GammaKnowledgeBase",
    "ProofType",
    "canonical_json",
    "export_public_key_pem",
    "generate_uuid7",
    "normalize_action",
    "normalize_resource",
    "sha256_hex",
    "theorem_hash_for_expression",
    "utc_now",
)
