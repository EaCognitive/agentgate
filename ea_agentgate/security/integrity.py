"""
Data integrity verification - HIPAA §164.312(c)(1) compliant.

Provides HMAC-SHA256 for tamper detection with:
- Cryptographic integrity verification
- Tamper-evident data protection
- Chain of custody support
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Protocol


# =============================================================================
# Integrity Provider Protocol
# =============================================================================


class IntegrityProvider(Protocol):
    """Protocol for data integrity providers."""

    def sign(self, data: str | bytes) -> str:
        """
        Generate integrity signature for data.

        Args:
            data: Data to sign

        Returns:
            Hex-encoded signature
        """
        raise NotImplementedError

    def verify(self, data: str | bytes, signature: str) -> bool:
        """
        Verify data integrity against signature.

        Args:
            data: Data to verify
            signature: Expected signature

        Returns:
            True if data is intact, False if tampered
        """
        raise NotImplementedError


# =============================================================================
# Exceptions
# =============================================================================


class IntegrityError(Exception):
    """Data integrity verification failed."""


class TamperDetectedError(IntegrityError):
    """Data has been tampered with."""


# =============================================================================
# HMAC-SHA256 Implementation
# =============================================================================


class HMACIntegrity:
    """
    HMAC-SHA256 integrity provider.

    Provides tamper detection for sensitive data.
    Used to verify PII vault entries haven't been modified.

    Example:
        integrity = HMACIntegrity(secret_key)

        # When storing
        signature = integrity.sign("SSN: 123-45-6789")

        # When retrieving
        if not integrity.verify("SSN: 123-45-6789", signature):
            raise TamperDetectedError("Data has been modified!")

    Security properties:
        - 256-bit HMAC (SHA-256)
        - Constant-time comparison (timing attack resistant)
        - Unique key per deployment
    """

    ALGORITHM = "HMAC-SHA256"

    def __init__(self, key: bytes):
        """
        Initialize HMAC integrity provider.

        Args:
            key: Secret key for HMAC (minimum 32 bytes recommended)
        """
        if len(key) < 16:
            raise ValueError("Key must be at least 16 bytes")

        self._key = key

    def sign(self, data: str | bytes) -> str:
        """
        Generate HMAC-SHA256 signature.

        Args:
            data: Data to sign

        Returns:
            Hex-encoded HMAC signature
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        signature = hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return signature

    def verify(self, data: str | bytes, signature: str) -> bool:
        """
        Verify data integrity using constant-time comparison.

        Args:
            data: Data to verify
            signature: Expected HMAC signature

        Returns:
            True if signature matches, False otherwise
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        expected = hmac.new(self._key, data, hashlib.sha256).hexdigest()

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected, signature)

    def sign_with_metadata(
        self,
        data: str | bytes,
        timestamp: float | None = None,
        sequence: int | None = None,
    ) -> str:
        """
        Sign data with embedded metadata for chain of custody.

        Args:
            data: Data to sign
            timestamp: Unix timestamp (uses current time if None)
            sequence: Sequence number for ordering

        Returns:
            Signature in format: hmac|timestamp|sequence
        """
        if timestamp is None:
            timestamp = time.time()

        if isinstance(data, str):
            data = data.encode("utf-8")

        # Include timestamp and sequence in signed data
        meta = f"|ts:{timestamp}|seq:{sequence or 0}|"
        full_data = data + meta.encode("utf-8")

        signature = hmac.new(self._key, full_data, hashlib.sha256).hexdigest()

        return f"{signature}|{timestamp}|{sequence or 0}"

    def verify_with_metadata(
        self,
        data: str | bytes,
        signature_with_meta: str,
    ) -> tuple[bool, float, int]:
        """
        Verify data with metadata extraction.

        Args:
            data: Data to verify
            signature_with_meta: Signature from sign_with_metadata()

        Returns:
            Tuple of (is_valid, timestamp, sequence)
        """
        try:
            parts = signature_with_meta.split("|")
            if len(parts) != 3:
                return False, 0.0, 0

            signature = parts[0]
            timestamp = float(parts[1])
            sequence = int(parts[2])

            if isinstance(data, str):
                data = data.encode("utf-8")

            meta = f"|ts:{timestamp}|seq:{sequence}|"
            full_data = data + meta.encode("utf-8")

            expected = hmac.new(self._key, full_data, hashlib.sha256).hexdigest()

            is_valid = hmac.compare_digest(expected, signature)
            return is_valid, timestamp, sequence

        except (ValueError, IndexError):
            return False, 0.0, 0


# =============================================================================
# Convenience Functions
# =============================================================================


def compute_hmac(data: str | bytes, key: bytes) -> str:
    """
    Compute HMAC-SHA256 of data.

    Args:
        data: Data to sign
        key: Secret key

    Returns:
        Hex-encoded HMAC
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: str | bytes, signature: str, key: bytes) -> bool:
    """
    Verify HMAC-SHA256 signature.

    Args:
        data: Data to verify
        signature: Expected signature
        key: Secret key

    Returns:
        True if valid
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def generate_integrity_key() -> bytes:
    """Generate a 32-byte key for HMAC operations."""
    return secrets.token_bytes(32)


# =============================================================================
# Chain of Custody Support
# =============================================================================


@dataclass
class IntegrityRecord:
    """Record for chain of custody tracking."""

    data_hash: str
    signature: str
    timestamp: float
    sequence: int
    previous_hash: str | None = None


class ChainOfCustody:
    """
    Blockchain-like chain of custody for audit records.

    Creates a tamper-evident chain where each record references
    the previous record's hash, making it impossible to modify
    historical records without detection.

    Example:
        chain = ChainOfCustody(integrity_key)

        chain.add_record("User accessed SSN for session-123")
        chain.add_record("User cleared session-123")

        # Verify entire chain is intact
        if not chain.verify_chain():
            raise TamperDetectedError("Audit log has been modified!")
    """

    def __init__(self, key: bytes):
        self._integrity = HMACIntegrity(key)
        self._records: list[IntegrityRecord] = []
        self._sequence = 0

    def add_record(self, data: str) -> IntegrityRecord:
        """Add a new record to the chain."""
        timestamp = time.time()
        self._sequence += 1

        # Hash the data
        data_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()

        # Get previous hash
        previous_hash = self._records[-1].signature if self._records else None

        # Create chain data: data_hash + previous_hash + timestamp + sequence
        chain_data = f"{data_hash}|{previous_hash or 'genesis'}|{timestamp}|{self._sequence}"

        # Sign the chain data
        signature = self._integrity.sign(chain_data)

        record = IntegrityRecord(
            data_hash=data_hash,
            signature=signature,
            timestamp=timestamp,
            sequence=self._sequence,
            previous_hash=previous_hash,
        )

        self._records.append(record)
        return record

    def verify_chain(self) -> bool:
        """
        Verify entire chain integrity.

        Returns:
            True if chain is intact, False if tampered
        """
        previous_signature = None

        for record in self._records:
            # Verify previous_hash matches
            if record.previous_hash != previous_signature:
                return False

            # Reconstruct and verify chain data
            chain_data = (
                f"{record.data_hash}|{record.previous_hash or 'genesis'}|"
                f"{record.timestamp}|{record.sequence}"
            )

            if not self._integrity.verify(chain_data, record.signature):
                return False

            previous_signature = record.signature

        return True

    def get_records(self) -> list[IntegrityRecord]:
        """Get all records in the chain."""
        return list(self._records)

    @property
    def records(self) -> list[IntegrityRecord]:
        """Direct access to records list (for testing)."""
        return self._records


__all__ = [
    "IntegrityProvider",
    "IntegrityError",
    "TamperDetectedError",
    "HMACIntegrity",
    "compute_hmac",
    "verify_hmac",
    "generate_integrity_key",
    "IntegrityRecord",
    "ChainOfCustody",
]
