"""
Encryption utilities for PII protection - HIPAA §164.312(a)(2)(iv) compliant.

Provides AES-256-GCM encryption for data at rest with:
- Authenticated encryption (confidentiality + integrity)
- Unique nonce per encryption
- Key derivation from passwords
- Key rotation support
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AESGCM_IMPL
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Use AESGCM_IMPL for implementation, aliased to avoid confusion
AESGCM = AESGCM_IMPL


# =============================================================================
# Encryption Provider Protocol
# =============================================================================


class EncryptionProvider(Protocol):
    """Protocol for encryption providers."""

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string.

        Args:
            plaintext: The string to encrypt

        Returns:
            Base64-encoded ciphertext with embedded nonce
        """
        raise NotImplementedError

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext string.

        Args:
            ciphertext: Base64-encoded ciphertext

        Returns:
            Original plaintext string

        Raises:
            DecryptionError: If decryption fails (wrong key, tampered data)
        """
        raise NotImplementedError

    @property
    def key_id(self) -> str:
        """Return identifier for the current encryption key."""
        raise NotImplementedError


# =============================================================================
# Exceptions
# =============================================================================


class EncryptionError(Exception):
    """Base encryption error."""


class DecryptionError(EncryptionError):
    """Decryption failed - wrong key or tampered data."""


class KeyDerivationError(EncryptionError):
    """Key derivation failed."""


# =============================================================================
# AES-256-GCM Implementation
# =============================================================================


@dataclass
class EncryptedData:
    """Container for encrypted data with metadata."""

    ciphertext: bytes
    nonce: bytes
    tag: bytes
    key_id: str
    version: int = 1


class AESGCMEncryption:
    """
    AES-256-GCM encryption provider.

    HIPAA-compliant encryption for PHI at rest.
    Uses authenticated encryption to provide both confidentiality and integrity.

    Example:
        key = generate_key()
        encryptor = AESGCMEncryption(key)

        ciphertext = encryptor.encrypt("SSN: 123-45-6789")
        plaintext = encryptor.decrypt(ciphertext)

    Security properties:
        - 256-bit key (AES-256)
        - 96-bit random nonce per encryption
        - 128-bit authentication tag
        - Resistant to padding oracle attacks
    """

    # Algorithm identifier
    ALGORITHM = "AES-256-GCM"

    # Key size in bytes (256 bits)
    KEY_SIZE = 32

    # Nonce size in bytes (96 bits recommended for GCM)
    NONCE_SIZE = 12

    # Tag size in bytes (128 bits)
    TAG_SIZE = 16

    # Version for format changes
    VERSION = 1

    def __init__(
        self,
        key: bytes,
        key_id: str | None = None,
    ):
        """
        Initialize AES-256-GCM encryption.

        Args:
            key: 32-byte (256-bit) encryption key
            key_id: Optional key identifier for rotation tracking

        Raises:
            ValueError: If key is not 32 bytes
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits)")

        self._key = key
        self._key_id = key_id or self._compute_key_id(key)
        self._aesgcm = AESGCM_IMPL(key)

    @property
    def key_id(self) -> str:
        """Return key identifier (first 8 chars of key hash)."""
        return self._key_id

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string using AES-256-GCM.

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded string: version|key_id|nonce|ciphertext|tag
        """
        plaintext_bytes = plaintext.encode("utf-8")

        # Generate random nonce (MUST be unique per encryption)
        nonce = os.urandom(self.NONCE_SIZE)

        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, None)
        # GCM appends tag to ciphertext
        ciphertext = ciphertext_with_tag[: -self.TAG_SIZE]
        tag = ciphertext_with_tag[-self.TAG_SIZE :]

        # Pack: version (1 byte) | key_id (8 bytes) | nonce | ciphertext | tag
        packed = (
            bytes([self.VERSION])
            + self._key_id.encode("utf-8")[:8].ljust(8, b"\x00")
            + nonce
            + ciphertext
            + tag
        )

        return base64.b64encode(packed).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext string.

        Args:
            ciphertext: Base64-encoded encrypted data

        Returns:
            Original plaintext string

        Raises:
            DecryptionError: If decryption fails
        """
        try:
            packed = base64.b64decode(ciphertext)
        except Exception as e:
            raise DecryptionError(f"Invalid base64 encoding: {e}") from e

        # Minimum size: version (1) + key_id (8) + nonce (12) + tag (16) = 37
        if len(packed) < 37:
            raise DecryptionError("Ciphertext too short")

        # Unpack
        version = packed[0]
        stored_key_id = packed[1:9].rstrip(b"\x00").decode("utf-8")
        nonce = packed[9 : 9 + self.NONCE_SIZE]
        ciphertext_bytes = packed[9 + self.NONCE_SIZE : -self.TAG_SIZE]
        tag = packed[-self.TAG_SIZE :]

        # Version check
        if version != self.VERSION:
            raise DecryptionError(f"Unsupported version: {version}")

        # Key ID warning (doesn't prevent decryption, but logs mismatch)
        if stored_key_id != self._key_id:
            # In production, this might indicate key rotation is needed
            pass

        try:
            # Cryptography library expects ciphertext + tag
            ciphertext_with_tag = ciphertext_bytes + tag
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext_with_tag, None)

            return plaintext_bytes.decode("utf-8")

        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e

    def _compute_key_id(self, key: bytes) -> str:
        """Compute key identifier from key hash."""
        return hashlib.sha256(key).hexdigest()[:8]


def generate_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit key.

    Returns:
        32-byte random key suitable for AES-256

    Example:
        key = generate_key()
        # Store securely (e.g., AWS KMS, HashiCorp Vault)
    """
    return secrets.token_bytes(32)


def derive_key(
    password: str,
    salt: bytes | None = None,
    iterations: int = 100000,
) -> tuple[bytes, bytes]:
    """
    Derive encryption key from password using PBKDF2.

    Args:
        password: User password or passphrase
        salt: 16-byte salt (generated if not provided)
        iterations: PBKDF2 iterations (100,000+ recommended)

    Returns:
        Tuple of (32-byte key, 16-byte salt)

    Example:
        key, salt = derive_key("my-secret-passphrase")
        # Store salt alongside encrypted data
        # Never store the password or derived key

    Security notes:
        - Use a unique salt per key derivation
        - Higher iterations = slower brute force
        - 100,000 iterations is NIST minimum for 2023
    """
    if salt is None:
        salt = os.urandom(16)

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode("utf-8"))
    except Exception as exc:
        raise KeyDerivationError(f"Key derivation failed: {exc}") from exc

    return key, salt


# =============================================================================
# Encryption Key Wrapper (for key rotation)
# =============================================================================


class EncryptionKeyRing:
    """
    Manages multiple encryption keys for rotation.

    Supports:
    - Adding new keys for encryption
    - Keeping old keys for decryption
    - Automatic key selection based on key_id in ciphertext

    Example:
        keyring = EncryptionKeyRing()
        keyring.add_key(old_key, key_id="key-2024-01")
        keyring.add_key(new_key, key_id="key-2024-02", active=True)

        # Encrypts with new key
        ciphertext = keyring.encrypt("sensitive data")

        # Decrypts with whichever key was used
        plaintext = keyring.decrypt(ciphertext)
    """

    def __init__(self):
        self._keys: dict[str, AESGCMEncryption] = {}
        self._active_key_id: str | None = None

    def add_key(
        self,
        key: bytes,
        key_id: str | None = None,
        active: bool = False,
    ) -> str:
        """
        Add a key to the keyring.

        Args:
            key: 32-byte encryption key
            key_id: Optional key identifier
            active: If True, use this key for new encryptions

        Returns:
            The key_id assigned to this key
        """
        encryptor = AESGCMEncryption(key, key_id)
        actual_key_id = encryptor.key_id
        self._keys[actual_key_id] = encryptor

        if active or self._active_key_id is None:
            self._active_key_id = actual_key_id

        return actual_key_id

    def encrypt(self, plaintext: str) -> str:
        """Encrypt with the active key."""
        if self._active_key_id is None:
            raise EncryptionError("No active key in keyring")

        return self._keys[self._active_key_id].encrypt(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt with the appropriate key based on key_id in ciphertext."""
        # Extract key_id from ciphertext
        try:
            packed = base64.b64decode(ciphertext)
            if len(packed) < 9:
                raise DecryptionError("Ciphertext too short")
            stored_key_id = packed[1:9].rstrip(b"\x00").decode("utf-8")
        except Exception as e:
            raise DecryptionError(f"Cannot parse ciphertext: {e}") from e

        if stored_key_id not in self._keys:
            raise DecryptionError(f"Unknown key_id: {stored_key_id}")

        return self._keys[stored_key_id].decrypt(ciphertext)

    @property
    def key_id(self) -> str:
        """Return active key ID."""
        if self._active_key_id is None:
            raise EncryptionError("No active key")
        return self._active_key_id


__all__ = [
    "EncryptionProvider",
    "EncryptionError",
    "DecryptionError",
    "KeyDerivationError",
    "AESGCMEncryption",
    "EncryptionKeyRing",
    "generate_key",
    "derive_key",
]
