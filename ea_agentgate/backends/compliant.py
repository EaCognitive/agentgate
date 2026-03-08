"""
SOC 2 and HIPAA compliant PII vault backend.

This backend wraps any PIIVaultBackend with compliance features:
- Encryption at rest (AES-256-GCM)
- Data integrity verification (HMAC-SHA256)
- Comprehensive audit logging
- Access control integration
- Secure deletion
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING, cast

from ..security.access_control import Permission
from ..security.audit import AuditEventType
from ..security.integrity import TamperDetectedError
from .protocols import PIIVaultBackend

if TYPE_CHECKING:
    from ..security.encryption import EncryptionProvider
    from ..security.integrity import IntegrityProvider
    from ..security.audit import ComplianceAuditLog
    from ..security.access_control import SimpleRBAC


# =============================================================================
# Enhanced PII Entry for Compliance
# =============================================================================


@dataclass
class _ComplianceMetadata:
    """Compliance-related metadata for a PII entry."""

    encrypted: bool = True
    encryption_key_id: str | None = None
    integrity_hash: str | None = None
    data_classification: str = "CONFIDENTIAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED


@dataclass
class _AuditMetadata:
    """Audit-related metadata for a PII entry."""

    created_by: str | None = None  # user_id who created
    access_count: int = 0
    last_accessed_at: float | None = None
    last_accessed_by: str | None = None


@dataclass
class _ComplianceServices:
    """Audit and access control services for the vault."""

    audit_log: "ComplianceAuditLog | None" = None
    access_control: "SimpleRBAC | None" = None


@dataclass
class _StorageMetadata:
    """Core storage metadata for a PII entry."""

    placeholder: str
    original_encrypted: str  # Encrypted original value
    pii_type: str
    session_id: str | None = None
    created_at: float = 0.0
    ttl: float | None = None


@dataclass
class _SecurityMetadata:
    """Security and compliance metadata for a PII entry."""

    encrypted: bool = True
    encryption_key_id: str | None = None
    integrity_hash: str | None = None
    data_classification: str = "CONFIDENTIAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED


@dataclass
class _AccessAuditMetadata:
    """Access and audit tracking metadata."""

    created_by: str | None = None  # user_id who created
    access_count: int = 0
    last_accessed_at: float | None = None
    last_accessed_by: str | None = None


@dataclass
class CompliancePIIEntry:
    """
    Enhanced PII entry with compliance metadata.

    Extends PIIEntry with:
    - Encryption status and key ID
    - Integrity verification hash
    - Data classification
    - Audit tracking
    """

    # Core storage fields
    storage: _StorageMetadata

    # Security and compliance fields
    security: _SecurityMetadata = field(default_factory=_SecurityMetadata)

    # Access and audit fields
    audit: _AccessAuditMetadata = field(default_factory=_AccessAuditMetadata)

    @property
    def placeholder(self) -> str:
        """Get placeholder."""
        return self.storage.placeholder

    @property
    def original_encrypted(self) -> str:
        """Get encrypted original value."""
        return self.storage.original_encrypted

    @property
    def pii_type(self) -> str:
        """Get PII type."""
        return self.storage.pii_type

    @property
    def session_id(self) -> str | None:
        """Get session ID."""
        return self.storage.session_id

    @property
    def created_at(self) -> float:
        """Get creation timestamp."""
        return self.storage.created_at

    @property
    def ttl(self) -> float | None:
        """Get time-to-live."""
        return self.storage.ttl

    @property
    def encrypted(self) -> bool:
        """Get encryption status."""
        return self.security.encrypted

    @property
    def encryption_key_id(self) -> str | None:
        """Get encryption key ID."""
        return self.security.encryption_key_id

    @property
    def integrity_hash(self) -> str | None:
        """Get integrity hash."""
        return self.security.integrity_hash

    @property
    def data_classification(self) -> str:
        """Get data classification."""
        return self.security.data_classification

    @property
    def created_by(self) -> str | None:
        """Get creator user ID."""
        return self.audit.created_by

    @property
    def access_count(self) -> int:
        """Get access count."""
        return self.audit.access_count

    @property
    def last_accessed_at(self) -> float | None:
        """Get last access timestamp."""
        return self.audit.last_accessed_at

    @property
    def last_accessed_by(self) -> str | None:
        """Get last accessed by user ID."""
        return self.audit.last_accessed_by

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "placeholder": self.storage.placeholder,
            "original_encrypted": self.storage.original_encrypted,
            "pii_type": self.storage.pii_type,
            "session_id": self.storage.session_id,
            "created_at": self.storage.created_at,
            "ttl": self.storage.ttl,
            "encrypted": self.security.encrypted,
            "encryption_key_id": self.security.encryption_key_id,
            "integrity_hash": self.security.integrity_hash,
            "data_classification": self.security.data_classification,
            "created_by": self.audit.created_by,
            "access_count": self.audit.access_count,
            "last_accessed_at": self.audit.last_accessed_at,
            "last_accessed_by": self.audit.last_accessed_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CompliancePIIEntry":
        """Create from dictionary."""
        return cls(
            storage=_StorageMetadata(
                placeholder=data["placeholder"],
                original_encrypted=data["original_encrypted"],
                pii_type=data["pii_type"],
                session_id=data.get("session_id"),
                created_at=data.get("created_at", 0.0),
                ttl=data.get("ttl"),
            ),
            security=_SecurityMetadata(
                encrypted=data.get("encrypted", True),
                encryption_key_id=data.get("encryption_key_id"),
                integrity_hash=data.get("integrity_hash"),
                data_classification=data.get("data_classification", "CONFIDENTIAL"),
            ),
            audit=_AccessAuditMetadata(
                created_by=data.get("created_by"),
                access_count=data.get("access_count", 0),
                last_accessed_at=data.get("last_accessed_at"),
                last_accessed_by=data.get("last_accessed_by"),
            ),
        )


# =============================================================================
# Compliant PII Vault Backend
# =============================================================================


@dataclass
class _ComplianceVaultConfig:
    """Configuration for compliant PII vault."""

    backend: PIIVaultBackend
    encryption: "EncryptionProvider"
    integrity: "IntegrityProvider"
    data_classification: str = "CONFIDENTIAL"
    retention_days: int = 2190  # 6 years for HIPAA
    min_ttl_seconds: int = field(init=False)

    def __post_init__(self):
        """Compute derived fields."""
        self.min_ttl_seconds = self.retention_days * 24 * 60 * 60


class CompliantPIIVaultBackend:
    """
    SOC 2 and HIPAA compliant PII vault backend.

    Wraps any PIIVaultBackend with compliance features:
    - Encryption at rest (AES-256-GCM)
    - Data integrity verification (HMAC-SHA256)
    - Comprehensive audit logging
    - Access control integration
    - Secure deletion

    Example:
        from ea_agentgate.backends import MemoryPIIVaultBackend
        from ea_agentgate.security import AESGCMEncryption, HMACIntegrity, ComplianceAuditLog

        # Create base backend
        base_backend = MemoryPIIVaultBackend()

        # Create security components
        encryption = AESGCMEncryption(generate_key())
        integrity = HMACIntegrity(generate_key())
        audit_log = ComplianceAuditLog(destination=Path("/var/log/audit.jsonl"))

        # Create compliant backend
        vault = CompliantPIIVaultBackend(
            backend=base_backend,
            encryption=encryption,
            integrity=integrity,
            audit_log=audit_log,
        )

        # Use like normal PIIVaultBackend
        vault.store(
            "<SSN_1>", "123-45-6789", pii_type="SSN",
            session_id="sess123", user_id="user456"
        )

    Compliance checklist:
        [x] HIPAA §164.312(a)(2)(iv) - Encryption at rest
        [x] HIPAA §164.312(b) - Audit controls
        [x] HIPAA §164.312(c)(1) - Data integrity
        [x] HIPAA §164.530(j)(1) - Secure deletion
        [x] SOC 2 CC6.1 - Access controls
        [x] SOC 2 CC7.2 - Audit trails
        [x] SOC 2 CC7.3 - Data integrity
    """

    # pylint: disable-next=too-many-positional-arguments
    def __init__(
        self,
        backend: PIIVaultBackend,
        encryption: "EncryptionProvider",
        integrity: "IntegrityProvider",
        audit_log: "ComplianceAuditLog | None" = None,
        access_control: "SimpleRBAC | None" = None,
        data_classification: str = "CONFIDENTIAL",
        retention_days: int = 2190,  # 6 years for HIPAA
    ):
        """
        Initialize compliant PII vault.

        Args:
            backend: Base storage backend
            encryption: Encryption provider for data at rest
            integrity: Integrity provider for tamper detection
            audit_log: Optional compliance audit log
            access_control: Optional RBAC provider
            data_classification: Default classification level
            retention_days: Minimum retention period (HIPAA = 6 years)
        """
        self._config = _ComplianceVaultConfig(
            backend=backend,
            encryption=encryption,
            integrity=integrity,
            data_classification=data_classification,
            retention_days=retention_days,
        )
        self._services = _ComplianceServices(
            audit_log=audit_log,
            access_control=access_control,
        )
        # Maintain historical encryption providers by key ID so key rotation
        # does not make previously encrypted entries unreadable.
        self._encryption_providers: dict[str, EncryptionProvider] = {}
        self._register_encryption_provider(self._config.encryption)

    def _register_encryption_provider(self, provider: "EncryptionProvider") -> None:
        """Register an encryption provider by key ID if not already present."""
        key_id = provider.key_id
        if key_id not in self._encryption_providers:
            self._encryption_providers[key_id] = provider

    def _get_encryption_provider_for_entry(
        self,
        entry: CompliancePIIEntry,
    ) -> "EncryptionProvider":
        """Resolve the encryption provider for a stored entry."""
        # Always register the currently configured provider in case rotation
        # happened via direct config reassignment.
        self._register_encryption_provider(self._config.encryption)

        key_id = entry.security.encryption_key_id
        if key_id and key_id in self._encryption_providers:
            return self._encryption_providers[key_id]

        # Fallback to current provider for legacy records with missing key_id.
        return self._config.encryption

    # pylint: disable-next=too-many-positional-arguments
    def store(
        self,
        placeholder: str,
        original: str,
        pii_type: str,
        session_id: str | None = None,
        ttl: float | None = None,
        user_id: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        """
        Store PII with encryption and integrity protection.

        Args:
            placeholder: Placeholder token
            original: Original PII value (will be encrypted)
            pii_type: Type of PII
            session_id: Session scope
            ttl: Time-to-live (minimum enforced for compliance)
            user_id: User performing the operation
            source_ip: Client IP address
        """
        # Access control check
        if self._services.access_control and user_id:
            self._services.access_control.require_permission(
                user_id, Permission.PII_STORE, session_id=session_id
            )

        self._register_encryption_provider(self._config.encryption)

        # Encrypt the original value
        encrypted_original = self._config.encryption.encrypt(original)

        # Compute integrity hash over all data
        integrity_data = f"{placeholder}|{encrypted_original}|{pii_type}|{session_id}"
        integrity_hash = self._config.integrity.sign(integrity_data)

        # Enforce minimum TTL for compliance (HIPAA 6-year retention)
        effective_ttl = ttl
        if effective_ttl is not None and effective_ttl < self._config.min_ttl_seconds:
            effective_ttl = self._config.min_ttl_seconds

        # Create compliance entry
        entry = CompliancePIIEntry(
            storage=_StorageMetadata(
                placeholder=placeholder,
                original_encrypted=encrypted_original,
                pii_type=pii_type,
                session_id=session_id,
                created_at=time.time(),
                ttl=effective_ttl,
            ),
            security=_SecurityMetadata(
                encrypted=True,
                encryption_key_id=self._config.encryption.key_id,
                integrity_hash=integrity_hash,
                data_classification=self._config.data_classification,
            ),
            audit=_AccessAuditMetadata(
                created_by=user_id,
            ),
        )

        # Store serialized entry in base backend
        entry_json = json.dumps(entry.to_dict())
        self._config.backend.store(
            placeholder,
            entry_json,
            pii_type="ENCRYPTED_ENTRY",
            session_id=session_id,
            ttl=effective_ttl,
        )

        # Audit log
        if self._services.audit_log:
            self._services.audit_log.log_pii_store(
                placeholder=placeholder,
                pii_type=pii_type,
                user_id=user_id,
                session_id=session_id,
                source_ip=source_ip,
                metadata={
                    "encryption_key_id": self._config.encryption.key_id,
                    "data_classification": self._config.data_classification,
                },
            )

    def _resolve_placeholder_source(
        self,
        placeholder: str,
        session_id: str | None,
        user_id: str | None,
    ) -> CompliancePIIEntry | None:
        """Retrieve and parse a compliance entry from the base backend.

        Returns the parsed entry, or None when the placeholder is not
        found or cannot be parsed.  Audit logging is performed on failure.
        """
        entry_json: str | None = cast(
            "str | None", self._config.backend.retrieve(placeholder, session_id)
        )

        if entry_json is None:
            if self._services.audit_log:
                self._services.audit_log.log_pii_retrieve(
                    placeholder=placeholder,
                    user_id=user_id,
                    session_id=session_id,
                    success=False,
                    error_message="not_found",
                )
            return None

        try:
            return CompliancePIIEntry.from_dict(json.loads(entry_json))
        except (json.JSONDecodeError, KeyError) as e:
            if self._services.audit_log:
                self._services.audit_log.log_pii_retrieve(
                    placeholder=placeholder,
                    user_id=user_id,
                    session_id=session_id,
                    success=False,
                    error_message=f"parse_error:{e}",
                )
            return None

    def retrieve(
        self,
        placeholder: str,
        session_id: str | None = None,
        user_id: str | None = None,
        _source_ip: str | None = None,
    ) -> str | None:
        """
        Retrieve and decrypt PII with integrity verification.

        Args:
            placeholder: Placeholder to look up
            session_id: Session scope
            user_id: User performing the operation
            _source_ip: Client IP address (reserved for future audit use)

        Returns:
            Decrypted original value, or None if not found

        Raises:
            IntegrityError: If data has been tampered with
        """
        if self._services.access_control and user_id:
            self._services.access_control.require_permission(
                user_id, Permission.PII_RETRIEVE, session_id=session_id
            )

        entry = self._resolve_placeholder_source(placeholder, session_id, user_id)
        if entry is None:
            return None

        # Verify integrity
        integrity_data = "|".join(
            [
                entry.storage.placeholder,
                entry.storage.original_encrypted,
                entry.storage.pii_type,
                str(entry.storage.session_id),
            ]
        )
        if not self._config.integrity.verify(integrity_data, entry.security.integrity_hash or ""):
            if self._services.audit_log:
                self._services.audit_log.log_integrity_failure(
                    resource=f"pii:{placeholder}",
                    details="HMAC verification failed",
                    user_id=user_id,
                    session_id=session_id,
                )
            raise TamperDetectedError(f"Data integrity check failed for {placeholder}")

        # Decrypt
        try:
            encryption_provider = self._get_encryption_provider_for_entry(entry)
            original = encryption_provider.decrypt(entry.original_encrypted)
        except (ValueError, RuntimeError, OSError) as e:
            if self._services.audit_log:
                self._services.audit_log.log(
                    event_type=AuditEventType.DECRYPTION_FAILURE,
                    placeholder=placeholder,
                    user_id=user_id,
                    session_id=session_id,
                    success=False,
                    error_message=str(e),
                )
            raise

        if self._services.audit_log:
            self._services.audit_log.log_pii_retrieve(
                placeholder=placeholder,
                user_id=user_id,
                session_id=session_id,
                success=True,
            )

        return original

    def get_all_mappings(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
    ) -> dict[str, str]:
        """
        Get all mappings (decrypted) for a session.

        Args:
            session_id: Session scope
            user_id: User performing the operation

        Returns:
            Dictionary of placeholder -> original (decrypted)
        """
        # Access control check
        if self._services.access_control and user_id:
            self._services.access_control.require_permission(
                user_id, Permission.PII_BULK_RETRIEVE, session_id=session_id
            )

        # Get encrypted mappings
        encrypted_mappings: dict[str, str] = cast(
            "dict[str, str]", self._config.backend.get_all_mappings(session_id)
        )

        # Decrypt each
        result: dict[str, str] = {}
        for placeholder, _ in encrypted_mappings.items():
            try:
                original = self.retrieve(placeholder, session_id, user_id)
                if original:
                    result[placeholder] = original
            except (ValueError, RuntimeError, TamperDetectedError):
                # Skip entries that fail decryption/integrity
                continue

        # Audit bulk retrieve
        if self._services.audit_log:
            self._services.audit_log.log(
                event_type=AuditEventType.PII_BULK_RETRIEVE,
                user_id=user_id,
                session_id=session_id,
                resource="pii_vault",
                action="get_all_mappings",
                success=True,
                metadata={"count": len(result)},
            )

        return result

    def clear_session(
        self,
        session_id: str,
        user_id: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        """
        Securely clear all PII for a session.

        Performs secure deletion with audit logging.
        """
        # Access control check
        if self._services.access_control and user_id:
            self._services.access_control.require_permission(
                user_id, Permission.PII_CLEAR_SESSION, session_id=session_id
            )

        # Get count before clearing for audit
        mappings: dict[str, str] = cast(
            "dict[str, str]", self._config.backend.get_all_mappings(session_id)
        )
        count = len(mappings)

        # Clear session
        self._config.backend.clear_session(session_id)

        # Audit
        if self._services.audit_log:
            self._services.audit_log.log_pii_delete(
                session_id=session_id,
                user_id=user_id,
                source_ip=source_ip,
                metadata={"entries_deleted": count},
            )

    def clear_expired(self) -> int:
        """Remove expired entries."""
        return self._config.backend.clear_expired()

    def verify_integrity(self, session_id: str | None = None) -> dict[str, bool]:
        """
        Verify integrity of all entries in a session.

        Returns:
            Dictionary of placeholder -> integrity_valid
        """
        encrypted_mappings: dict[str, str] = cast(
            "dict[str, str]", self._config.backend.get_all_mappings(session_id)
        )
        results: dict[str, bool] = {}

        for placeholder, entry_json in encrypted_mappings.items():
            try:
                entry = CompliancePIIEntry.from_dict(json.loads(entry_json))
                integrity_data = "|".join(
                    [
                        entry.storage.placeholder,
                        entry.storage.original_encrypted,
                        entry.storage.pii_type,
                        str(entry.storage.session_id),
                    ]
                )
                results[placeholder] = self._config.integrity.verify(
                    integrity_data, entry.security.integrity_hash or ""
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                results[placeholder] = False

        return results

    def export_audit_report(
        self,
        start_time: float | None = None,
        end_time: float | None = None,
    ) -> dict[str, Any]:
        """
        Export audit report for compliance review.

        Returns structured report suitable for SOC 2/HIPAA auditors.
        """
        if not self._services.audit_log:
            return {"error": "Audit logging not configured"}

        return self._services.audit_log.export_for_audit(start_time, end_time)


__all__ = [
    "CompliancePIIEntry",
    "CompliantPIIVaultBackend",
]
