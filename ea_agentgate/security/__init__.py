"""Security exports for AgentGate compliance and access control."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "EncryptionProvider": ("ea_agentgate.security.encryption", "EncryptionProvider"),
    "AESGCMEncryption": ("ea_agentgate.security.encryption", "AESGCMEncryption"),
    "generate_key": ("ea_agentgate.security.encryption", "generate_key"),
    "derive_key": ("ea_agentgate.security.encryption", "derive_key"),
    "IntegrityProvider": ("ea_agentgate.security.integrity", "IntegrityProvider"),
    "HMACIntegrity": ("ea_agentgate.security.integrity", "HMACIntegrity"),
    "ChainOfCustody": ("ea_agentgate.security.integrity", "ChainOfCustody"),
    "IntegrityRecord": ("ea_agentgate.security.integrity", "IntegrityRecord"),
    "TamperDetectedError": (
        "ea_agentgate.security.integrity",
        "TamperDetectedError",
    ),
    "compute_hmac": ("ea_agentgate.security.integrity", "compute_hmac"),
    "verify_hmac": ("ea_agentgate.security.integrity", "verify_hmac"),
    "ComplianceAuditLog": ("ea_agentgate.security.audit", "ComplianceAuditLog"),
    "AuditEvent": ("ea_agentgate.security.audit_models", "AuditEvent"),
    "AuditEventType": ("ea_agentgate.security.audit_models", "AuditEventType"),
    "secure_wipe_string": (
        "ea_agentgate.security.secure_delete",
        "secure_wipe_string",
    ),
    "secure_wipe_bytes": ("ea_agentgate.security.secure_delete", "secure_wipe_bytes"),
    "SecureString": ("ea_agentgate.security.secure_delete", "SecureString"),
    "SecureDict": ("ea_agentgate.security.secure_delete", "SecureDict"),
    "AccessControlProvider": (
        "ea_agentgate.security.access_control",
        "AccessControlProvider",
    ),
    "Permission": ("ea_agentgate.security.access_control", "Permission"),
    "Role": ("ea_agentgate.security.access_control", "Role"),
    "Roles": ("ea_agentgate.security.access_control", "Roles"),
    "SimpleRBAC": ("ea_agentgate.security.access_control", "SimpleRBAC"),
    "AccessDeniedError": (
        "ea_agentgate.security.access_control",
        "AccessDeniedError",
    ),
    "AuthenticationRequiredError": (
        "ea_agentgate.security.access_control",
        "AuthenticationRequiredError",
    ),
    "AccessContext": ("ea_agentgate.security.access_control", "AccessContext"),
    "ConditionOperator": ("ea_agentgate.security.policy_engine", "ConditionOperator"),
    "PolicyCondition": ("ea_agentgate.security.policy_engine", "PolicyCondition"),
    "PolicyDecision": ("ea_agentgate.security.policy_engine", "PolicyDecision"),
    "PolicyEffect": ("ea_agentgate.security.policy_engine", "PolicyEffect"),
    "PolicyEngine": ("ea_agentgate.security.policy_engine", "PolicyEngine"),
    "PolicyRule": ("ea_agentgate.security.policy_engine", "PolicyRule"),
    "PolicySet": ("ea_agentgate.security.policy_engine", "PolicySet"),
    "validate_policy_set": (
        "ea_agentgate.security.policy_engine",
        "validate_policy_set",
    ),
    "SecurityMiddleware": (
        "ea_agentgate.middleware.policy_middleware",
        "PolicyMiddleware",
    ),
}

__all__ = [*_LAZY_EXPORTS]


def __getattr__(name: str) -> Any:
    """Resolve security exports lazily."""
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        module = import_module(module_name)
        return getattr(module, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
