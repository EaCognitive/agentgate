"""Public package surface for AgentGate.

Keep the top-level import lightweight so ``import ea_agentgate`` works
from a base wheel install without requiring optional provider, crypto,
or server dependencies. Public symbols are loaded lazily on demand.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from ._version import __version__

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "Agent": ("ea_agentgate.agent", "Agent"),
    "ToolDef": ("ea_agentgate.tool_registry", "ToolDef"),
    "providers": ("ea_agentgate", "providers"),
    "Trace": ("ea_agentgate.trace", "Trace"),
    "TraceStatus": ("ea_agentgate.trace", "TraceStatus"),
    "UniversalClient": ("ea_agentgate.client", "UniversalClient"),
    "AgentGate": ("ea_agentgate.client", "UniversalClient"),
    "CompletionResult": ("ea_agentgate.client", "CompletionResult"),
    "AllProvidersFailedError": ("ea_agentgate.client", "AllProvidersFailedError"),
    "Metadata": ("ea_agentgate.client", "Metadata"),
    "TokenUsage": ("ea_agentgate.client", "TokenUsage"),
    "Performance": ("ea_agentgate.client", "Performance"),
    "AgentGateError": ("ea_agentgate.exceptions", "AgentGateError"),
    "AgentSafetyError": ("ea_agentgate.exceptions", "AgentSafetyError"),
    "ValidationError": ("ea_agentgate.exceptions", "ValidationError"),
    "RateLimitError": ("ea_agentgate.exceptions", "RateLimitError"),
    "BudgetExceededError": ("ea_agentgate.exceptions", "BudgetExceededError"),
    "ApprovalRequired": ("ea_agentgate.exceptions", "ApprovalRequired"),
    "ApprovalDenied": ("ea_agentgate.exceptions", "ApprovalDenied"),
    "ApprovalTimeout": ("ea_agentgate.exceptions", "ApprovalTimeout"),
    "TransactionFailed": ("ea_agentgate.exceptions", "TransactionFailed"),
    "GuardrailViolationError": ("ea_agentgate.exceptions", "GuardrailViolationError"),
    "check_admissibility": ("ea_agentgate.verification", "check_admissibility"),
    "verify_certificate": ("ea_agentgate.verification", "verify_certificate"),
    "verify_plan": ("ea_agentgate.verification", "verify_plan"),
    "AdmissibilityResult": ("ea_agentgate.verification", "AdmissibilityResult"),
    "CertificateVerificationResult": (
        "ea_agentgate.verification",
        "CertificateVerificationResult",
    ),
    "PlanVerificationResult": ("ea_agentgate.verification", "PlanVerificationResult"),
}

__all__ = [*_LAZY_EXPORTS, "__version__"]


def __getattr__(name: str) -> Any:
    """Resolve public exports lazily."""
    if name == "providers":
        return import_module("ea_agentgate.providers")
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        module = import_module(module_name)
        return getattr(module, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
