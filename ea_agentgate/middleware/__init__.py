"""Middleware exports for agent tool execution."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .base import FailureMode, Middleware, MiddlewareContext

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "Validator": ("ea_agentgate.middleware.validator", "Validator"),
    "RateLimiter": ("ea_agentgate.middleware.rate_limiter", "RateLimiter"),
    "CostTracker": ("ea_agentgate.middleware.cost_tracker", "CostTracker"),
    "AuditLog": ("ea_agentgate.middleware.audit_log", "AuditLog"),
    "HumanApproval": ("ea_agentgate.middleware.approval", "HumanApproval"),
    "DashboardReporter": ("ea_agentgate.middleware.dashboard", "DashboardReporter"),
    "SemanticValidator": (
        "ea_agentgate.middleware.semantic_validator",
        "SemanticValidator",
    ),
    "SemanticCache": ("ea_agentgate.middleware.semantic_cache", "SemanticCache"),
    "OTelExporter": ("ea_agentgate.middleware.otel_exporter", "OTelExporter"),
    "PIIVault": ("ea_agentgate.middleware.pii_vault", "PIIVault"),
    "PIIDetector": ("ea_agentgate.middleware.pii_vault", "PIIDetector"),
    "PIIEntity": ("ea_agentgate.middleware.pii_vault", "PIIEntity"),
    "PlaceholderManager": (
        "ea_agentgate.middleware.pii_vault",
        "PlaceholderManager",
    ),
    "DatasetRecorder": (
        "ea_agentgate.middleware.dataset_recorder",
        "DatasetRecorder",
    ),
    "DatasetRecorderContext": (
        "ea_agentgate.middleware.dataset_recorder",
        "DatasetRecorderContext",
    ),
    "RecordingConfig": ("ea_agentgate.middleware.dataset_recorder", "RecordingConfig"),
    "StatefulGuardrail": ("ea_agentgate.middleware.guardrail", "StatefulGuardrail"),
    "PromptGuardMiddleware": (
        "ea_agentgate.middleware.prompt_guard",
        "PromptGuardMiddleware",
    ),
    "warmup_prompt_guard": (
        "ea_agentgate.middleware.prompt_guard",
        "warmup_prompt_guard",
    ),
    "FeedbackCollector": (
        "ea_agentgate.middleware.feedback_collector",
        "FeedbackCollector",
    ),
    "FeedbackRecord": ("ea_agentgate.feedback.models", "FeedbackRecord"),
    "PolicyMiddleware": (
        "ea_agentgate.middleware.policy_middleware",
        "PolicyMiddleware",
    ),
    "AdmissibilityDeniedError": (
        "ea_agentgate.middleware.proof_middleware",
        "AdmissibilityDeniedError",
    ),
    "ProofCarryingMiddleware": (
        "ea_agentgate.middleware.proof_middleware",
        "ProofCarryingMiddleware",
    ),
}

__all__ = ["FailureMode", "Middleware", "MiddlewareContext", *_LAZY_EXPORTS]


def __getattr__(name: str) -> Any:
    """Resolve middleware exports lazily."""
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        module = import_module(module_name)
        return getattr(module, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
