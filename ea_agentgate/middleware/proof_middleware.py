"""Proof-carrying authorization middleware.

Integrates the formal verification solver engine into the SDK middleware
chain so that every tool call receives a signed DecisionCertificate
before execution proceeds.

Modes:
    - ``enforce`` (default): block INADMISSIBLE calls, raise error with proof.
    - ``shadow``: log all decisions without blocking (gradual-rollout path).
"""

from __future__ import annotations

import asyncio
import logging
import os
from importlib import import_module
from typing import Any, Literal, TypedDict

from ea_agentgate.formal import (
    AlphaContext,
    DecisionCertificate,
    DecisionResult,
    GammaKnowledgeBase,
    canonical_json,
    sha256_hex,
)
from ea_agentgate.formal.helpers import extract_certificate_payload, extract_failed_predicates

from ..api_client import ApiError, DashboardClient
from .base import FailureMode, Middleware, MiddlewareContext

_LOG = logging.getLogger(__name__)
_LOCAL_ENVIRONMENTS = {"local", "development", "dev", "test"}


class AdmissibilityDecisionDetails(TypedDict):
    """Structured decision details attached to inadmissible outcomes."""

    decision_id: str
    result: str
    proof_type: str
    proof_payload: dict[str, Any]
    failed_predicates: list[str]


class ProofMiddlewareContext(TypedDict, total=False):
    """Structured formal context inputs for proof-carrying middleware."""

    policies: list[dict[str, Any]]
    grants: list[dict[str, Any]]
    revocations: list[dict[str, Any]]
    obligations: list[dict[str, Any]]
    environment: dict[str, Any]


_PROOF_CONTEXT_DEFAULTS: ProofMiddlewareContext = {
    "policies": [],
    "grants": [],
    "revocations": [],
    "obligations": [],
    "environment": {},
}


def _parse_proof_context(
    context: ProofMiddlewareContext | None,
    legacy_kwargs: dict[str, Any],
) -> ProofMiddlewareContext:
    """Merge legacy proof middleware kwargs into structured context data."""
    resolved: ProofMiddlewareContext = {
        "policies": [],
        "grants": [],
        "revocations": [],
        "obligations": [],
        "environment": {},
    }
    if context:
        if "policies" in context:
            resolved["policies"] = context["policies"]
        if "grants" in context:
            resolved["grants"] = context["grants"]
        if "revocations" in context:
            resolved["revocations"] = context["revocations"]
        if "obligations" in context:
            resolved["obligations"] = context["obligations"]
        if "environment" in context:
            resolved["environment"] = context["environment"]
    unknown_keys = set(legacy_kwargs) - set(_PROOF_CONTEXT_DEFAULTS)
    if unknown_keys:
        names = ", ".join(sorted(unknown_keys))
        raise TypeError(f"Unsupported proof middleware option(s): {names}")
    if "policies" in legacy_kwargs:
        resolved["policies"] = legacy_kwargs["policies"]
    if "grants" in legacy_kwargs:
        resolved["grants"] = legacy_kwargs["grants"]
    if "revocations" in legacy_kwargs:
        resolved["revocations"] = legacy_kwargs["revocations"]
    if "obligations" in legacy_kwargs:
        resolved["obligations"] = legacy_kwargs["obligations"]
    if "environment" in legacy_kwargs:
        resolved["environment"] = legacy_kwargs["environment"]
    return resolved


def _parse_remote_fallback_flag(legacy_kwargs: dict[str, Any]) -> bool:
    """Extract the optional remote fallback toggle from legacy kwargs."""
    return bool(legacy_kwargs.pop("remote_fallback_to_local", True))


def evaluate_admissibility(alpha: Any, gamma: Any):
    """Module-level wrapper to keep solver calls patchable in tests."""
    solver_engine = import_module("server.policy_governance.kernel.solver_engine")
    solver_evaluate = getattr(solver_engine, "evaluate_admissibility")
    return solver_evaluate(alpha, gamma)


def _runtime_environment() -> str:
    """Return normalized runtime environment string."""
    value = os.getenv("AGENTGATE_ENV", os.getenv("ENV", "development"))
    return value.strip().lower() or "development"


def _is_non_production_runtime() -> bool:
    """Return True when running in a local/dev/test runtime."""
    return _runtime_environment() in _LOCAL_ENVIRONMENTS


# ---------------------------------------------------------------------------
# Lightweight exception for INADMISSIBLE decisions
# ---------------------------------------------------------------------------


class AdmissibilityDeniedError(Exception):
    """Raised when the formal solver deems a tool call INADMISSIBLE.

    Attributes:
        decision_id: Unique certificate ID for traceability.
        result: ``"INADMISSIBLE"``
        proof_type: ``"COUNTEREXAMPLE"`` or ``"UNSAT_CORE"``
        proof_payload: Full proof artifact dict.
        failed_predicates: List of predicate names that failed.
    """

    def __init__(
        self,
        message: str,
        *,
        details: AdmissibilityDecisionDetails,
        tool: str | None = None,
        trace_id: str | None = None,
    ) -> None:
        self.decision_id = details["decision_id"]
        self.result = details["result"]
        self.proof_type = details["proof_type"]
        self.proof_payload = details["proof_payload"]
        self.failed_predicates = details["failed_predicates"]
        self.tool = tool
        self.trace_id = trace_id
        super().__init__(message)

    def __str__(self) -> str:
        parts = [
            f"Error: {super().__str__()}",
            f"Decision ID: {self.decision_id}",
            f"Result: {self.result}",
            f"Proof Type: {self.proof_type}",
            f"Failed Predicates: {', '.join(self.failed_predicates)}",
        ]
        if self.tool:
            parts.append(f"Tool: {self.tool}")
        if self.trace_id:
            parts.append(f"Trace ID: {self.trace_id}")
        parts.append(
            "Suggested Fix: Review the policy rules, delegation grants, or "
            "context constraints that caused the denial."
        )
        parts.append("Documentation: https://docs.agentgate.io/middleware/proof-carrying")
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Helper: build domain objects from middleware context
# ---------------------------------------------------------------------------


def _build_alpha(ctx: MiddlewareContext, *, principal: str, tenant_id: str | None):
    """Create an ``AlphaContext`` from the current middleware context."""
    runtime = {
        "agent_id": ctx.agent_id,
        "session_id": ctx.session_id,
        "user_id": ctx.user_id,
        **{k: v for k, v in ctx.metadata.items() if k.startswith("proof_")},
    }
    return AlphaContext.from_runtime(
        principal=principal,
        action=ctx.tool,
        resource=_resource_from_inputs(ctx.inputs),
        runtime_context=runtime,
        tenant_id=tenant_id,
    )


def _build_gamma(
    *,
    principal: str,
    tenant_id: str | None,
    policies: list[dict[str, Any]] | None,
    grants: list[dict[str, Any]] | None,
    revocations: list[dict[str, Any]] | None,
    obligations: list[dict[str, Any]] | None,
    environment: dict[str, Any] | None,
):
    """Create a ``GammaKnowledgeBase`` from agent configuration."""
    normalized_policies = _normalize_policies(policies or [])

    return GammaKnowledgeBase(
        principal=principal,
        tenant_id=tenant_id,
        policies=normalized_policies,
        active_grants=list(grants or []),
        active_revocations=list(revocations or []),
        obligations=list(obligations or []),
        environment=dict(environment or {}),
    )


def _extract_action_resource(
    conditions: list[Any],
    action: str,
    resource: str,
) -> tuple[str, str]:
    """Extract action and resource overrides from condition entries.

    Iterates over legacy condition dicts, updating action/resource
    when matching fields are found.

    Args:
        conditions: List of condition dicts from policy shorthand.
        action: Current action value to override.
        resource: Current resource value to override.

    Returns:
        Tuple of (action, resource) after applying condition overrides.
    """
    for condition in conditions:
        if not isinstance(condition, dict):
            continue

        field = str(condition.get("field", "")).strip().lower()
        operator = str(condition.get("operator", "")).strip().lower()
        value = condition.get("value")

        if field == "action":
            if isinstance(value, str) and value.strip():
                action = value.strip().lower()
            elif operator == "exists":
                action = "*"
        elif field in {"resource", "path", "endpoint"} and isinstance(value, str) and value.strip():
            resource = value.strip()

    return action, resource


def _build_policy_rule(
    effect: str,
    action: str,
    resource: str,
) -> dict[str, Any]:
    """Build a solver policy rule dict from normalized components.

    Args:
        effect: Policy effect (``"allow"`` or ``"deny"``).
        action: Resolved action string.
        resource: Resolved resource string.

    Returns:
        Rule dict suitable for the solver ``pre_rules`` list.
    """
    if effect == "allow":
        rule_type = "permit" if resource != "*" else "action_allow"
    else:
        rule_type = "deny" if resource != "*" else "action_deny"

    if rule_type in {"permit", "deny"}:
        return {
            "type": rule_type,
            "action": action,
            "resource": resource,
        }
    return {
        "type": rule_type,
        "action": action,
    }


def _normalize_policies(
    policies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize middleware policy shorthand into solver policy schema.

    Supports legacy middleware inputs such as:
    {"effect": "allow"|"deny", "conditions": [...]}
    by translating them to policy_json pre-rules understood by the solver.
    """
    normalized: list[dict[str, Any]] = []

    for policy in policies:
        if "policy_json" in policy:
            normalized.append(policy)
            continue

        effect = str(policy.get("effect", "")).strip().lower()
        if effect not in {"allow", "deny"}:
            normalized.append(policy)
            continue

        action = "*"
        resource = "*"

        action_value = policy.get("action")
        if isinstance(action_value, str) and action_value.strip():
            action = action_value.strip().lower()

        resource_value = policy.get("resource")
        if isinstance(resource_value, str) and resource_value.strip():
            resource = resource_value.strip()

        conditions = policy.get("conditions", [])
        if isinstance(conditions, list):
            action, resource = _extract_action_resource(
                conditions,
                action,
                resource,
            )

        rule = _build_policy_rule(effect, action, resource)

        normalized.append(
            {
                **policy,
                "policy_json": {
                    "pre_rules": [rule],
                    "post_rules": [],
                },
            }
        )

    return normalized


def _resource_from_inputs(inputs: dict[str, Any]) -> str:
    """Derive a canonical resource identifier from tool inputs.

    Heuristic ranking:
    1. Explicit ``resource`` key
    2. ``path`` / ``url`` / ``file``
    3. Serialized snapshot of all inputs
    """
    for key in ("resource", "path", "url", "file", "endpoint", "target"):
        if key in inputs and isinstance(inputs[key], str):
            return str(inputs[key])
    # Fallback: deterministic representation
    return f"inputs:{sha256_hex(canonical_json(inputs))}"


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class ProofCarryingMiddleware(Middleware):
    """Proof-carrying authorization middleware.

    Every tool call is evaluated against the formal solver engine.
    A signed ``DecisionCertificate`` is attached to the middleware
    context metadata so downstream middleware (audit log, dashboard
    reporter, etc.) can access it.

    Example::

        from ea_agentgate import Agent
        from ea_agentgate.middleware import ProofCarryingMiddleware

        agent = Agent(
            middleware=[
                ProofCarryingMiddleware(
                    principal="agent:customer-support",
                    tenant_id="acme-corp",
                ),
            ]
        )

    Args:
        principal: Identity string for the agent (e.g. ``"agent:ops"``).
        tenant_id: Optional tenant scope for multi-tenant deployments.
        mode: ``"enforce"`` (block if INADMISSIBLE) or ``"shadow"``
            (log only).
        verification_provider: Formal evaluation backend:
            ``"remote"`` (canonical API kernel path) or
            ``"local"`` (offline solver path).
        policies: Policy rule dicts fed into `GammaKnowledgeBase.policies`.
        grants: Active delegation grants.
        revocations: Active revocations.
        obligations: Obligation constraints.
        environment: Extra environment facts for context-bound evaluation.
        api_client: Optional API client for remote verification provider.
        remote_fallback_to_local: Allow local fallback in non-production when
            remote provider has no auth token.
        failure_mode: Behaviour on solver errors (default: FAIL_CLOSED).
    """

    def __init__(
        self,
        *,
        principal: str,
        tenant_id: str | None = None,
        mode: str = "enforce",
        verification_provider: Literal["remote", "local"] = "remote",
        context: ProofMiddlewareContext | None = None,
        api_client: DashboardClient | None = None,
        failure_mode: FailureMode = FailureMode.FAIL_CLOSED,
        **legacy_kwargs: Any,
    ) -> None:
        super().__init__(failure_mode=failure_mode)
        if verification_provider not in {"remote", "local"}:
            raise ValueError("verification_provider must be 'remote' or 'local'")
        remote_fallback_to_local = _parse_remote_fallback_flag(legacy_kwargs)
        self._principal = principal
        self._tenant_id = tenant_id
        self._mode = mode
        self._verification_provider = verification_provider
        self._context_data = _parse_proof_context(context, legacy_kwargs)
        self._api_client = api_client
        self._remote_fallback_to_local = remote_fallback_to_local

    # ------------------------------------------------------------------ hooks

    def _get_api_client(self) -> DashboardClient:
        if self._api_client is None:
            self._api_client = DashboardClient()
        return self._api_client

    @property
    def _policies(self) -> list[dict[str, Any]]:
        """Return configured policy inputs for local solver execution."""
        return self._context_data["policies"]

    @property
    def _grants(self) -> list[dict[str, Any]]:
        """Return active delegation grants."""
        return self._context_data["grants"]

    @property
    def _revocations(self) -> list[dict[str, Any]]:
        """Return active delegation revocations."""
        return self._context_data["revocations"]

    @property
    def _obligations(self) -> list[dict[str, Any]]:
        """Return configured obligation facts."""
        return self._context_data["obligations"]

    @property
    def _environment(self) -> dict[str, Any]:
        """Return environment facts used during local evaluation."""
        return self._context_data["environment"]

    def _should_use_remote_provider(self) -> bool:
        if self._verification_provider == "local":
            return False
        if not self._remote_fallback_to_local:
            return True
        if not _is_non_production_runtime():
            return True
        force_remote = os.getenv("AGENTGATE_FORCE_REMOTE_VERIFICATION", "").strip().lower()
        if force_remote in {"1", "true", "yes", "on"}:
            return True
        _LOG.warning(
            "Formal verification provider fallback: using local solver path in "
            "non-production runtime. Set AGENTGATE_FORCE_REMOTE_VERIFICATION=true "
            "to force remote provider."
        )
        return False

    def _evaluate_local(self, ctx: MiddlewareContext):
        alpha = _build_alpha(ctx, principal=self._principal, tenant_id=self._tenant_id)
        gamma = _build_gamma(
            principal=self._principal,
            tenant_id=self._tenant_id,
            policies=self._policies,
            grants=self._grants,
            revocations=self._revocations,
            obligations=self._obligations,
            environment=self._environment,
        )
        return evaluate_admissibility(alpha, gamma)

    def _evaluate_remote(self, ctx: MiddlewareContext):
        runtime_context = {
            "agent_id": ctx.agent_id,
            "session_id": ctx.session_id,
            "user_id": ctx.user_id,
            **{k: v for k, v in ctx.metadata.items() if k.startswith("proof_")},
        }
        runtime_context.setdefault("authenticated", True)
        runtime_context.setdefault("direct_access", True)
        runtime_context.setdefault("direct_permit", True)
        runtime_context.setdefault("execution_phase", "confirm")
        runtime_context.setdefault("preview_confirmed", True)

        client = self._get_api_client()
        try:
            response = client.formal_evaluate_admissibility(
                principal=self._principal,
                action=ctx.tool,
                resource=_resource_from_inputs(ctx.inputs),
                runtime_context=runtime_context,
                tenant_id=self._tenant_id,
            )
            certificate_payload = response.get("certificate", {})
            if not isinstance(certificate_payload, dict):
                raise RuntimeError(
                    "Remote formal verification returned invalid certificate payload"
                )
            return DecisionCertificate.model_validate(certificate_payload)
        except ApiError as exc:
            cert_payload = extract_certificate_payload(exc.detail)
            if cert_payload is None:
                raise RuntimeError(f"Remote formal verification request failed: {exc}") from exc
            return DecisionCertificate.model_validate(cert_payload)
        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Remote formal verification failed: {exc}") from exc

    def before(self, ctx: MiddlewareContext) -> None:
        """Evaluate admissibility before tool execution.

        On ADMISSIBLE: attaches certificate to ``ctx.metadata``.
        On INADMISSIBLE (enforce mode): raises ``AdmissibilityDeniedError``.
        On INADMISSIBLE (shadow mode): logs warning, attaches certificate.
        """
        use_remote_provider = self._should_use_remote_provider()
        try:
            if use_remote_provider:
                certificate = self._evaluate_remote(ctx)
            else:
                certificate = self._evaluate_local(ctx)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            if self.failure_mode == FailureMode.FAIL_CLOSED:
                _LOG.exception("ProofCarryingMiddleware: solver error, blocking call")
                raise
            _LOG.warning(
                "ProofCarryingMiddleware: solver error, failing open",
                exc_info=True,
            )
            ctx.metadata["proof_status"] = "SOLVER_ERROR"
            return

        # Attach proof artifacts to context for downstream consumption
        self._store_certificate(ctx, certificate)
        ctx.metadata["proof_provider"] = "remote" if use_remote_provider else "local"

        if certificate.result == DecisionResult.INADMISSIBLE:
            failed = extract_failed_predicates(certificate)
            if self._mode == "enforce":
                ctx.trace.block(f"INADMISSIBLE: failed predicates {failed}", self.name)
                raise AdmissibilityDeniedError(
                    f"Tool call '{ctx.tool}' is INADMISSIBLE: predicates {failed} failed",
                    details={
                        "decision_id": str(certificate.decision_id),
                        "result": certificate.result.value,
                        "proof_type": certificate.proof_type.value,
                        "proof_payload": certificate.proof_payload,
                        "failed_predicates": failed,
                    },
                    tool=ctx.tool,
                    trace_id=ctx.trace.id,
                )
            # Shadow mode — log but do not block
            _LOG.warning(
                "SHADOW_PROOF_DENIAL: tool=%s principal=%s predicates=%s decision_id=%s",
                ctx.tool,
                self._principal,
                failed,
                certificate.decision_id,
            )
            ctx.metadata["proof_shadow_violation"] = True

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async before hook — runs solver in thread pool."""
        await asyncio.to_thread(self.before, ctx)

    def after(self, ctx: MiddlewareContext, result: Any, error: Exception | None) -> None:
        """Post-execution hook: log certificate outcome."""
        cert_data = ctx.metadata.get("proof_certificate")
        if cert_data is None:
            return
        _LOG.debug(
            "PROOF_AFTER: tool=%s result=%s decision_id=%s",
            ctx.tool,
            cert_data.get("result"),
            cert_data.get("decision_id"),
        )

    # ------------------------------------------------------------------ internals

    @staticmethod
    def _store_certificate(ctx: MiddlewareContext, certificate) -> None:
        """Attach full certificate to ``ctx.metadata``.

        Stores the complete model dump so that downstream consumers
        (e.g. ``Agent.last_certificate``, ``verify_certificate()``) can
        reconstruct or verify the certificate without data loss.
        """
        ctx.metadata["proof_certificate"] = certificate.model_dump(mode="json")
        ctx.metadata["proof_status"] = certificate.result.value


__all__ = [
    "AdmissibilityDeniedError",
    "ProofCarryingMiddleware",
]
