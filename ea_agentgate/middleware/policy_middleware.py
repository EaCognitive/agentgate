"""Policy-as-Code middleware for declarative guardrails.

Integrates the PolicyEngine into the middleware chain for request
evaluation against JSON-based security policies.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, TYPE_CHECKING

from .base import Middleware, MiddlewareContext
from ..exceptions import GuardrailViolationError

if TYPE_CHECKING:
    from ..security.policy_engine import PolicyEngine, PolicyDecision

_LOG = logging.getLogger(__name__)


class PolicyMiddleware(Middleware):
    """Middleware that evaluates requests against policy engine rules.

    Converts MiddlewareContext to request context and evaluates against
    loaded policy sets. Supports enforce and shadow modes.

    Example:
        from ea_agentgate.security.policy_engine import PolicyEngine

        engine = PolicyEngine()
        policy_set = engine.load_policy_from_file("policies/default.json")
        engine.load_policy_set(policy_set)

        middleware = PolicyMiddleware(
            engine=engine,
            policy_set_id="default",
            mode="enforce",
        )

        agent = Agent(middleware=[middleware])
    """

    def __init__(
        self,
        *,
        engine: "PolicyEngine",
        policy_set_id: str | None = None,
        mode: str = "enforce",
        on_deny: str = "block",
    ) -> None:
        """Initialize policy middleware.

        Args:
            engine: PolicyEngine instance with loaded policy sets.
            policy_set_id: Specific policy set ID to evaluate.
                If None, evaluates against all loaded sets.
            mode: "enforce" blocks violations, "shadow" logs only.
            on_deny: "block" raises exception, "log" logs warning.
        """
        super().__init__()
        self._engine = engine
        self._policy_set_id = policy_set_id
        self._mode = mode
        self._on_deny = on_deny

    def before(self, ctx: MiddlewareContext) -> None:
        """Evaluate request against policy engine before tool execution.

        Builds request context from middleware context and evaluates
        against the configured policy set(s).

        Args:
            ctx: Middleware context.

        Raises:
            GuardrailViolationError: When policy denies request in
                enforce mode with on_deny="block".
        """
        request_context = self._build_request_context(ctx)

        if self._policy_set_id is not None:
            decision = self._engine.evaluate(
                policy_set_id=self._policy_set_id,
                request_context=request_context,
            )
        else:
            decision = self._engine.evaluate_all(
                request_context=request_context,
            )

        self._store_decision(ctx, decision)
        self._enforce_decision(ctx, decision)

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async version of before hook.

        Runs policy evaluation in thread pool to avoid blocking
        the event loop.

        Args:
            ctx: Middleware context.
        """
        await asyncio.to_thread(self.before, ctx)

    def _build_request_context(
        self,
        ctx: MiddlewareContext,
    ) -> dict[str, Any]:
        """Convert MiddlewareContext to policy evaluation context.

        Args:
            ctx: Middleware context.

        Returns:
            Dictionary with nested structure for policy evaluation.
        """
        user_data: dict[str, Any] = {}
        if ctx.user_id:
            user_data["id"] = ctx.user_id

        session_data: dict[str, Any] = {}
        if ctx.session_id:
            session_data["id"] = ctx.session_id

        agent_data: dict[str, Any] = {}
        if ctx.agent_id:
            agent_data["id"] = ctx.agent_id

        return {
            "request": {
                "tool": ctx.tool,
                "inputs": ctx.inputs,
                "user": user_data,
                "session": session_data,
                "agent": agent_data,
                "metadata": ctx.metadata,
            }
        }

    @staticmethod
    def _store_decision(
        ctx: MiddlewareContext,
        decision: "PolicyDecision",
    ) -> None:
        """Store policy decision in context metadata.

        Args:
            ctx: Middleware context.
            decision: Policy evaluation decision.
        """
        ctx.metadata["policy_decision"] = {
            "allowed": decision.allowed,
            "effect": decision.effect.value,
            "matched_rules": decision.matched_rules,
            "reason": decision.reason,
            "policy_set_id": decision.policy_set_id,
            "evaluation_time_ms": decision.evaluation_time_ms,
        }

    def _enforce_decision(
        self,
        ctx: MiddlewareContext,
        decision: "PolicyDecision",
    ) -> None:
        """Enforce or log policy decision based on mode.

        Args:
            ctx: Middleware context.
            decision: Policy evaluation decision.

        Raises:
            GuardrailViolationError: When request is denied in
                enforce mode with on_deny="block".
        """
        if decision.allowed:
            return

        if self._mode == "shadow":
            _LOG.warning(
                "SHADOW_POLICY_VIOLATION: policy=%s tool=%s reason=%s",
                decision.policy_set_id,
                ctx.tool,
                decision.reason,
            )
            ctx.metadata["policy_shadow_violation"] = True
            return

        if self._on_deny == "log":
            _LOG.error(
                "POLICY_VIOLATION: policy=%s tool=%s reason=%s",
                decision.policy_set_id,
                ctx.tool,
                decision.reason,
            )
            return

        ctx.trace.block(decision.reason, self.name)
        raise GuardrailViolationError(
            decision.reason,
            details={
                "policy_id": decision.policy_set_id,
                "attempted_action": ctx.tool,
            },
            middleware=self.name,
            tool=ctx.tool,
            trace_id=ctx.trace.id,
        )


__all__ = [
    "PolicyMiddleware",
]
