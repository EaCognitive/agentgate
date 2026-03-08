"""Stateful temporal guardrail middleware."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .base import Middleware, MiddlewareContext
from ..exceptions import GuardrailViolationError
from ..security.policy import (
    Policy,
    PolicyMode,
    FailureMode,
    load_policy_from_file,
)

if TYPE_CHECKING:
    from ..backends.guardrail_backend import (
        GuardrailBackend,
        AsyncGuardrailBackend,
        TransitionResult,
    )

_LOG = logging.getLogger(__name__)

_DEFAULT_SESSION = "default"


class StatefulGuardrail(Middleware):
    """Stateful temporal guardrail middleware.

    Tracks agent session state and enforces temporal constraints
    (cooldowns, frequency limits, exclusion windows) on tool
    execution.

    Supports enforce mode (block violations) and shadow mode
    (log-only).

    Example:
        from ea_agentgate.security.policy import (
            load_policy_from_file,
            PolicyMode,
        )
        from ea_agentgate.backends import MemoryGuardrailBackend

        guardrail = StatefulGuardrail(
            policy="policy.json",
            backend=MemoryGuardrailBackend(),
        )

        agent = Agent(middleware=[guardrail])
    """

    def __init__(
        self,
        *,
        policy: Policy | str | Path,
        backend: "GuardrailBackend",
        async_backend: "AsyncGuardrailBackend | None" = None,
        mode: PolicyMode | None = None,
        failure_mode: FailureMode = FailureMode.CLOSED,
    ) -> None:
        """Initialize stateful guardrail.

        Args:
            policy: Policy object or path to a JSON policy file.
            backend: Synchronous guardrail backend.
            async_backend: Optional async guardrail backend.
            mode: Override the policy's default mode. When None,
                the mode embedded in the policy is used.
            failure_mode: How to handle backend failures. CLOSED
                blocks on failure; OPEN permits on failure.
        """
        super().__init__()
        if isinstance(policy, (str, Path)):
            self._policy = load_policy_from_file(policy)
        else:
            self._policy = policy

        self._backend = backend
        self._async_backend = async_backend
        self._mode = mode if mode is not None else self._policy.mode
        self._failure_mode = failure_mode

    # -----------------------------------------------------------------
    # Sync Hooks
    # -----------------------------------------------------------------

    def before(self, ctx: MiddlewareContext) -> None:
        """Check guardrail policy before tool execution.

        Resolves the session, evaluates the state transition, and
        blocks or logs depending on the effective mode.
        """
        session_id = self._resolve_session(ctx)

        try:
            result = self._backend.check_and_transition(
                session_id,
                ctx.tool,
                self._policy,
                self._mode,
            )
        except (OSError, ConnectionError, TimeoutError) as exc:
            self._handle_backend_failure(exc, ctx)
            return

        self._store_result(ctx, result)
        self._evaluate_result(result, ctx)

    def after(
        self,
        ctx: MiddlewareContext,
        result: Any,
        error: Exception | None,
    ) -> None:
        """Log transition details after tool execution.

        Args:
            ctx: The middleware context.
            result: The tool's return value (None if error).
            error: The exception if tool failed (None if success).
        """
        guardrail_result = ctx.metadata.get("guardrail_result")
        if not guardrail_result:
            return

        _LOG.debug(
            "Guardrail transition: %s -> %s (tool=%s, allowed=%s)",
            guardrail_result.get("previous_state"),
            guardrail_result.get("new_state"),
            ctx.tool,
            guardrail_result.get("allowed"),
        )

    # -----------------------------------------------------------------
    # Async Hooks
    # -----------------------------------------------------------------

    def is_async_native(self) -> bool:
        """Return True if an async backend is configured."""
        return self._async_backend is not None

    async def abefore(self, ctx: MiddlewareContext) -> None:
        """Async check guardrail policy before tool execution.

        Uses the async backend when available; otherwise falls
        back to the sync implementation via a thread pool.
        """
        if self._async_backend is None:
            await asyncio.to_thread(self.before, ctx)
            return

        session_id = self._resolve_session(ctx)

        try:
            result = await self._async_backend.acheck_and_transition(
                session_id,
                ctx.tool,
                self._policy,
                self._mode,
            )
        except (OSError, ConnectionError, TimeoutError) as exc:
            self._handle_backend_failure(exc, ctx)
            return

        self._store_result(ctx, result)
        self._evaluate_result(result, ctx)

    # -----------------------------------------------------------------
    # Private Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _resolve_session(ctx: MiddlewareContext) -> str:
        """Resolve the effective session identifier.

        Args:
            ctx: The middleware context.

        Returns:
            A non-empty session identifier string.
        """
        return ctx.session_id or ctx.agent_id or _DEFAULT_SESSION

    @staticmethod
    def _store_result(
        ctx: MiddlewareContext,
        result: "TransitionResult",
    ) -> None:
        """Persist transition result into context metadata.

        Args:
            ctx: The middleware context.
            result: The transition result from the backend.
        """
        ctx.metadata["guardrail_result"] = {
            "allowed": result.allowed,
            "previous_state": result.previous_state,
            "new_state": result.new_state,
            "reason": result.reason,
            "mode": result.mode,
            "violated_constraint": result.violated_constraint,
            "timestamp": result.timestamp,
        }

    def _evaluate_result(
        self,
        result: "TransitionResult",
        ctx: MiddlewareContext,
    ) -> None:
        """Evaluate transition result and enforce or log.

        Args:
            result: The transition result from the backend.
            ctx: The middleware context.

        Raises:
            GuardrailViolationError: When the transition is
                disallowed and the effective mode is ENFORCE.
        """
        if result.allowed:
            return

        if self._mode == PolicyMode.ENFORCE:
            ctx.trace.block(result.reason, self.name)
            raise GuardrailViolationError(
                result.reason,
                details={
                    "policy_id": self._policy.policy_id,
                    "current_state": result.previous_state,
                    "attempted_action": ctx.tool,
                    "violated_constraint": result.violated_constraint,
                },
                middleware=self.name,
                tool=ctx.tool,
                trace_id=ctx.trace.id,
            )

        # Shadow mode: log but do not block
        _LOG.warning(
            "SHADOW_VIOLATION: policy=%s state=%s action=%s reason=%s",
            self._policy.policy_id,
            result.previous_state,
            ctx.tool,
            result.reason,
        )
        ctx.metadata["guardrail_shadow_violation"] = True

    def _handle_backend_failure(
        self,
        exc: Exception,
        ctx: MiddlewareContext,
    ) -> None:
        """Handle backend communication failures.

        In CLOSED mode, raises a GuardrailViolationError to
        block the request. In OPEN mode, logs a warning and
        allows the request to proceed.

        Args:
            exc: The original backend exception.
            ctx: The middleware context.

        Raises:
            GuardrailViolationError: When failure_mode is CLOSED.
        """
        if self._failure_mode == FailureMode.CLOSED:
            raise GuardrailViolationError(
                f"Backend failure: {exc}",
                details={
                    "policy_id": self._policy.policy_id,
                    "attempted_action": ctx.tool,
                },
            ) from exc

        _LOG.warning(
            "Guardrail backend error (fail-open): %s",
            exc,
        )
        ctx.metadata["guardrail_backend_error"] = str(exc)


__all__ = [
    "StatefulGuardrail",
]
