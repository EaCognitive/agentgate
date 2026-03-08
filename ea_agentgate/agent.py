"""Main Agent class for safe tool execution."""

from __future__ import annotations

import asyncio
import functools
import inspect
import uuid
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import (
    Any,
    TypeVar,
    ParamSpec,
    cast,
)
from collections.abc import Callable, Generator, AsyncGenerator

from .trace import Trace
from .middleware.base import Middleware, MiddlewareChain, MiddlewareContext
from .tool_registry import ToolDef, ToolRegistry
from .transaction_manager import TransactionManager
from .verification_manager import VerificationConfig, VerificationInputs, VerificationManager

P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class AgentConfig:
    """Configuration for Agent identifiers."""

    agent_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    session_id: str | None = None
    user_id: str | None = None


_VERIFICATION_KWARG_ALIASES = {
    "formal_verification": "enabled",
    "principal": "principal",
    "tenant_id": "tenant_id",
    "verification_mode": "mode",
    "verification_provider": "provider",
    "formal_api_client": "api_client",
    "certificate_callback": "certificate_callback",
}
_VERIFICATION_INPUT_KWARG_ALIASES = {
    "policies": "policies",
    "grants": "grants",
    "revocations": "revocations",
    "obligations": "obligations",
    "environment": "environment",
}


def _build_verification_config(
    verification: VerificationConfig | None,
    overrides: dict[str, Any],
) -> VerificationConfig:
    """Merge legacy verification kwargs into a VerificationConfig."""
    config = verification or VerificationConfig()
    if not overrides:
        return config

    remaining = dict(overrides)
    updated_fields: dict[str, Any] = {}
    for legacy_name, field_name in _VERIFICATION_KWARG_ALIASES.items():
        if legacy_name in remaining:
            updated_fields[field_name] = remaining.pop(legacy_name)
    input_updates: dict[str, Any] = {}
    for legacy_name, field_name in _VERIFICATION_INPUT_KWARG_ALIASES.items():
        if legacy_name in remaining:
            input_updates[field_name] = remaining.pop(legacy_name)

    if remaining:
        unknown_args = ", ".join(sorted(remaining))
        raise TypeError(f"Unexpected verification arguments: {unknown_args}")
    if input_updates:
        verification_inputs = verification.inputs if verification else VerificationInputs()
        updated_fields["inputs"] = replace(verification_inputs, **input_updates)
    return replace(config, **updated_fields)


def _convert_args_to_kwargs(
    tool_def: ToolDef,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Convert positional args to keyword args using tool signature.

    Inspects the function signature of the tool and maps positional
    arguments to their corresponding parameter names.

    Args:
        tool_def: The tool definition whose function signature is used.
        args: Positional arguments to convert.
        kwargs: Existing keyword arguments (mutated in place).

    Returns:
        The updated kwargs dict with positional args merged in.
    """
    sig = inspect.signature(tool_def.fn)
    params = list(sig.parameters.keys())
    for i, arg in enumerate(args):
        if i < len(params):
            kwargs[params[i]] = arg
    return kwargs


class Agent:
    """Agent with safe, traced tool execution.

    Provides:
    - Automatic tracing of all tool calls
    - Middleware stack for validation, rate limiting, etc.
    - Transaction support with automatic rollback
    - Human-in-the-loop approvals
    - Optional formal verification with proof-carrying authorization

    Example:
        agent = Agent(
            middleware=[
                Validator(block_paths=["/"]),
                RateLimiter(max_calls=100, window="1m"),
                AuditLog(destination="audit.jsonl"),
            ]
        )

        @agent.tool
        def delete_file(path: str) -> str:
            os.remove(path)
            return f"Deleted {path}"

        # Execute with full tracing
        result = agent.call("delete_file", path="/tmp/cache.txt")

        # View traces
        for trace in agent.traces:
            print(trace)

    Formal Verification:
        agent = Agent(
            formal_verification=True,
            principal="agent:ops",
            policies=[{"effect": "deny", "action": "delete", "resource": "/prod/*"}],
        )

        result = agent.call("read_data", resource="/api/users")
        cert = agent.last_certificate  # DecisionCertificate dict
    """

    def __init__(
        self,
        middleware: list[Middleware] | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        user_id: str | None = None,
        *,
        verification: VerificationConfig | None = None,
        **verification_kwargs: Any,
    ) -> None:
        """Initialize agent.

        Args:
            middleware: List of middleware to apply to all tool calls.
            agent_id: Unique identifier for this agent.
            session_id: Session identifier.
            user_id: User identifier.
            verification: Optional grouped formal verification config.
            **verification_kwargs: Backward-compatible formal verification
                keyword arguments such as
                ``formal_verification``, ``principal``, ``tenant_id``,
                ``verification_mode``, and ``formal_api_client``.
        """
        self.middleware = middleware or []
        self.config = AgentConfig(
            agent_id=agent_id or str(uuid.uuid4())[:8],
            session_id=session_id,
            user_id=user_id,
        )

        # Verification manager
        self._verification = VerificationManager(
            _build_verification_config(verification, verification_kwargs),
        )

        # Auto-inject ProofCarryingMiddleware when enabled
        proof_mw = self._verification.build_middleware()
        if proof_mw is not None:
            self.middleware = [proof_mw] + self.middleware

        self._tool_registry = ToolRegistry()
        self._traces: list[Trace] = []
        self._chain = MiddlewareChain(self.middleware)
        self.txn = TransactionManager()

    # ------------------------------------------------------------------
    # Identity properties
    # ------------------------------------------------------------------

    @property
    def agent_id(self) -> str:
        """Current agent identifier."""
        return self.config.agent_id

    @agent_id.setter
    def agent_id(self, value: str) -> None:
        self.config.agent_id = value

    @property
    def session_id(self) -> str | None:
        """Current session identifier."""
        return self.config.session_id

    @session_id.setter
    def session_id(self, value: str | None) -> None:
        self.config.session_id = value

    @property
    def user_id(self) -> str | None:
        """Current user identifier."""
        return self.config.user_id

    @user_id.setter
    def user_id(self, value: str | None) -> None:
        self.config.user_id = value

    # ------------------------------------------------------------------
    # Tool and trace accessors
    # ------------------------------------------------------------------

    @property
    def traces(self) -> list[Trace]:
        """Return a copy of all traces from this agent."""
        return self._traces.copy()

    @property
    def tools(self) -> dict[str, ToolDef]:
        """Return registered tools as a dict copy."""
        return self._tool_registry.tools

    @property
    def formal_verification(self) -> bool:
        """Whether formal verification is enabled."""
        return self._verification.enabled

    @property
    def last_certificate(self) -> dict[str, Any] | None:
        """Most recent DecisionCertificate from formal verification.

        Returns ``None`` if formal verification is disabled or no tool
        call has been made yet.

        The dict contains:
        - ``decision_id``: Unique certificate ID
        - ``result``: ``"ADMISSIBLE"`` or ``"INADMISSIBLE"``
        - ``proof_type``: ``"CONSTRUCTIVE_TRACE"`` / ``"UNSAT_CORE"``
          / ``"COUNTEREXAMPLE"``
        - ``theorem_hash``: SHA-256 of the theorem expression
        - ``alpha_hash``: SHA-256 of the action context
        - ``gamma_hash``: SHA-256 of the knowledge base
        - ``signature``: Ed25519 signature (base64)
        """
        return self._verification.last_certificate

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_last_certificate(self) -> bool:
        """Verify the most recent certificate's signature and theorem hash.

        Returns:
            ``True`` if the certificate is valid, ``False`` if invalid
            or no certificate exists.
        """
        return self._verification.verify_last_certificate()

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def tool(
        self,
        fn: Callable[P, R] | None = None,
        *,
        name: str | None = None,
        requires_approval: bool = False,
        cost: float | None = None,
    ) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorator to register a tool with the agent.

        Example:
            @agent.tool
            def my_tool(x: int) -> int:
                return x * 2

            @agent.tool(requires_approval=True, cost=0.10)
            def expensive_tool(data: str) -> str:
                ...
        """

        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            """Register *func* in the tool registry."""
            tool_name = name or func.__name__
            self._tool_registry.register(
                tool_name,
                func,
                requires_approval=requires_approval,
                cost=cost,
            )

            @functools.wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                """Delegate to ``Agent.call`` for traced execution."""
                return cast(R, self.call(tool_name, *args, **kwargs))

            return wrapper

        if fn is not None:
            return decorator(fn)
        return decorator

    def register_tool(
        self,
        name: str,
        fn: Callable[..., Any],
        requires_approval: bool = False,
        cost: float | None = None,
    ) -> None:
        """Register a tool with the agent.

        Args:
            name: Name to register the tool under.
            fn: The tool function.
            requires_approval: Whether tool requires human approval.
            cost: Optional cost per invocation.
        """
        self._tool_registry.register(
            name,
            fn,
            requires_approval=requires_approval,
            cost=cost,
        )

    def compensate(
        self,
        tool_name: str,
        compensation: Callable[..., Any],
    ) -> None:
        """Register a compensation function for a tool.

        Compensation is called during rollback if the tool succeeded
        but a later step failed.

        Args:
            tool_name: Name of the tool.
            compensation: Callable invoked with the tool output during
                rollback.

        Example:
            agent.compensate(
                "create_user",
                lambda ctx: db.delete_user(ctx["user_id"]),
            )
        """
        self.txn.set_compensation(tool_name, compensation)
        self._tool_registry.set_compensation(tool_name, compensation)

    # ------------------------------------------------------------------
    # Synchronous execution
    # ------------------------------------------------------------------

    def call(self, tool_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a tool by name with tracing and middleware.

        Args:
            tool_name: Name of the registered tool.
            *args: Positional arguments (converted to kwargs via sig).
            **kwargs: Keyword arguments.

        Returns:
            Tool's return value.

        Raises:
            Various exceptions from middleware (ValidationError, etc.)
            RuntimeError: If tool is async and called from async context.
        """
        tool_def = self._tool_registry.get(tool_name)

        # Async tool guard
        if inspect.iscoroutinefunction(tool_def.fn):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(
                    self.acall(tool_name, *args, **kwargs),
                )
            raise RuntimeError(
                f"Tool '{tool_name}' is async. Use agent.acall() "
                f"instead of agent.call() when in an async context."
            )

        if args:
            kwargs = _convert_args_to_kwargs(tool_def, args, kwargs)

        trace, ctx = self._prepare_call(tool_name, tool_def, kwargs)

        trace.start()
        try:
            result = self._chain.execute(ctx, tool_def.fn)
            trace.succeed(result)
        except Exception as exc:
            self._verification.extract_certificate(ctx)
            trace.fail(str(exc))
            self._traces.append(trace)
            self.txn.record_trace(trace)
            raise

        self._verification.extract_certificate(ctx)
        self._traces.append(trace)
        self.txn.record_trace(trace)
        return result

    # ------------------------------------------------------------------
    # Transaction delegation
    # ------------------------------------------------------------------

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Execute tools in a transaction with automatic rollback.

        If any tool fails, all previously successful tools have
        their compensation functions called in reverse order.

        Example:
            with agent.transaction():
                agent.call("create_user", email="test@example.com")
                agent.call("charge_card", amount=99.00)
        """
        with self.txn.transaction():
            yield

    def rollback(self) -> None:
        """Rollback the current transaction synchronously."""
        self.txn.rollback()

    # ------------------------------------------------------------------
    # Trace management
    # ------------------------------------------------------------------

    def record_trace(self, trace: Trace) -> None:
        """Record a trace from an integration or external validation path."""
        self._record_trace(trace)

    def clear_traces(self) -> None:
        """Clear all traces."""
        self._traces.clear()

    def _record_trace(self, trace: Trace) -> None:
        """Record a trace and keep transaction state in sync."""
        self._traces.append(trace)
        self.txn.record_trace(trace)

    # ------------------------------------------------------------------
    # Middleware management
    # ------------------------------------------------------------------

    def add_middleware(self, middleware: Middleware) -> None:
        """Add middleware to the stack."""
        self.middleware.append(middleware)
        self._chain = MiddlewareChain(self.middleware)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _close(self) -> None:
        """Close the agent and release middleware resources."""
        for mw in self.middleware:
            closer = getattr(mw, "close", None)
            if callable(closer):
                closer()

    def __enter__(self) -> "Agent":
        """Enter context manager."""
        return self

    def __exit__(self, *_: Any) -> None:
        """Exit context manager and close resources."""
        self._close()

    # ------------------------------------------------------------------
    # Async methods
    # ------------------------------------------------------------------

    async def acall(
        self,
        tool_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Async call a tool by name with tracing and middleware.

        Supports both sync and async tool functions. This method should
        be used when running in an async context (e.g., FastAPI).

        Args:
            tool_name: Name of the registered tool.
            *args: Positional arguments (converted to kwargs via sig).
            **kwargs: Keyword arguments.

        Returns:
            Tool's return value.

        Example:
            result = await agent.acall(
                "fetch_data", url="https://api.example.com",
            )
        """
        tool_def = self._tool_registry.get(tool_name)

        if args:
            kwargs = _convert_args_to_kwargs(tool_def, args, kwargs)

        trace, ctx = self._prepare_call(tool_name, tool_def, kwargs)

        trace.start()
        try:
            result = await self._chain.aexecute(ctx, tool_def.fn)
            trace.succeed(result)
        except Exception as exc:
            self._verification.extract_certificate(ctx)
            trace.fail(str(exc))
            self._traces.append(trace)
            self.txn.record_trace(trace)
            raise

        self._verification.extract_certificate(ctx)
        self._traces.append(trace)
        self.txn.record_trace(trace)
        return result

    @asynccontextmanager
    async def atransaction(self) -> AsyncGenerator[None, None]:
        """Async transaction with automatic rollback.

        If any tool fails, all previously successful tools have
        their compensation functions called in reverse order.
        Supports both sync and async compensation functions.

        Example:
            async with agent.atransaction():
                await agent.acall("create_user", email="test@example.com")
                await agent.acall("charge_card", amount=99.00)
        """
        async with self.txn.atransaction():
            yield

    async def arollback(self) -> None:
        """Async rollback the current transaction."""
        await self.txn.arollback()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _prepare_call(
        self,
        tool_name: str,
        tool_def: ToolDef,
        kwargs: dict[str, Any],
    ) -> tuple[Trace, MiddlewareContext]:
        """Build Trace and MiddlewareContext for a tool call.

        Args:
            tool_name: Name of the tool being called.
            tool_def: The tool definition.
            kwargs: Resolved keyword arguments.

        Returns:
            A (Trace, MiddlewareContext) tuple ready for execution.
        """
        trace = Trace(tool=tool_name, inputs=kwargs)
        trace.context.compensation = (
            tool_def.compensation.__name__ if tool_def.compensation else None
        )

        ctx = MiddlewareContext(
            tool=tool_name,
            inputs=kwargs,
            trace=trace,
            agent_id=self.config.agent_id,
            session_id=self.config.session_id,
            user_id=self.config.user_id,
            metadata={
                "requires_approval": tool_def.requires_approval,
            },
        )

        if tool_def.cost is not None:
            ctx.cost = tool_def.cost

        return trace, ctx
