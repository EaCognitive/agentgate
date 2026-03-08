"""Transaction management with compensation-based rollback.

Provides saga-style transactions for tool execution: if a step in a
multi-tool workflow fails, compensation functions for previously
successful steps are called in reverse order.
"""

from __future__ import annotations

import asyncio
import inspect
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable, Generator, AsyncGenerator

from .trace import Trace, TraceStatus
from .exceptions import TransactionFailed


@dataclass
class TransactionState:
    """State for an active transaction."""

    is_active: bool = False
    traces: list[Trace] = field(default_factory=list)
    compensations: dict[str, Callable[..., Any]] = field(
        default_factory=dict,
    )


class TransactionManager:
    """Manages transactional tool execution with rollback support.

    Tracks traces produced during a transaction and invokes registered
    compensation functions in reverse order when a step fails.

    Example:
        txn = TransactionManager()
        with txn.transaction():
            # ... execute tools, record traces via txn.record_trace() ...
            pass
    """

    def __init__(self) -> None:
        """Initialize the transaction manager with inactive state."""
        self._state = TransactionState()

    @property
    def is_active(self) -> bool:
        """Whether a transaction is currently in progress."""
        return self._state.is_active

    @property
    def traces(self) -> list[Trace]:
        """Traces recorded during the current transaction."""
        return self._state.traces

    @property
    def compensations(self) -> dict[str, Callable[..., Any]]:
        """Registered compensation functions keyed by tool name."""
        return self._state.compensations

    def record_trace(self, trace: Trace) -> None:
        """Record a trace in the current transaction.

        Args:
            trace: The trace to record. Only recorded when a
                transaction is active.
        """
        if self._state.is_active:
            self._state.traces.append(trace)

    def set_compensation(
        self,
        tool_name: str,
        compensation: Callable[..., Any],
    ) -> None:
        """Register a compensation function for a tool.

        Args:
            tool_name: Name of the tool.
            compensation: Callable invoked during rollback with the
                tool's output as the single argument.
        """
        self._state.compensations[tool_name] = compensation

    def begin(self) -> None:
        """Begin a new transaction.

        Resets state and marks the transaction as active.
        """
        self._state = TransactionState(is_active=True)

    def commit(self) -> None:
        """Commit the current transaction.

        Clears transaction state without calling compensations.
        """
        self._state = TransactionState()

    def rollback(self) -> None:
        """Rollback the current transaction synchronously.

        Calls compensation functions for successful steps in reverse
        order. Compensation errors are recorded but do not halt the
        rollback process.
        """
        for trace in reversed(self._state.traces):
            if trace.result.status != TraceStatus.SUCCESS:
                continue
            compensation = self._state.compensations.get(trace.tool)
            if compensation:
                try:
                    compensation(trace.result.output)
                    trace.result.status = TraceStatus.COMPENSATED
                except (RuntimeError, OSError, TimeoutError) as err:
                    trace.result.error = f"Compensation failed: {err}"
        self._state = TransactionState()

    async def arollback(self) -> None:
        """Rollback the current transaction asynchronously.

        Supports both sync and async compensation functions.
        Compensation errors are recorded but do not halt the rollback.
        """
        await self._execute_compensations_async(self._state.traces)
        self._state = TransactionState()

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Synchronous transaction context manager.

        On exception, compensations for successful steps are called in
        reverse order, then ``TransactionFailed`` is raised with full
        context.

        Example:
            with txn.transaction():
                agent.call("create_user", name="Alice")
                agent.call("charge_card", amount=99.00)
        """
        self._state = TransactionState(is_active=True)
        try:
            yield
        except Exception as exc:
            completed = self._collect_completed()
            compensated = self._compensate_sync()
            failed_step = self._find_failed_step()
            raise TransactionFailed(
                message=(f"Transaction failed at '{failed_step}': {exc}"),
                failed_step=failed_step,
                completed_steps=completed,
                compensated_steps=compensated,
                traces=self._state.traces.copy(),
            ) from exc
        finally:
            self._state = TransactionState()

    @asynccontextmanager
    async def atransaction(self) -> AsyncGenerator[None, None]:
        """Asynchronous transaction context manager.

        On exception, compensations for successful steps are called in
        reverse order (supporting both sync and async compensations),
        then ``TransactionFailed`` is raised with full context.

        Example:
            async with txn.atransaction():
                await agent.acall("create_user", name="Alice")
                await agent.acall("charge_card", amount=99.00)
        """
        self._state = TransactionState(is_active=True)
        try:
            yield
        except Exception as exc:
            completed = self._collect_completed()
            compensated = await self._execute_compensations_async(
                self._state.traces,
            )
            failed_step = self._find_failed_step()
            raise TransactionFailed(
                message=(f"Transaction failed at '{failed_step}': {exc}"),
                failed_step=failed_step,
                completed_steps=completed,
                compensated_steps=compensated,
                traces=self._state.traces.copy(),
            ) from exc
        finally:
            self._state = TransactionState()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_completed(self) -> list[str]:
        """Return tool names of all successful traces."""
        return [t.tool for t in self._state.traces if t.result.status == TraceStatus.SUCCESS]

    def _find_failed_step(self) -> str:
        """Return the tool name of the first failed trace."""
        for trace in self._state.traces:
            if trace.result.status == TraceStatus.FAILED:
                return trace.tool
        return ""

    def _compensate_sync(self) -> list[str]:
        """Run sync compensations in reverse and return names."""
        compensated: list[str] = []
        for trace in reversed(self._state.traces):
            if trace.result.status != TraceStatus.SUCCESS:
                continue
            compensation = self._state.compensations.get(trace.tool)
            if compensation:
                try:
                    compensation(trace.result.output)
                    trace.result.status = TraceStatus.COMPENSATED
                    compensated.append(trace.tool)
                except (
                    RuntimeError,
                    OSError,
                    TimeoutError,
                ) as err:
                    trace.result.error = f"Compensation failed: {err}"
        return compensated

    async def _execute_compensations_async(
        self,
        traces: list[Trace],
    ) -> list[str]:
        """Run compensations (sync or async) in reverse order.

        Args:
            traces: Transaction traces to compensate.

        Returns:
            List of tool names that were successfully compensated.
        """
        compensated: list[str] = []
        for trace in reversed(traces):
            if trace.result.status != TraceStatus.SUCCESS:
                continue
            compensation = self._state.compensations.get(trace.tool)
            if compensation:
                try:
                    if inspect.iscoroutinefunction(compensation):
                        await compensation(trace.result.output)
                    else:
                        await asyncio.to_thread(
                            compensation,
                            trace.result.output,
                        )
                    trace.result.status = TraceStatus.COMPENSATED
                    compensated.append(trace.tool)
                except (
                    RuntimeError,
                    OSError,
                    TimeoutError,
                ) as err:
                    trace.result.error = f"Compensation failed: {err}"
        return compensated
