"""Dashboard reporter middleware - sends traces to the dashboard API."""

from __future__ import annotations

import os
import uuid
import threading
from importlib import import_module
from types import ModuleType
from typing import Any

from .base import Middleware, MiddlewareContext

HTTPX_MODULE: ModuleType | None
try:
    HTTPX_MODULE = import_module("httpx")
except ImportError:
    HTTPX_MODULE = None


class DashboardReporter(Middleware):
    """
    Reports traces and events to the agentgate dashboard.

    Example:
        from ea_agentgate import Agent
        from ea_agentgate.middleware import DashboardReporter

        agent = Agent(
            middleware=[
                DashboardReporter(
                    api_url="http://localhost:8000",
                    api_key="your-api-key",  # Optional
                ),
            ]
        )
    """

    def __init__(
        self,
        *,
        api_url: str | None = None,
        api_key: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        async_send: bool = True,
    ):
        """
        Initialize dashboard reporter.

        Args:
            api_url: Dashboard API URL (default: from AGENTGATE_API_URL env)
            api_key: API key for authentication (default: from AGENTGATE_API_KEY env)
            agent_id: Identifier for this agent instance
            session_id: Session identifier for grouping traces
            async_send: If True, send in background thread (non-blocking)
        """
        super().__init__()
        self.api_url = api_url or os.getenv("AGENTGATE_API_URL", "http://localhost:8000")
        self.api_key = api_key or os.getenv("AGENTGATE_API_KEY")
        self.agent_id = agent_id or str(uuid.uuid4())[:8]
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.async_send = async_send

        self._client = None
        self._queue: list[dict[str, Any]] = []

    def _get_client(self):
        """Lazy-load httpx client."""
        if HTTPX_MODULE is None:
            return None
        if self._client is None:
            self._client = HTTPX_MODULE.Client(
                base_url=self.api_url,
                timeout=5.0,
                headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            )
        return self._client

    def _send_trace(self, data: dict[str, Any]) -> None:
        """Send trace to dashboard API."""
        client = self._get_client()
        if not client:
            return

        try:
            client.post("/api/traces", json=data)
        except (OSError, ValueError, RuntimeError):
            # Queue for retry or just drop in async mode
            if not self.async_send:
                raise

    def _send_approval_request(self, data: dict[str, Any]) -> None:
        """Send approval request to dashboard API."""
        client = self._get_client()
        if not client:
            return

        try:
            client.post("/api/approvals", json=data)
        except (OSError, ValueError, RuntimeError):
            pass

    def before(self, ctx: MiddlewareContext) -> None:
        """Record trace start."""
        ctx.metadata["dashboard_agent_id"] = self.agent_id
        ctx.metadata["dashboard_session_id"] = self.session_id

    def after(self, ctx: MiddlewareContext, _result: Any, error: Exception | None) -> None:
        """Send completed trace to dashboard."""
        trace = ctx.trace

        # Merge context metadata with trace metadata
        # Context metadata includes PII redaction info from PIIVault middleware
        merged_metadata = {**trace.context.metadata, **ctx.metadata}

        # Remove internal keys that shouldn't be sent to dashboard
        merged_metadata.pop("_pii_placeholder_mgr", None)

        data = {
            "trace_id": trace.id,
            "tool": trace.tool,
            "inputs": trace.inputs,
            "output": trace.result.output if not error else None,
            "status": trace.status.value,
            "error": str(error) if error else trace.result.error,
            "blocked_by": trace.context.blocked_by,
            "duration_ms": trace.timing.duration_ms,
            "cost": trace.context.cost,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "metadata": merged_metadata,
        }

        if self.async_send:
            threading.Thread(target=self._send_trace, args=(data,), daemon=True).start()
        else:
            self._send_trace(data)

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None
