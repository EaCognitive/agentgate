"""Human-in-the-loop approval middleware."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from collections.abc import Callable, Awaitable

from .base import Middleware, MiddlewareContext
from ..exceptions import ApprovalRequired, ApprovalDenied


@dataclass
class ApprovalRequest:
    """A pending approval request."""

    id: str
    tool: str
    inputs: dict[str, Any]
    trace_id: str
    created_at: datetime
    expires_at: datetime | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON-safe serialization.

        Uses a fallback serializer (default=str) to prevent TypeError crashes
        if inputs or context contain non-serializable objects such as file
        handles, sockets, or custom class instances.
        """

        def _safe_serialize(obj: Any) -> Any:
            """Round-trip through JSON to ensure all nested values are serializable."""
            try:
                return json.loads(json.dumps(obj, default=str))
            except (TypeError, ValueError):
                return str(obj)

        return {
            "id": self.id,
            "tool": self.tool,
            "inputs": _safe_serialize(self.inputs),
            "trace_id": self.trace_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "context": _safe_serialize(self.context),
        }


@dataclass
class ApprovalDecision:
    """A decision on an approval request."""

    approved: bool
    decided_by: str
    decided_at: datetime = field(default_factory=datetime.now)
    reason: str | None = None


@dataclass
class ApprovalConfig:
    """Configuration for human approval middleware."""

    tools: list[str]
    handler: Callable[[ApprovalRequest], bool | Awaitable[bool]] | None = None
    webhook: str | None = None
    timeout: float | None = None
    auto_approve_duplicates: bool = True


class HumanApproval(Middleware):
    """
    Requires human approval for sensitive operations.

    Supports both sync (blocking) and async (webhook) approval flows.

    Example (sync - for testing/CLI):
        approval = HumanApproval(
            tools=["delete_*", "send_email"],
            handler=lambda req: input(f"Approve {req.tool}? (y/n): ").lower() == "y"
        )

    Example (async - for production):
        approval = HumanApproval(
            tools=["delete_*", "transfer_money"],
            webhook="https://your-app.com/approvals",
            timeout=300,  # 5 minutes
        )
    """

    def __init__(
        self,
        *,
        tools: list[str] | None = None,
        handler: Callable[[ApprovalRequest], bool | Awaitable[bool]] | None = None,
        webhook: str | None = None,
        timeout: float | None = None,
        auto_approve_duplicates: bool = True,
    ):
        """
        Initialize approval middleware.

        Args:
            tools: Tool patterns requiring approval (supports wildcards)
            handler: Sync/async function to handle approval
            webhook: URL to POST approval requests to
            timeout: Seconds to wait for approval (None = wait forever)
            auto_approve_duplicates: Auto-approve identical requests that were approved before
        """
        super().__init__()
        self.config = ApprovalConfig(
            tools=tools or [],
            handler=handler,
            webhook=webhook,
            timeout=timeout,
            auto_approve_duplicates=auto_approve_duplicates,
        )

        # Track approvals
        self._pending: dict[str, ApprovalRequest] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._approved_hashes: set[str] = set()  # For duplicate detection

    def _requires_approval(self, tool: str) -> bool:
        """Check if tool requires approval."""
        return any(fnmatch.fnmatch(tool, pattern) for pattern in self.config.tools)

    def _make_hash(self, tool: str, inputs: dict[str, Any]) -> str:
        """Create hash for duplicate detection."""
        data = json.dumps({"tool": tool, "inputs": inputs}, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def before(self, ctx: MiddlewareContext) -> None:
        """Check for approval before execution."""
        if not self._requires_approval(ctx.tool):
            return

        # Check for pre-approved (via approve() method)
        request_hash = self._make_hash(ctx.tool, ctx.inputs)
        if self.config.auto_approve_duplicates and request_hash in self._approved_hashes:
            ctx.approved_by = "auto (duplicate)"
            return

        # Create approval request
        request = ApprovalRequest(
            id=str(uuid.uuid4())[:8],
            tool=ctx.tool,
            inputs=ctx.inputs,
            trace_id=ctx.trace.id,
            created_at=datetime.now(),
            expires_at=None,
            context={
                "agent_id": ctx.agent_id,
                "session_id": ctx.session_id,
                "user_id": ctx.user_id,
            },
        )

        # Handle approval
        if self.config.handler:
            # Sync handler
            result = self.config.handler(request)
            if isinstance(result, bool):
                if result:
                    self._approved_hashes.add(request_hash)
                    ctx.approved_by = "handler"
                    ctx.approval_id = request.id
                else:
                    raise ApprovalDenied(
                        f"Approval denied for {ctx.tool}",
                        tool=ctx.tool,
                    )
            else:
                # Async handler - not supported in sync middleware
                raise NotImplementedError("Async approval handlers require async middleware")

        elif self.config.webhook:
            # Webhook mode - raise exception to pause execution
            self._pending[request.id] = request
            raise ApprovalRequired(
                f"Tool '{ctx.tool}' requires human approval",
                tool=ctx.tool,
                inputs=ctx.inputs,
                approval_id=request.id,
            )

        else:
            # No handler configured - raise for manual handling
            self._pending[request.id] = request
            raise ApprovalRequired(
                f"Tool '{ctx.tool}' requires human approval",
                tool=ctx.tool,
                inputs=ctx.inputs,
                approval_id=request.id,
            )

    def approve(
        self,
        approval_id: str | None = None,
        tool: str | None = None,
        inputs: dict[str, Any] | None = None,
        approved_by: str = "manual",
    ) -> None:
        """
        Manually approve a request.

        Can approve by ID (for pending requests) or by tool+inputs (pre-approve).
        """
        if approval_id and approval_id in self._pending:
            request = self._pending.pop(approval_id)
            request_hash = self._make_hash(request.tool, request.inputs)
            self._approved_hashes.add(request_hash)
            self._decisions[approval_id] = ApprovalDecision(
                approved=True,
                decided_by=approved_by,
            )
        elif tool and inputs is not None:
            request_hash = self._make_hash(tool, inputs)
            self._approved_hashes.add(request_hash)

    def deny(self, approval_id: str, denied_by: str = "manual", reason: str | None = None) -> None:
        """Deny a pending request."""
        if approval_id in self._pending:
            self._pending.pop(approval_id)
            self._decisions[approval_id] = ApprovalDecision(
                approved=False,
                decided_by=denied_by,
                reason=reason,
            )

    def get_pending(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self._pending.values())

    def is_approved(self, approval_id: str) -> bool | None:
        """Check if a request was approved (None if still pending)."""
        if approval_id in self._decisions:
            return self._decisions[approval_id].approved
        if approval_id in self._pending:
            return None
        return None
