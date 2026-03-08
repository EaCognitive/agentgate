"""Tests for middleware components."""

import io
import json

import pytest

from ea_agentgate.exceptions import ApprovalDenied, BudgetExceededError, RateLimitError
from ea_agentgate.middleware.approval import HumanApproval
from ea_agentgate.middleware.audit_log import AuditLog
from ea_agentgate.middleware.base import MiddlewareContext
from ea_agentgate.middleware.cost_tracker import CostTracker
from ea_agentgate.middleware.rate_limiter import RateLimiter
from ea_agentgate.trace import Trace


class TestRateLimiter:
    """Test RateLimiter middleware."""

    def test_allows_within_limit(self):
        """Requests within limit are allowed."""
        limiter = RateLimiter(max_calls=10, window="1m")
        ctx = MiddlewareContext(
            tool="test",
            inputs={},
            trace=Trace(tool="test", inputs={}),
        )
        # Should not raise
        limiter.before(ctx)

    def test_blocks_over_limit(self):
        """Requests over limit are blocked."""
        limiter = RateLimiter(max_calls=2, window="1m")
        ctx = MiddlewareContext(
            tool="test",
            inputs={},
            trace=Trace(tool="test", inputs={}),
        )

        # First two should pass
        limiter.before(ctx)
        limiter.before(ctx)

        # Third should fail
        with pytest.raises(RateLimitError):
            limiter.before(ctx)

    def test_per_tool_limiting(self):
        """Rate limits can be per-tool."""
        limiter = RateLimiter(max_calls=1, window="1m", scope="tool")

        ctx1 = MiddlewareContext(
            tool="tool1",
            inputs={},
            trace=Trace(tool="tool1", inputs={}),
        )
        ctx2 = MiddlewareContext(
            tool="tool2",
            inputs={},
            trace=Trace(tool="tool2", inputs={}),
        )

        # Both tools can be called once
        limiter.before(ctx1)
        limiter.before(ctx2)

        # Second call to same tool fails
        with pytest.raises(RateLimitError):
            limiter.before(ctx1)


class TestCostTracker:
    """Test CostTracker middleware."""

    def test_tracks_costs(self):
        """Costs are tracked correctly."""
        tracker = CostTracker(max_budget=100.0, default_cost=10.0)
        ctx = MiddlewareContext(
            tool="api_call",
            inputs={},
            trace=Trace(tool="api_call", inputs={}),
        )

        tracker.before(ctx)
        tracker.after(ctx, "done", None)

        assert tracker.total_cost == 10.0

    def test_blocks_over_budget(self):
        """Requests are blocked when budget exceeded."""
        tracker = CostTracker(max_budget=10.0, default_cost=8.0)

        # First call costs 8
        ctx1 = MiddlewareContext(
            tool="expensive",
            inputs={},
            trace=Trace(tool="expensive", inputs={}),
        )
        tracker.before(ctx1)
        tracker.after(ctx1, "done", None)

        # Second call would exceed budget (8 + 8 > 10)
        ctx2 = MiddlewareContext(
            tool="expensive",
            inputs={},
            trace=Trace(tool="expensive", inputs={}),
        )
        with pytest.raises(BudgetExceededError):
            tracker.before(ctx2)


class TestAuditLog:
    """Test AuditLog middleware."""

    def test_logs_to_stream(self):
        """Audit entries are logged to a stream."""
        output = io.StringIO()
        audit = AuditLog(destination=output)

        ctx = MiddlewareContext(
            tool="read_file",
            inputs={"path": "/tmp/test.txt"},
            trace=Trace(tool="read_file", inputs={"path": "/tmp/test.txt"}),
        )

        audit.before(ctx)
        audit.after(ctx, result="file contents", error=None)

        output.seek(0)
        lines = output.readlines()
        assert len(lines) >= 1

        # Parse the JSON log entry
        entry = json.loads(lines[0])
        assert entry["tool"] == "read_file"

    def test_redacts_sensitive_keys(self):
        """Sensitive keys are redacted."""
        output = io.StringIO()
        audit = AuditLog(
            destination=output,
            redact_keys=["password", "api_key"],
        )

        ctx = MiddlewareContext(
            tool="login",
            inputs={"username": "user", "password": "secret123"},
            trace=Trace(tool="login", inputs={"username": "user", "password": "secret123"}),
        )

        audit.before(ctx)

        output.seek(0)
        entry = json.loads(output.readline())
        assert entry["inputs"]["password"] == "[REDACTED]"
        assert entry["inputs"]["username"] == "user"

    def test_context_manager(self):
        """AuditLog works as context manager."""
        output = io.StringIO()
        with AuditLog(destination=output) as audit:
            assert audit is not None
        # Should not raise after exiting context

    def test_get_entries(self):
        """Can retrieve logged entries."""
        audit = AuditLog()
        ctx = MiddlewareContext(
            tool="test",
            inputs={},
            trace=Trace(tool="test", inputs={}),
        )
        audit.before(ctx)

        entries = audit.get_entries()
        assert len(entries) == 1
        assert entries[0]["tool"] == "test"


class TestHumanApproval:
    """Test HumanApproval middleware."""

    def test_no_approval_for_unlisted_tools(self):
        """Tools not in list don't need approval."""
        approval = HumanApproval(tools=["dangerous_tool"])

        ctx = MiddlewareContext(
            tool="safe_tool",
            inputs={},
            trace=Trace(tool="safe_tool", inputs={}),
        )

        # Should not block
        approval.before(ctx)

    def test_requires_approval_for_specified_tools(self):
        """Tools in list need approval."""
        approval = HumanApproval(
            tools=["delete_file"],
            handler=lambda req: False,  # Always deny
        )

        ctx = MiddlewareContext(
            tool="delete_file",
            inputs={"path": "/important.txt"},
            trace=Trace(tool="delete_file", inputs={"path": "/important.txt"}),
        )

        with pytest.raises(ApprovalDenied):
            approval.before(ctx)

    def test_approval_granted(self):
        """Approved requests proceed."""
        approval = HumanApproval(
            tools=["sensitive_action"],
            handler=lambda req: True,  # Always approve
        )

        ctx = MiddlewareContext(
            tool="sensitive_action",
            inputs={},
            trace=Trace(tool="sensitive_action", inputs={}),
        )

        # Should not raise
        approval.before(ctx)
        assert ctx.approved_by == "handler"
