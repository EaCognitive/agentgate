"""Tests for policy middleware."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ea_agentgate.exceptions import GuardrailViolationError
from ea_agentgate.middleware.base import MiddlewareContext
from ea_agentgate.middleware.policy_middleware import PolicyMiddleware
from ea_agentgate.security.policy_engine import (
    ConditionOperator,
    PolicyCondition,
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    PolicySet,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(name="engine")
def fixture_engine() -> PolicyEngine:
    """Create policy engine with test policy."""
    engine = PolicyEngine()

    policy_set = PolicySet(
        policy_set_id="test_policy",
        version="1.0.0",
        description="Test policy",
        default_effect=PolicyEffect.ALLOW,
        rules=[
            PolicyRule(
                rule_id="block_dangerous_tools",
                description="Block dangerous tools",
                priority=100,
                effect=PolicyEffect.DENY,
                conditions=[
                    PolicyCondition(
                        field="request.tool",
                        operator=ConditionOperator.IN,
                        value=["rm", "delete", "drop"],
                    )
                ],
            ),
            PolicyRule(
                rule_id="require_auth_for_pii",
                description="Require auth for PII access",
                priority=90,
                effect=PolicyEffect.DENY,
                conditions=[
                    PolicyCondition(
                        field="request.tool",
                        operator=ConditionOperator.CONTAINS,
                        value="pii",
                    ),
                    PolicyCondition(
                        field="request.user.id",
                        operator=ConditionOperator.NOT_EXISTS,
                        value=None,
                    ),
                ],
            ),
        ],
    )

    engine.load_policy_set(policy_set)
    return engine


@pytest.fixture(name="mock_trace")
def fixture_mock_trace() -> MagicMock:
    """Create mock trace object."""
    trace = MagicMock()
    trace.id = "test-trace-123"
    return trace


# =============================================================================
# Middleware Tests - Enforce Mode
# =============================================================================


def test_policy_middleware_allows_safe_tool(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware allows safe tools in enforce mode."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="read_file",
        inputs={"path": "/tmp/file.txt"},
        trace=mock_trace,
    )

    middleware.before(ctx)

    assert "policy_decision" in ctx.metadata
    assert ctx.metadata["policy_decision"]["allowed"]


def test_policy_middleware_blocks_dangerous_tool(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware blocks dangerous tools in enforce mode."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="rm",
        inputs={"path": "/etc/passwd"},
        trace=mock_trace,
    )

    with pytest.raises(GuardrailViolationError) as exc_info:
        middleware.before(ctx)

    assert exc_info.value.tool == "rm"
    mock_trace.block.assert_called_once()


def test_policy_middleware_blocks_pii_without_auth(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware blocks PII access without user auth."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="read_pii_data",
        inputs={"user_id": "123"},
        trace=mock_trace,
        user_id=None,
    )

    with pytest.raises(GuardrailViolationError):
        middleware.before(ctx)


def test_policy_middleware_allows_pii_with_auth(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware allows PII access with user auth."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="read_pii_data",
        inputs={"user_id": "123"},
        trace=mock_trace,
        user_id="admin-456",
    )

    middleware.before(ctx)

    assert ctx.metadata["policy_decision"]["allowed"]


# =============================================================================
# Middleware Tests - Shadow Mode
# =============================================================================


def test_policy_middleware_shadow_mode_logs_violation(
    engine: PolicyEngine,
    mock_trace: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test shadow mode logs violations without blocking."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="shadow",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="rm",
        inputs={"path": "/etc/passwd"},
        trace=mock_trace,
    )

    middleware.before(ctx)

    assert "policy_shadow_violation" in ctx.metadata
    assert ctx.metadata["policy_shadow_violation"]
    assert "SHADOW_POLICY_VIOLATION" in caplog.text


# =============================================================================
# Middleware Tests - On Deny Modes
# =============================================================================


def test_policy_middleware_on_deny_log(
    engine: PolicyEngine,
    mock_trace: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test on_deny=log mode logs without raising exception."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="log",
    )

    ctx = MiddlewareContext(
        tool="rm",
        inputs={"path": "/etc/passwd"},
        trace=mock_trace,
    )

    middleware.before(ctx)

    assert "POLICY_VIOLATION" in caplog.text
    assert not ctx.metadata["policy_decision"]["allowed"]


# =============================================================================
# Middleware Tests - Evaluate All
# =============================================================================


def test_policy_middleware_evaluate_all(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware evaluates all policies when ID not specified."""
    policy_set_2 = PolicySet(
        policy_set_id="additional_policy",
        version="1.0.0",
        description="Additional policy",
        default_effect=PolicyEffect.ALLOW,
        rules=[
            PolicyRule(
                rule_id="block_exec",
                description="Block exec",
                priority=50,
                effect=PolicyEffect.DENY,
                conditions=[
                    PolicyCondition(
                        field="request.tool",
                        operator=ConditionOperator.EQUALS,
                        value="exec",
                    )
                ],
            )
        ],
    )

    engine.load_policy_set(policy_set_2)

    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id=None,
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="exec",
        inputs={"command": "ls"},
        trace=mock_trace,
    )

    with pytest.raises(GuardrailViolationError):
        middleware.before(ctx)


# =============================================================================
# Middleware Tests - Request Context Building
# =============================================================================


def test_policy_middleware_builds_complete_context(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware builds complete request context."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="test_tool",
        inputs={"key": "value"},
        trace=mock_trace,
        user_id="user-123",
        session_id="session-456",
        agent_id="agent-789",
    )

    ctx.metadata["custom_field"] = "custom_value"

    middleware.before(ctx)

    decision_metadata = ctx.metadata["policy_decision"]
    assert decision_metadata["allowed"]


# =============================================================================
# Middleware Tests - Async
# =============================================================================


@pytest.mark.asyncio
async def test_policy_middleware_async(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test async middleware execution."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="read_file",
        inputs={"path": "/tmp/file.txt"},
        trace=mock_trace,
    )

    await middleware.abefore(ctx)

    assert "policy_decision" in ctx.metadata
    assert ctx.metadata["policy_decision"]["allowed"]


@pytest.mark.asyncio
async def test_policy_middleware_async_blocks(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test async middleware blocks dangerous tools."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="rm",
        inputs={"path": "/etc/passwd"},
        trace=mock_trace,
    )

    with pytest.raises(GuardrailViolationError):
        await middleware.abefore(ctx)


# =============================================================================
# Middleware Tests - Metadata Storage
# =============================================================================


def test_policy_middleware_stores_decision_metadata(
    engine: PolicyEngine,
    mock_trace: MagicMock,
) -> None:
    """Test middleware stores complete decision metadata."""
    middleware = PolicyMiddleware(
        engine=engine,
        policy_set_id="test_policy",
        mode="enforce",
        on_deny="block",
    )

    ctx = MiddlewareContext(
        tool="read_file",
        inputs={"path": "/tmp/file.txt"},
        trace=mock_trace,
    )

    middleware.before(ctx)

    decision = ctx.metadata["policy_decision"]
    assert "allowed" in decision
    assert "effect" in decision
    assert "matched_rules" in decision
    assert "reason" in decision
    assert "policy_set_id" in decision
    assert "evaluation_time_ms" in decision
