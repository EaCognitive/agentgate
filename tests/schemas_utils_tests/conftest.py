"""
Shared fixtures for schema and utility tests.
"""

from typing import Any

import pytest

from server.models.schemas import TraceStatus


@pytest.fixture
def sample_user_data() -> dict[str, Any]:
    """Sample user data for testing."""
    return {
        "email": "test@example.com",
        "name": "Test User",
        "role": "viewer",
    }


@pytest.fixture
def sample_trace_data() -> dict[str, Any]:
    """Sample trace data for testing."""
    return {
        "trace_id": "trace-123",
        "tool": "test_tool",
        "inputs": {"param": "value"},
        "output": {"result": "success"},
        "status": TraceStatus.SUCCESS,
        "cost": 0.01,
        "agent_id": "agent-1",
        "session_id": "session-1",
    }


@pytest.fixture
def sample_approval_data() -> dict[str, Any]:
    """Sample approval data for testing."""
    return {
        "approval_id": "approval-123",
        "tool": "dangerous_tool",
        "inputs": {"action": "delete"},
        "trace_id": "trace-123",
        "agent_id": "agent-1",
        "session_id": "session-1",
        "context": {"reason": "testing"},
    }
