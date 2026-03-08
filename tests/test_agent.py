"""Tests for the Agent class."""

import pytest

from ea_agentgate.agent import Agent
from ea_agentgate.exceptions import RateLimitError, TransactionFailed
from ea_agentgate.middleware.cost_tracker import CostTracker
from ea_agentgate.middleware.rate_limiter import RateLimiter
from ea_agentgate.trace import TraceStatus


class TestAgentBasics:
    """Test basic Agent functionality."""

    def test_create_agent(self):
        """Agent can be created with default settings."""
        agent = Agent()
        assert agent is not None
        assert len(agent.middleware) == 0

    def test_register_tool(self, basic_agent, sample_tool):
        """Tools can be registered with the agent."""
        basic_agent.register_tool("read_file", sample_tool)
        assert "read_file" in basic_agent.tools

    def test_register_tool_decorator(self, basic_agent):
        """Tools can be registered using decorator syntax."""

        @basic_agent.tool
        def my_tool(x: int) -> int:
            return x * 2

        _ = my_tool
        assert "my_tool" in basic_agent.tools

    def test_register_tool_with_options(self, basic_agent):
        """Tools can be registered with options."""

        @basic_agent.tool(name="custom_name", requires_approval=True, cost=0.5)
        def my_tool(x: int) -> int:
            return x * 2

        _ = my_tool
        assert "custom_name" in basic_agent.tools
        tool_def = basic_agent.tools["custom_name"]
        assert tool_def.requires_approval is True
        assert tool_def.cost == 0.5

    def test_call_tool(self, basic_agent, sample_tool):
        """Tools can be executed through the agent."""
        basic_agent.register_tool("read_file", sample_tool)
        result = basic_agent.call("read_file", path="/tmp/test.txt")
        assert result == "Contents of /tmp/test.txt"

    def test_call_tool_with_args(self, basic_agent):
        """Tools can be called with positional arguments."""

        @basic_agent.tool
        def add(a: int, b: int) -> int:
            return a + b

        _ = add
        result = basic_agent.call("add", 2, 3)
        assert result == 5

    def test_call_unregistered_tool(self, basic_agent):
        """Calling an unregistered tool raises an error."""
        with pytest.raises(KeyError):
            basic_agent.call("nonexistent_tool")

    def test_traces_recorded(self, basic_agent, sample_tool):
        """Execution traces are recorded."""
        basic_agent.register_tool("read_file", sample_tool)
        basic_agent.call("read_file", path="/tmp/test.txt")

        traces = basic_agent.traces
        assert len(traces) == 1
        assert traces[0].tool == "read_file"
        assert traces[0].status == TraceStatus.SUCCESS

    def test_traces_property(self, basic_agent, sample_tool):
        """Traces are also available via property."""
        basic_agent.register_tool("read_file", sample_tool)
        basic_agent.call("read_file", path="/tmp/test.txt")

        assert len(basic_agent.traces) == 1
        assert basic_agent.traces[0].tool == "read_file"

    def test_failed_tool_traces(self, basic_agent, failing_tool):
        """Failed tools are recorded with error status."""
        basic_agent.register_tool("fail", failing_tool)

        with pytest.raises(ValueError):
            basic_agent.call("fail")

        traces = basic_agent.traces
        assert len(traces) == 1
        assert traces[0].status == TraceStatus.FAILED

    def test_clear_traces(self, basic_agent, sample_tool):
        """Traces can be cleared."""
        basic_agent.register_tool("read_file", sample_tool)
        basic_agent.call("read_file", path="/tmp/test.txt")
        assert len(basic_agent.traces) == 1

        basic_agent.clear_traces()
        assert len(basic_agent.traces) == 0


class TestAgentTransactions:
    """Test transaction support."""

    def test_begin_transaction(self, basic_agent):
        """Transactions can be started."""
        basic_agent.txn.begin()
        assert basic_agent.txn.is_active is True

    def test_commit_transaction(self, basic_agent, sample_tool):
        """Transactions can be committed."""
        basic_agent.register_tool("read_file", sample_tool)
        basic_agent.txn.begin()
        basic_agent.call("read_file", path="/tmp/test.txt")
        basic_agent.txn.commit()

        assert basic_agent.txn.is_active is False

    def test_rollback_clears_transaction_traces(self, basic_agent, sample_tool):
        """Rollback clears transaction traces but keeps them in history."""
        basic_agent.register_tool("read_file", sample_tool)
        basic_agent.txn.begin()
        basic_agent.call("read_file", path="/tmp/test.txt")
        basic_agent.rollback()

        # Traces should still exist but transaction should be ended
        assert basic_agent.txn.is_active is False
        assert len(basic_agent.traces) == 1

    def test_transaction_context_manager(self, basic_agent, sample_tool):
        """Transactions work with context manager."""
        basic_agent.register_tool("read_file", sample_tool)

        with basic_agent.transaction():
            basic_agent.call("read_file", path="/tmp/test.txt")

        assert len(basic_agent.traces) == 1

    def test_transaction_rollback_on_failure(self, basic_agent):
        """Transaction calls compensation on failure."""
        compensated = []

        @basic_agent.tool
        def create_user(name: str) -> dict:
            return {"id": 123, "name": name}

        _ = create_user

        @basic_agent.tool
        def fail_step():
            raise ValueError("Step failed")

        _ = fail_step

        def compensate_create_user(output):
            compensated.append(output["id"])

        with pytest.raises(TransactionFailed) as exc_info:
            with basic_agent.transaction():
                basic_agent.compensate("create_user", compensate_create_user)
                basic_agent.call("create_user", name="test")
                basic_agent.call("fail_step")

        assert 123 in compensated
        assert exc_info.value.failed_step == "fail_step"
        assert "create_user" in exc_info.value.completed_steps
        assert "create_user" in exc_info.value.compensated_steps


class TestAgentMiddleware:
    """Test middleware integration."""

    def test_add_middleware(self, basic_agent):
        """Middleware can be added to an agent."""

        basic_agent.add_middleware(RateLimiter(max_calls=10, window="1m"))
        assert len(basic_agent.middleware) == 1

    def test_middleware_blocks_execution(self):
        """Middleware can block tool execution."""

        agent = Agent(middleware=[RateLimiter(max_calls=1, window="1m")])

        @agent.tool
        def fast_tool():
            return "ok"

        _ = fast_tool
        # First call should succeed
        result = agent.call("fast_tool")
        assert result == "ok"

        # Second immediate call should be blocked
        with pytest.raises(RateLimitError):
            agent.call("fast_tool")

    def test_middleware_in_constructor(self):
        """Middleware can be provided in constructor."""

        agent = Agent(
            middleware=[
                RateLimiter(max_calls=100, window="1m"),
                CostTracker(max_budget=50.0),
            ]
        )

        assert len(agent.middleware) == 2


class TestAgentIdentifiers:
    """Test agent identifiers."""

    def test_auto_generated_agent_id(self):
        """Agent ID is auto-generated if not provided."""
        agent = Agent()
        assert agent.agent_id is not None
        assert len(agent.agent_id) == 8

    def test_custom_identifiers(self):
        """Custom identifiers can be set."""
        agent = Agent(
            agent_id="my-agent",
            session_id="session-123",
            user_id="user-456",
        )
        assert agent.agent_id == "my-agent"
        assert agent.session_id == "session-123"
        assert agent.user_id == "user-456"
