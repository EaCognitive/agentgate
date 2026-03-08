"""Tests for Trace models."""

from datetime import timedelta

from server.models.schemas import TraceCreate, TraceRead, TraceStatus, utc_now


class TestTraceModels:
    """Test Trace-related model classes."""

    def test_trace_create(self, sample_trace_data):
        """Test TraceCreate model."""
        trace = TraceCreate(**sample_trace_data)

        assert trace.trace_id == "trace-123"
        assert trace.tool == "test_tool"
        assert trace.inputs == {"param": "value"}
        assert trace.status == TraceStatus.SUCCESS
        assert trace.cost == 0.01

    def test_trace_create_defaults(self):
        """Test TraceCreate with default values."""
        trace = TraceCreate(trace_id="trace-123", tool="test_tool")

        assert trace.trace_id == "trace-123"
        assert trace.tool == "test_tool"
        assert trace.inputs is None
        assert trace.output is None
        assert trace.status == TraceStatus.PENDING
        assert trace.cost == 0.0
        assert trace.agent_id is None

    def test_trace_read_structure(self):
        """Test TraceRead model structure."""
        now = utc_now()
        trace = TraceRead(
            id=1,
            trace_id="trace-123",
            tool="test_tool",
            inputs={"param": "value"},
            output={"result": "success"},
            status=TraceStatus.SUCCESS,
            error=None,
            blocked_by=None,
            duration_ms=100.5,
            cost=0.01,
            agent_id="agent-1",
            session_id="session-1",
            started_at=now,
            ended_at=now + timedelta(milliseconds=100),
        )

        assert trace.id == 1
        assert trace.trace_id == "trace-123"
        assert trace.duration_ms == 100.5
        assert trace.status == TraceStatus.SUCCESS
