"""Tests for edge cases."""

from server.models.schemas import (
    DatasetCreate,
    TraceCreate,
    TraceRead,
    TraceStatus,
    UserBase,
    utc_now,
)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string_fields(self):
        """Test handling of empty strings."""
        user = UserBase(email="", role="viewer")
        assert user.email == ""

    def test_zero_cost(self):
        """Test zero cost values."""
        trace = TraceCreate(trace_id="trace-123", tool="test_tool", cost=0.0)
        assert trace.cost == 0.0

    def test_negative_cost(self):
        """Test negative cost values (should be allowed for credits)."""
        trace = TraceCreate(trace_id="trace-123", tool="test_tool", cost=-1.0)
        assert trace.cost == -1.0

    def test_large_duration(self):
        """Test very large duration values."""
        trace = TraceRead(
            id=1,
            trace_id="trace-123",
            tool="test_tool",
            inputs=None,
            output=None,
            status=TraceStatus.SUCCESS,
            error=None,
            blocked_by=None,
            duration_ms=999999999.99,
            cost=0.0,
            agent_id=None,
            session_id=None,
            started_at=utc_now(),
            ended_at=None,
        )

        assert trace.duration_ms == 999999999.99

    def test_empty_dict_json_fields(self):
        """Test empty dict for JSON fields."""
        trace = TraceCreate(trace_id="trace-123", tool="test_tool", inputs={}, output={})

        assert isinstance(trace.inputs, dict)
        assert len(trace.inputs) == 0
        assert isinstance(trace.output, dict)
        assert len(trace.output) == 0

    def test_empty_list_fields(self):
        """Test empty lists."""
        dataset = DatasetCreate(name="Test", tags=[])
        assert isinstance(dataset.tags, list)
        assert len(dataset.tags) == 0

    def test_whitespace_in_strings(self):
        """Test whitespace handling in string fields."""
        user = UserBase(email="  test@example.com  ", role="viewer")
        # SQLModel doesn't automatically strip whitespace
        assert user.email == "  test@example.com  "

    def test_unicode_in_strings(self):
        """Test Unicode characters in string fields."""
        user = UserBase(email="tëst@example.com", name="Tëst Üser", role="viewer")
        assert user.email == "tëst@example.com"
        assert user.name == "Tëst Üser"

    def test_special_characters_in_json(self):
        """Test special characters in JSON fields."""
        trace = TraceCreate(
            trace_id="trace-123",
            tool="test_tool",
            inputs={"special": "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`"},
        )

        expected_special = "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`"
        assert trace.inputs is not None
        actual = trace.inputs.get("special")
        assert actual == expected_special
