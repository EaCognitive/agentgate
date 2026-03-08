"""Tests for model serialization."""

from datetime import datetime

from server.models.schemas import (
    ApprovalCreate,
    DatasetCreate,
    TestCaseCreate,
    TraceCreate,
    TraceRead,
    TraceStatus,
    UserBase,
    utc_now,
)


class TestSerialization:
    """Test model serialization and deserialization."""

    def test_user_base_dict_serialization(self):
        """Test UserBase serialization to dict."""
        user = UserBase(email="test@example.com", name="Test", role="viewer")
        user_dict = user.model_dump()

        assert user_dict["email"] == "test@example.com"
        assert user_dict["name"] == "Test"
        assert user_dict["role"] == "viewer"

    def test_user_base_dict_deserialization(self):
        """Test UserBase deserialization from dict."""
        data = {"email": "test@example.com", "name": "Test", "role": "admin"}
        user = UserBase(**data)

        assert user.email == "test@example.com"
        assert user.name == "Test"
        assert user.role == "admin"

    def test_trace_with_json_fields(self):
        """Test Trace serialization with JSON fields."""
        trace = TraceCreate(
            trace_id="trace-123",
            tool="test_tool",
            inputs={"key": "value", "nested": {"data": 123}},
            output={"result": ["item1", "item2"]},
        )

        trace_dict = trace.model_dump()

        assert trace_dict["inputs"]["nested"]["data"] == 123
        assert trace_dict["output"]["result"] == ["item1", "item2"]

    def test_approval_with_context(self):
        """Test Approval serialization with context."""
        approval = ApprovalCreate(
            approval_id="approval-123",
            tool="test_tool",
            context={"reason": "test", "metadata": {"key": "value"}},
        )

        approval_dict = approval.model_dump()
        assert approval_dict["context"]["reason"] == "test"
        assert approval_dict["context"]["metadata"]["key"] == "value"

    def test_datetime_serialization(self):
        """Test datetime field serialization."""
        now = utc_now()
        trace = TraceRead(
            id=1,
            trace_id="trace-123",
            tool="test_tool",
            inputs=None,
            output=None,
            status=TraceStatus.SUCCESS,
            error=None,
            blocked_by=None,
            duration_ms=None,
            cost=0.0,
            agent_id=None,
            session_id=None,
            started_at=now,
            ended_at=None,
        )

        trace_dict = trace.model_dump()
        assert isinstance(trace_dict["started_at"], datetime)

    def test_enum_serialization(self):
        """Test enum field serialization."""
        trace = TraceCreate(trace_id="trace-123", tool="test_tool", status=TraceStatus.SUCCESS)

        trace_dict = trace.model_dump()
        assert trace_dict["status"] == TraceStatus.SUCCESS

    def test_list_field_serialization(self):
        """Test list field serialization."""
        dataset = DatasetCreate(name="Test Dataset", tags=["tag1", "tag2", "tag3"])

        dataset_dict = dataset.model_dump()
        assert dataset_dict["tags"] == ["tag1", "tag2", "tag3"]

    def test_nested_json_serialization(self):
        """Test nested JSON structure serialization."""
        test_case = TestCaseCreate(
            dataset_id=1,
            name="Test",
            tool="test_tool",
            inputs={"param": "value"},
            assertions=[
                {"type": "equals", "expected": "value"},
                {"type": "contains", "pattern": "val"},
            ],
        )

        test_dict = test_case.model_dump()
        assert len(test_dict["assertions"]) == 2
        assert test_dict["assertions"][0]["type"] == "equals"
