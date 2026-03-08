"""Tests for the Dataset/Test Case feature (Feature 2: Save to Dataset)."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ea_agentgate.middleware.base import MiddlewareContext
from ea_agentgate.middleware.dataset_recorder import (
    DatasetRecorder,
    DatasetRecorderContext,
    RecordingConfig,
    RecordingFilterConfig,
)
from server.models import (
    AssertionType,
    Dataset,
    PytestExportConfig,
    PytestExportResult,
    TestCase,
    TestCaseFromTrace,
    TestCaseStatus,
    TestResult,
    TestResultStatus,
    TestRun,
    TestRunStatus,
)


# Test Dataset and TestCase models
def test_dataset_model_creation():
    """Test that Dataset model can be created with required fields."""

    dataset = Dataset(
        name="Test Dataset",
        description="A test dataset for validation",
        tags=["test", "validation"],
    )

    assert dataset.name == "Test Dataset"
    assert dataset.description == "A test dataset for validation"
    assert dataset.tags == ["test", "validation"]
    assert dataset.test_count == 0


def test_testcase_model_creation():
    """Test that TestCase model can be created with required fields."""

    test_case = TestCase(
        dataset_id=1,
        name="Test API Call",
        tool="api_call",
        inputs={"url": "https://api.example.com", "method": "GET"},
        expected_output={"status": 200},
        assertions=[
            {"type": "type_check", "expected_type": "object"},
            {"type": "json_path", "path": "$.status"},
        ],
        status=TestCaseStatus.ACTIVE,
    )

    assert test_case.name == "Test API Call"
    assert test_case.tool == "api_call"
    assert test_case.inputs["url"] == "https://api.example.com"
    assert len(test_case.assertions) == 2
    assert test_case.status == TestCaseStatus.ACTIVE


def test_testcase_status_enum():
    """Test TestCaseStatus enum values."""

    assert TestCaseStatus.ACTIVE == "active"
    assert TestCaseStatus.DISABLED == "disabled"
    assert TestCaseStatus.DRAFT == "draft"


def test_assertion_type_enum():
    """Test AssertionType enum values."""

    assert AssertionType.EQUALS == "equals"
    assert AssertionType.CONTAINS == "contains"
    assert AssertionType.NOT_CONTAINS == "not_contains"
    assert AssertionType.MATCHES_REGEX == "matches_regex"
    assert AssertionType.JSON_PATH == "json_path"
    assert AssertionType.TYPE_CHECK == "type_check"
    # CUSTOM was removed for security reasons (code injection vulnerability)


def test_testrun_model_creation():
    """Test that TestRun model can be created."""

    test_run = TestRun(
        run_id="test-run-1",
        dataset_id=1,
        status=TestRunStatus.COMPLETED,
        total_tests=10,
        passed_count=8,
        failed_count=2,
        error_count=0,
        started_at=datetime.now(timezone.utc),
        duration_ms=5000,
    )

    assert test_run.total_tests == 10
    assert test_run.passed_count == 8
    assert test_run.status == TestRunStatus.COMPLETED


def test_testresult_model_creation():
    """Test that TestResult model can be created."""

    result = TestResult(
        test_run_id=1,
        test_case_id=1,
        status=TestResultStatus.PASSED,
        actual_output={"value": 42},
        assertion_results=[
            {"assertion_index": 0, "passed": True, "message": None},
        ],
        duration_ms=100,
        started_at=datetime.now(timezone.utc),
    )

    assert result.status == TestResultStatus.PASSED
    assert result.actual_output["value"] == 42


# Test DatasetRecorder middleware
def test_dataset_recorder_middleware_init():
    """Test DatasetRecorder middleware initialization."""

    config = RecordingConfig(
        dataset_id=1,
        dashboard_url="http://localhost:8000",
        filter=RecordingFilterConfig(
            only_success=True,
            tool_filter=["api_call", "database_query"],
            sample_rate=0.5,
        ),
    )
    recorder = DatasetRecorder(dataset_id=1, config=config)

    assert recorder.config.dataset_id == 1
    assert recorder.config.dashboard_url == "http://localhost:8000"
    assert recorder.config.filter.only_success is True
    assert recorder.config.filter.tool_filter == ["api_call", "database_query"]
    assert recorder.config.filter.sample_rate == 0.5


def test_dataset_recorder_should_record_success_only():
    """Test that recorder filters based on success status."""

    config = RecordingConfig(
        dataset_id=1,
        filter=RecordingFilterConfig(only_success=True),
    )
    recorder = DatasetRecorder(dataset_id=1, config=config)

    # Create mock context
    ctx = MagicMock(spec=MiddlewareContext)
    ctx.tool = "api_call"
    ctx.session_id = "test-session"

    # Should record successful calls
    assert recorder.should_record(ctx, error=None) is True

    # Should not record failed calls
    assert recorder.should_record(ctx, error=Exception("test error")) is False


def test_dataset_recorder_tool_filter():
    """Test that recorder filters by tool name."""

    config = RecordingConfig(
        dataset_id=1,
        filter=RecordingFilterConfig(
            tool_filter=["api_call", "database_query"],
            sample_rate=1.0,
        ),
    )
    recorder = DatasetRecorder(dataset_id=1, config=config)

    ctx = MagicMock(spec=MiddlewareContext)
    ctx.session_id = "test-session"

    # Should record allowed tools
    ctx.tool = "api_call"
    assert recorder.should_record(ctx, error=None) is True

    # Should not record other tools
    ctx.tool = "bash"
    assert recorder.should_record(ctx, error=None) is False


def test_dataset_recorder_generate_assertions_object():
    """Test assertion generation for object results."""

    config = RecordingConfig(dataset_id=1, auto_assertions=True)
    recorder = DatasetRecorder(dataset_id=1, config=config)

    result = {"status": "success", "data": {"id": 1}}
    assertions = recorder.generate_assertions(result)

    # Should have type check assertion
    type_assertions = [a for a in assertions if a["type"] == "type_check"]
    assert len(type_assertions) == 1
    assert type_assertions[0]["expected_type"] == "object"

    # Should have json_path assertions for keys
    path_assertions = [a for a in assertions if a["type"] == "json_path"]
    assert len(path_assertions) >= 1


def test_dataset_recorder_generate_assertions_string():
    """Test assertion generation for string results."""

    config = RecordingConfig(dataset_id=1, auto_assertions=True)
    recorder = DatasetRecorder(dataset_id=1, config=config)

    result = "Hello World"
    assertions = recorder.generate_assertions(result)

    type_assertions = [a for a in assertions if a["type"] == "type_check"]
    assert len(type_assertions) == 1
    assert type_assertions[0]["expected_type"] == "string"


def test_dataset_recorder_generate_assertions_array():
    """Test assertion generation for array results."""

    config = RecordingConfig(dataset_id=1, auto_assertions=True)
    recorder = DatasetRecorder(dataset_id=1, config=config)

    result = [1, 2, 3]
    assertions = recorder.generate_assertions(result)

    type_assertions = [a for a in assertions if a["type"] == "type_check"]
    assert len(type_assertions) == 1
    assert type_assertions[0]["expected_type"] == "array"


def test_dataset_recorder_context_manager():
    """Test DatasetRecorderContext for scoped recording."""

    config = RecordingConfig(
        dataset_id=1,
        filter=RecordingFilterConfig(
            sample_rate=0.1,
            tool_filter=["api_call"],
        ),
    )
    recorder = DatasetRecorder(dataset_id=1, config=config)

    # Original config
    assert recorder.config.filter.sample_rate == 0.1
    assert recorder.config.filter.tool_filter == ["api_call"]

    # Override in context
    with DatasetRecorderContext(recorder, sample_rate=1.0, tool_filter=[]):
        assert recorder.config.filter.sample_rate == 1.0
        assert not recorder.config.filter.tool_filter

    # Restored after context
    assert recorder.config.filter.sample_rate == 0.1
    assert recorder.config.filter.tool_filter == ["api_call"]


def test_dataset_recorder_serialize_result():
    """Test result serialization."""

    recorder = DatasetRecorder(dataset_id=1)

    # Serializable result
    result = {"key": "value", "number": 42}
    serialized = recorder.serialize_result(result)
    assert serialized["value"] == result
    assert "_serialized" not in serialized

    # Non-serializable result (falls back to string)
    result = Path("custom-object")
    serialized = recorder.serialize_result(result)
    assert serialized["_serialized"] is True


def test_pytest_export_config():
    """Test PytestExportConfig model."""

    config = PytestExportConfig(
        dataset_id=1,
        output_dir="tests/",
        async_tests=True,
    )

    assert config.dataset_id == 1
    assert config.output_dir == "tests/"
    assert config.async_tests is True


def test_pytest_export_result():
    """Test PytestExportResult model."""

    result = PytestExportResult(
        file_path="tests/test_api.py",
        content="def test_example(): pass",
        test_count=5,
    )

    assert result.file_path == "tests/test_api.py"
    assert "def test_example" in result.content
    assert result.test_count == 5


# Test TestCaseFromTrace schema
def test_testcase_from_trace_schema():
    """Test TestCaseFromTrace schema for trace conversion."""

    data = TestCaseFromTrace(
        trace_id="trace-123",
        dataset_id=1,
        name="Test from production",
        assertions=[
            {"type": "type_check", "expected_type": "object"},
        ],
        tags=["production", "api"],
    )

    assert data.trace_id == "trace-123"
    assert data.dataset_id == 1
    assert data.name == "Test from production"
    assert len(data.assertions) == 1
    assert data.tags == ["production", "api"]


def test_testcase_from_trace_optional_fields():
    """Test TestCaseFromTrace with required fields."""

    # trace_id and dataset_id are required
    data = TestCaseFromTrace(trace_id="trace-456", dataset_id=1)

    assert data.trace_id == "trace-456"
    assert data.dataset_id == 1
    assert data.name is None
    assert data.assertions is None
    assert data.tags is None


# Integration test for middleware name property
def test_dataset_recorder_middleware_name():
    """Test that middleware has correct name property."""

    recorder = DatasetRecorder(dataset_id=1)
    assert recorder.name == "DatasetRecorder"


def test_dataset_recorder_is_async_native():
    """Test that DatasetRecorder reports async support."""

    recorder = DatasetRecorder(dataset_id=1)
    assert recorder.is_async_native() is True


def test_recording_config_defaults():
    """Test RecordingConfig default values."""

    config = RecordingConfig(dataset_id=1)

    assert config.dataset_id == 1
    assert config.dashboard_url == "http://localhost:8000"
    assert config.filter.only_success is True
    assert not config.filter.tool_filter
    assert config.filter.sample_rate == 1.0
    assert config.auto_assertions is True
    assert config.filter.max_per_session is None
    assert not config.tags
    assert config.name_generator is None


if __name__ == "__main__":
    # Run all tests
    pytest.main([__file__, "-v"])
