"""Tests for TestCase models."""

from server.models.schemas import Assertion, AssertionType, TestCaseCreate, TestCaseFromTrace


class TestTestCaseModels:
    """Test TestCase-related model classes."""

    def test_test_case_create(self):
        """Test TestCaseCreate model."""
        test_case = TestCaseCreate(
            dataset_id=1,
            name="Test Case 1",
            description="A test case",
            tool="test_tool",
            inputs={"param": "value"},
            expected_output={"result": "success"},
            assertions=[{"type": "equals", "expected": "success"}],
            source_trace_id="trace-123",
            tags=["regression"],
        )

        assert test_case.dataset_id == 1
        assert test_case.name == "Test Case 1"
        assert test_case.tool == "test_tool"
        assert test_case.inputs == {"param": "value"}

    def test_test_case_from_trace(self):
        """Test TestCaseFromTrace model."""
        test_case = TestCaseFromTrace(
            trace_id="trace-123",
            dataset_id=1,
            name="From Trace",
            description="Created from trace",
            assertions=[{"type": "equals"}],
            tags=["trace-based"],
        )

        assert test_case.trace_id == "trace-123"
        assert test_case.dataset_id == 1

    def test_assertion_model(self):
        """Test Assertion model."""
        assertion = Assertion(
            type=AssertionType.EQUALS,
            field="result",
            expected="success",
            message="Result should be success",
        )

        assert assertion.type == AssertionType.EQUALS
        assert assertion.field == "result"
        assert assertion.expected == "success"

    def test_assertion_regex(self):
        """Test Assertion with regex pattern."""
        assertion = Assertion(
            type=AssertionType.MATCHES_REGEX, pattern=r"^success.*", message="Should match pattern"
        )

        assert assertion.type == AssertionType.MATCHES_REGEX
        assert assertion.pattern == r"^success.*"
