"""Tests for TestRun models."""

from datetime import timedelta

from server.models.schemas import (
    TestResultRead,
    TestResultStatus,
    TestRunCreate,
    TestRunRead,
    TestRunStatus,
    utc_now,
)


class TestTestRunModels:
    """Test TestRun-related model classes."""

    def test_test_run_create(self):
        """Test TestRunCreate model."""
        run = TestRunCreate(dataset_id=1, name="Test Run 1", config={"parallel": True})

        assert run.dataset_id == 1
        assert run.name == "Test Run 1"
        assert run.config == {"parallel": True}

    def test_test_run_read(self):
        """Test TestRunRead model."""
        now = utc_now()
        run = TestRunRead(
            id=1,
            run_id="run-123",
            dataset_id=1,
            name="Test Run 1",
            status=TestRunStatus.COMPLETED,
            total_tests=10,
            passed_count=8,
            failed_count=1,
            error_count=1,
            skipped_count=0,
            started_at=now,
            completed_at=now + timedelta(seconds=30),
            duration_ms=30000.0,
            created_at=now,
        )

        assert run.id == 1
        assert run.status == TestRunStatus.COMPLETED
        assert run.passed_count == 8
        assert run.failed_count == 1

    def test_test_result_read(self):
        """Test TestResultRead model."""
        now = utc_now()
        result = TestResultRead(
            id=1,
            run_id="run-123",
            test_case_id=1,
            status=TestResultStatus.PASSED,
            actual_output={"result": "success"},
            assertion_results=[{"passed": True}],
            error_message=None,
            duration_ms=100.0,
            executed_at=now,
        )

        assert result.id == 1
        assert result.status == TestResultStatus.PASSED
        assert result.actual_output == {"result": "success"}
