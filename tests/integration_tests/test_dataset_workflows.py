"""Dataset, Test Case, and Test Run integration tests."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    TestCase,
    TestCaseStatus,
    TestResult,
    TestResultStatus,
    Trace,
    TraceStatus,
)


@patch("server.utils.test_runner.run_tests_async", new_callable=AsyncMock)
def test_dataset_testing_workflow(
    mock_run_tests: AsyncMock,
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Test dataset creation and execution workflow."""
    _ = mock_run_tests
    # Step 1: Create dataset
    dataset_data = {
        "name": "E2E Test Dataset",
        "description": "Integration test dataset",
        "tags": ["integration", "e2e"],
    }
    response = client.post("/api/datasets", json=dataset_data, headers=admin_headers)
    assert response.status_code == 201
    dataset = response.json()
    dataset_id = dataset["id"]

    # Step 2: Create successful trace
    trace = Trace(
        trace_id="dataset_trace_001",
        agent_id="test-agent",
        tool="calculator",
        inputs={"operation": "add", "a": 2, "b": 3},
        status=TraceStatus.SUCCESS,
        output={"result": 5},
        started_at=datetime.now(timezone.utc),
    )
    session.add(trace)
    session.commit()
    session.refresh(trace)  # Ensure trace is in session

    # Step 3: Create test case from trace
    test_case_data = {
        "dataset_id": dataset_id,
        "trace_id": "dataset_trace_001",
        "name": "Addition Test",
        "description": "Test calculator addition",
    }
    response = client.post(
        f"/api/datasets/{dataset_id}/tests/from-trace",
        json=test_case_data,
        headers=admin_headers,
    )
    assert response.status_code == 201
    test_case = response.json()
    assert test_case["tool"] == "calculator"
    assert test_case["expected_output"] == {"result": 5}

    # Step 4: Create test run
    run_data = {"dataset_id": dataset_id, "name": "First Run", "config": {"timeout": 30}}
    response = client.post(f"/api/datasets/{dataset_id}/runs", json=run_data, headers=admin_headers)
    assert response.status_code == 201
    run = response.json()
    run_id = run["run_id"]

    # Step 5: Create test result (simulate execution)
    test_result = TestResult(
        run_id=run_id,
        test_case_id=test_case["id"],
        status=TestResultStatus.PASSED,
        actual_output={"result": 5},
        duration_ms=120,
    )
    session.add(test_result)
    session.commit()

    # Step 6: Get run results
    response = client.get(
        f"/api/datasets/{dataset_id}/runs/{run_id}/results", headers=admin_headers
    )
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 1
    assert results[0]["status"] == "passed"


def test_dataset_bulk_operations(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test bulk test case creation from multiple traces."""
    # Create dataset
    response = client.post(
        "/api/datasets",
        json={"name": "Bulk Dataset", "description": "Bulk operations test"},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Create multiple successful traces
    trace_ids = []
    for i in range(5):
        trace = Trace(
            trace_id=f"bulk_trace_{i}",
            agent_id="test-agent",
            tool="test_tool",
            inputs={"index": i},
            status=TraceStatus.SUCCESS,
            output={"result": i * 2},
            started_at=datetime.now(timezone.utc),
        )
        session.add(trace)
        trace_ids.append(trace.trace_id)
    session.commit()

    # Bulk create test cases
    response = client.post(
        f"/api/datasets/{dataset_id}/tests/bulk-from-traces",
        json=trace_ids,
        headers=admin_headers,
    )
    assert response.status_code == 200
    test_cases = response.json()
    assert len(test_cases) == 5

    # Verify dataset stats
    response = client.get(f"/api/datasets/{dataset_id}/stats", headers=admin_headers)
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_tests"] == 5


def test_dataset_pytest_export(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test pytest code generation from dataset."""
    # Create dataset with test case
    response = client.post(
        "/api/datasets",
        json={"name": "Pytest Export Dataset"},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Create test case
    test_data = {
        "dataset_id": dataset_id,
        "name": "Test Export",
        "description": "Export test",
        "tool": "sample_tool",
        "inputs": {"param": "value"},
        "expected_output": {"result": "success"},
        "assertions": [{"type": "equals", "expected": {"result": "success"}}],
    }
    client.post(f"/api/datasets/{dataset_id}/tests", json=test_data, headers=admin_headers)

    # Export as pytest
    response = client.post(f"/api/datasets/{dataset_id}/export/pytest", headers=admin_headers)
    assert response.status_code == 200
    pytest_code = response.text
    assert "import pytest" in pytest_code
    assert "def test_" in pytest_code
    assert "sample_tool" in pytest_code


def test_dataset_test_case_lifecycle(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test complete test case CRUD operations."""
    # Create dataset
    response = client.post(
        "/api/datasets",
        json={"name": "CRUD Dataset"},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Create test case
    test_data = {
        "dataset_id": dataset_id,
        "name": "CRUD Test",
        "description": "Test CRUD",
        "tool": "crud_tool",
        "inputs": {"action": "create"},
        "expected_output": {"status": "created"},
    }
    response = client.post(
        f"/api/datasets/{dataset_id}/tests", json=test_data, headers=admin_headers
    )
    test_id = response.json()["id"]

    # Read test case
    response = client.get(f"/api/datasets/{dataset_id}/tests/{test_id}", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["name"] == "CRUD Test"

    # Update test case
    update_data = {
        "name": "Updated CRUD Test",
        "description": "Updated description",
    }
    response = client.patch(
        f"/api/datasets/{dataset_id}/tests/{test_id}",
        json=update_data,
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Updated CRUD Test"

    # Delete test case
    response = client.delete(f"/api/datasets/{dataset_id}/tests/{test_id}", headers=admin_headers)
    assert response.status_code == 200

    # Verify deletion
    response = client.get(f"/api/datasets/{dataset_id}/tests/{test_id}", headers=admin_headers)
    assert response.status_code == 404


def test_dataset_filtering_and_statistics(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test dataset filtering and statistics aggregation."""
    # Create dataset
    response = client.post(
        "/api/datasets",
        json={"name": "Stats Dataset", "tags": ["stats", "testing"]},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Create test cases with different statuses
    statuses = [TestCaseStatus.ACTIVE, TestCaseStatus.ACTIVE, TestCaseStatus.DISABLED]
    for i, status_val in enumerate(statuses):
        test_case = TestCase(
            dataset_id=dataset_id,
            name=f"Test {i}",
            tool="test_tool",
            inputs={"index": i},
            status=status_val,
        )
        session.add(test_case)
    session.commit()

    # List with status filter
    response = client.get(
        f"/api/datasets/{dataset_id}/tests?status_filter=active",
        headers=admin_headers,
    )
    assert response.status_code == 200
    active_tests = response.json()
    assert len(active_tests) == 2

    # Get dataset stats
    response = client.get(f"/api/datasets/{dataset_id}/stats", headers=admin_headers)
    assert response.status_code == 200
    stats = response.json()
    assert stats["by_status"]["active"] == 2
    assert stats["by_status"]["disabled"] == 1


def test_dataset_version_control_workflow(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """Test dataset versioning through updates and modifications."""
    # Create initial dataset
    response = client.post(
        "/api/datasets",
        json={"name": "Versioned Dataset", "description": "v1", "tags": ["v1"]},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Add test cases (version 1)
    for i in range(3):
        test_data = {
            "dataset_id": dataset_id,
            "name": f"Test v1.{i}",
            "tool": "versioned_tool",
            "inputs": {"version": 1, "index": i},
            "expected_output": {"result": f"v1_{i}"},
        }
        client.post(f"/api/datasets/{dataset_id}/tests", json=test_data, headers=admin_headers)

    # Update dataset metadata (version 2)
    update_data = {"description": "v2 - Updated", "tags": ["v1", "v2"]}
    response = client.patch(f"/api/datasets/{dataset_id}", json=update_data, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["description"] == "v2 - Updated"

    # Verify test cases still exist
    response = client.get(f"/api/datasets/{dataset_id}/tests", headers=admin_headers)
    assert response.status_code == 200
    assert len(response.json()) == 3


@patch("server.utils.test_runner.run_tests_async", new_callable=AsyncMock)
def test_dataset_test_run_comparison(
    mock_run_tests: AsyncMock,
    client: TestClient,
    admin_headers: dict[str, str],
    session: Session,
) -> None:
    """Test comparing results across multiple test runs."""
    _ = mock_run_tests
    # Create dataset
    response = client.post(
        "/api/datasets",
        json={"name": "Comparison Dataset"},
        headers=admin_headers,
    )
    dataset_id = response.json()["id"]

    # Create test case
    test_data = {
        "dataset_id": dataset_id,
        "name": "Comparison Test",
        "tool": "comparison_tool",
        "inputs": {"param": "test"},
        "expected_output": {"result": "success"},
    }
    response = client.post(
        f"/api/datasets/{dataset_id}/tests", json=test_data, headers=admin_headers
    )
    test_case_id = response.json()["id"]

    # Create first run
    response = client.post(
        f"/api/datasets/{dataset_id}/runs",
        json={"dataset_id": dataset_id, "name": "Run 1"},
        headers=admin_headers,
    )
    run1_id = response.json()["run_id"]

    # Create result for run 1 (passed)
    result1 = TestResult(
        run_id=run1_id,
        test_case_id=test_case_id,
        status=TestResultStatus.PASSED,
        actual_output={"result": "success"},
        duration_ms=100,
    )
    session.add(result1)

    # Create second run
    response = client.post(
        f"/api/datasets/{dataset_id}/runs",
        json={"dataset_id": dataset_id, "name": "Run 2"},
        headers=admin_headers,
    )
    run2_id = response.json()["run_id"]

    # Create result for run 2 (failed)
    result2 = TestResult(
        run_id=run2_id,
        test_case_id=test_case_id,
        status=TestResultStatus.FAILED,
        actual_output={"result": "error"},
        duration_ms=150,
        error_message="Unexpected error",
    )
    session.add(result2)
    session.commit()

    # Get runs and compare
    response = client.get(f"/api/datasets/{dataset_id}/runs", headers=admin_headers)
    assert response.status_code == 200
    runs = response.json()
    assert len(runs) >= 2
