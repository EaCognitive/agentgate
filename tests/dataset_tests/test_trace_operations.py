"""Trace operations tests (create from trace, bulk operations)."""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Dataset, Trace, TraceStatus


class TestCreateFromTrace:
    """Test creating test cases from traces."""

    def test_create_from_trace_basic(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, test_trace: Trace
    ) -> None:
        """Test creating test case from a successful trace."""
        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/from-trace",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "trace_id": test_trace.trace_id,
                "dataset_id": test_dataset.id,  # Required by schema
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["tool"] == test_trace.tool
        assert data["inputs"] == test_trace.inputs
        assert data["expected_output"] == test_trace.output
        assert data["source_trace_id"] == test_trace.trace_id

    def test_create_from_trace_with_custom_name(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, test_trace: Trace
    ) -> None:
        """Test creating test case from trace with custom name."""
        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/from-trace",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "trace_id": test_trace.trace_id,
                "dataset_id": test_dataset.id,
                "name": "Custom Test Name",
                "description": "Custom description",
                "tags": ["custom", "tag"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Custom Test Name"
        assert data["description"] == "Custom description"
        assert data["tags"] == ["custom", "tag"]

    def test_create_from_trace_with_custom_assertions(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, test_trace: Trace
    ) -> None:
        """Test creating test case from trace with custom assertions."""
        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/from-trace",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "trace_id": test_trace.trace_id,
                "dataset_id": test_dataset.id,
                "assertions": [
                    {"type": "contains", "expected": "success"},
                    {"type": "type_check", "expected": "dict"},
                ],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert len(data["assertions"]) == 2

    def test_create_from_trace_dataset_not_found(
        self, client: TestClient, admin_token: str, test_trace: Trace
    ) -> None:
        """Test creating from trace for non-existent dataset returns 404."""
        response = client.post(
            "/api/datasets/99999/tests/from-trace",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "trace_id": test_trace.trace_id,
                "dataset_id": 99999,
            },
        )
        assert response.status_code == 404

    def test_create_from_trace_trace_not_found(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test creating from non-existent trace returns 404."""
        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/from-trace",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "trace_id": "non_existent_trace",
                "dataset_id": test_dataset.id,
            },
        )
        assert response.status_code == 404

    def test_create_from_trace_failed_trace_rejected(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test that failed traces cannot be converted to test cases."""
        # Create a failed trace
        trace = Trace(
            trace_id="trace_failed_123",
            tool="api_call",
            inputs={"url": "https://example.com"},
            error="Connection timeout",
            status=TraceStatus.FAILED,
        )
        session.add(trace)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/from-trace",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "trace_id": trace.trace_id,
                "dataset_id": test_dataset.id,
            },
        )
        assert response.status_code == 400
        assert "successful traces" in response.json()["detail"].lower()


class TestBulkOperations:
    """Test bulk operations."""

    def test_bulk_create_from_traces(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test bulk creating test cases from multiple traces."""
        # Create multiple successful traces
        trace_ids = []
        for i in range(3):
            trace = Trace(
                trace_id=f"trace_bulk_{i}",
                tool="api_call",
                inputs={"index": i},
                output={"result": i},
                status=TraceStatus.SUCCESS,
            )
            session.add(trace)
            trace_ids.append(trace.trace_id)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/bulk-from-traces",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=trace_ids,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    def test_bulk_create_from_traces_dataset_not_found(
        self, client: TestClient, admin_token: str
    ) -> None:
        """Test bulk create for non-existent dataset returns 404."""
        response = client.post(
            "/api/datasets/99999/tests/bulk-from-traces",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=["trace_1", "trace_2"],
        )
        assert response.status_code == 404

    def test_bulk_create_skips_failed_traces(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test that bulk create skips failed traces."""
        # Create mix of successful and failed traces
        success_trace = Trace(
            trace_id="trace_success_bulk",
            tool="api_call",
            inputs={},
            output={"result": "ok"},
            status=TraceStatus.SUCCESS,
        )
        failed_trace = Trace(
            trace_id="trace_failed_bulk",
            tool="api_call",
            inputs={},
            error="Failed",
            status=TraceStatus.FAILED,
        )
        session.add(success_trace)
        session.add(failed_trace)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests/bulk-from-traces",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=["trace_success_bulk", "trace_failed_bulk"],
        )
        assert response.status_code == 200
        data = response.json()
        # Only successful trace should be converted
        assert len(data) == 1
        assert data[0]["source_trace_id"] == "trace_success_bulk"
