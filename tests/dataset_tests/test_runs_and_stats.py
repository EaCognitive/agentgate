"""Test runs and statistics tests."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Dataset, TestCase, TestCaseStatus, TestRun


class TestTestRunManagement:
    """Test test run management endpoints."""

    def test_list_test_runs(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test listing test runs for a dataset."""
        assert test_dataset.id is not None
        # Create test runs
        assert test_dataset.id is not None
        for i in range(3):
            run = TestRun(
                run_id=f"run_{i}",
                dataset_id=test_dataset.id,
                name=f"Test Run {i}",
                triggered_by=1,
                total_tests=10,
            )
            session.add(run)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/runs",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    @patch("server.utils.test_runner.run_tests_async", new_callable=AsyncMock)
    def test_create_test_run(
        self,
        mock_run_tests: AsyncMock,
        *,
        client: TestClient,
        admin_token: str,
        test_dataset: Dataset,
        session: Session,
    ) -> None:
        """Test creating a new test run."""
        assert test_dataset.id is not None
        # Add some test cases
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.ACTIVE,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/runs",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "dataset_id": test_dataset.id,
                "name": "New Test Run",
                "config": {"timeout": 30},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Test Run"
        assert data["total_tests"] == 1
        assert "run_" in data["run_id"]
        # Verify background task was scheduled
        mock_run_tests.assert_called_once()

    def test_create_test_run_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test creating test run for non-existent dataset returns 404."""
        response = client.post(
            "/api/datasets/99999/runs",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "dataset_id": 99999,
                "name": "Test Run",
            },
        )
        assert response.status_code == 404

    def test_get_test_run(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test getting a test run by ID."""
        assert test_dataset.id is not None
        run = TestRun(
            run_id="run_get_test",
            dataset_id=test_dataset.id,
            name="Test Run",
            triggered_by=1,
            total_tests=5,
        )
        session.add(run)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/runs/{run.run_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["run_id"] == "run_get_test"
        assert data["total_tests"] == 5

    def test_get_test_run_not_found(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test getting non-existent test run returns 404."""
        assert test_dataset.id is not None
        response = client.get(
            f"/api/datasets/{test_dataset.id}/runs/non_existent_run",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    def test_get_test_run_results(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test getting test run results."""
        assert test_dataset.id is not None
        # Create test run with results
        assert test_dataset.id is not None
        run = TestRun(
            run_id="run_results_test",
            dataset_id=test_dataset.id,
            name="Test Run",
            triggered_by=1,
            total_tests=2,
        )
        session.add(run)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/runs/{run.run_id}/results",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_test_run_results_not_found(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test getting results for non-existent run returns 404."""
        assert test_dataset.id is not None
        response = client.get(
            f"/api/datasets/{test_dataset.id}/runs/non_existent_run/results",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    def test_get_test_run_results_with_status_filter(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test filtering test results by status."""
        assert test_dataset.id is not None
        run = TestRun(
            run_id="run_filter_test",
            dataset_id=test_dataset.id,
            name="Test Run",
            triggered_by=1,
            total_tests=1,
        )
        session.add(run)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/runs/{run.run_id}/results?status_filter=passed",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200


class TestDatasetStatistics:
    """Test dataset statistics endpoint."""

    def test_get_dataset_stats(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test getting dataset statistics."""
        assert test_dataset.id is not None
        # Add test cases with different statuses
        for status in [TestCaseStatus.ACTIVE, TestCaseStatus.DISABLED, TestCaseStatus.DRAFT]:
            test_case = TestCase(
                dataset_id=test_dataset.id,
                name=f"Test {status.value}",
                tool="api_call",
                inputs={},
                status=status,
            )
            session.add(test_case)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["dataset_id"] == test_dataset.id
        assert data["name"] == test_dataset.name
        assert "by_status" in data
        assert "by_tool" in data
        assert "recent_runs" in data

    def test_get_dataset_stats_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test getting stats for non-existent dataset returns 404."""
        response = client.get(
            "/api/datasets/99999/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
