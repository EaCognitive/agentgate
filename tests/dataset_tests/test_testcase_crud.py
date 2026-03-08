"""Test Case CRUD tests."""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Dataset, TestCase, TestCaseStatus


class TestTestCaseCRUD:
    """Test test case CRUD operations."""

    def test_list_test_cases(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test listing test cases in a dataset."""
        assert test_dataset.id is not None
        # Add test cases
        assert test_dataset.id is not None
        for i in range(3):
            test_case = TestCase(
                dataset_id=test_dataset.id,
                name=f"Test {i}",
                tool="api_call",
                inputs={"test": i},
            )
            session.add(test_case)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/tests",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    def test_list_test_cases_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test listing test cases for non-existent dataset returns 404."""
        response = client.get(
            "/api/datasets/99999/tests",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    def test_list_test_cases_with_status_filter(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test filtering test cases by status."""
        assert test_dataset.id is not None
        # Add test cases with different statuses
        assert test_dataset.id is not None
        test_case_active = TestCase(
            dataset_id=test_dataset.id,
            name="Active Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.ACTIVE,
        )
        test_case_disabled = TestCase(
            dataset_id=test_dataset.id,
            name="Disabled Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.DISABLED,
        )
        session.add(test_case_active)
        session.add(test_case_disabled)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/tests?status_filter=active",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert all(tc["status"] == "active" for tc in data)

    def test_list_test_cases_with_tool_filter(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test filtering test cases by tool."""
        assert test_dataset.id is not None
        test_case_api = TestCase(
            dataset_id=test_dataset.id,
            name="API Test",
            tool="api_call",
            inputs={},
        )
        assert test_dataset.id is not None
        test_case_db = TestCase(
            dataset_id=test_dataset.id,
            name="DB Test",
            tool="database_query",
            inputs={},
        )
        session.add(test_case_api)
        session.add(test_case_db)
        session.commit()

        response = client.get(
            f"/api/datasets/{test_dataset.id}/tests?tool=api_call",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert all(tc["tool"] == "api_call" for tc in data)

    def test_create_test_case(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test creating a new test case."""
        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "dataset_id": test_dataset.id,
                "name": "New Test",
                "description": "Test description",
                "tool": "api_call",
                "inputs": {"url": "https://example.com"},
                "expected_output": {"status": 200},
                "assertions": [
                    {
                        "type": "equals",
                        "expected": {"status": 200},
                    }
                ],
                "tags": ["api", "test"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Test"
        assert data["tool"] == "api_call"

    def test_create_test_case_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test creating test case for non-existent dataset returns 404."""
        response = client.post(
            "/api/datasets/99999/tests",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "dataset_id": 99999,
                "name": "New Test",
                "tool": "api_call",
                "inputs": {},
            },
        )
        assert response.status_code == 404

    def test_create_test_case_developer_cannot_add_to_others_dataset(
        self, client: TestClient, developer_token: str, test_dataset: Dataset
    ) -> None:
        """Test that developers cannot add test cases to datasets they don't own."""
        assert test_dataset.id is not None
        response = client.post(
            f"/api/datasets/{test_dataset.id}/tests",
            headers={"Authorization": f"Bearer {developer_token}"},
            json={
                "dataset_id": test_dataset.id,
                "name": "Hacked Test",
                "tool": "api_call",
                "inputs": {},
            },
        )
        assert response.status_code == 404

    def test_get_test_case(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test getting a test case by ID."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Test Case",
            tool="api_call",
            inputs={},
        )
        session.add(test_case)
        session.commit()
        session.refresh(test_case)

        response = client.get(
            f"/api/datasets/{test_dataset.id}/tests/{test_case.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_case.id
        assert data["name"] == "Test Case"

    def test_get_test_case_not_found(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test getting non-existent test case returns 404."""
        assert test_dataset.id is not None
        response = client.get(
            f"/api/datasets/{test_dataset.id}/tests/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    def test_update_test_case_all_fields(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test updating all fields of a test case."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Original",
            tool="api_call",
            inputs={"old": "value"},
        )
        session.add(test_case)
        session.commit()
        session.refresh(test_case)

        response = client.patch(
            f"/api/datasets/{test_dataset.id}/tests/{test_case.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "name": "Updated",
                "description": "New description",
                "inputs": {"new": "value"},
                "expected_output": {"result": "success"},
                "assertions": [{"type": "equals", "expected": "success"}],
                "status": "disabled",
                "tags": ["updated"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated"
        assert data["description"] == "New description"
        assert data["inputs"] == {"new": "value"}
        assert data["expected_output"] == {"result": "success"}
        assert data["status"] == "disabled"
        assert data["tags"] == ["updated"]

    def test_update_test_case_not_found(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test updating non-existent test case returns 404."""
        assert test_dataset.id is not None
        response = client.patch(
            f"/api/datasets/{test_dataset.id}/tests/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": "Updated"},
        )
        assert response.status_code == 404

    def test_delete_test_case(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test deleting a test case."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="To Delete",
            tool="api_call",
            inputs={},
        )
        session.add(test_case)
        session.commit()
        session.refresh(test_case)

        response = client.delete(
            f"/api/datasets/{test_dataset.id}/tests/{test_case.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Test case deleted"

    def test_delete_test_case_not_found(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test deleting non-existent test case returns 404."""
        response = client.delete(
            f"/api/datasets/{test_dataset.id}/tests/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
