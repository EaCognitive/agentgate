"""Dataset CRUD tests."""

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Dataset, TestCase, User


class TestDatasetCRUD:
    """Test dataset CRUD operations."""

    def test_list_datasets_admin(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test that admin can list all datasets."""
        response = client.get(
            "/api/datasets",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert any(d["id"] == test_dataset.id for d in data)

    def test_list_datasets_with_pagination(
        self, client: TestClient, admin_token: str, session: Session, admin_user: User
    ) -> None:
        """Test dataset listing with limit and offset."""
        # Create multiple datasets
        for i in range(10):
            dataset = Dataset(
                name=f"Dataset {i}",
                description=f"Dataset {i}",
                created_by=admin_user.id,
            )
            session.add(dataset)
        session.commit()

        response = client.get(
            "/api/datasets?limit=5&offset=0",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5

    def test_list_datasets_developer_only_own(
        self, client: TestClient, developer_token: str, session: Session, developer_user: User
    ) -> None:
        """Test that developers can only see their own datasets."""
        # Create dataset owned by developer
        dataset = Dataset(
            name="Developer Dataset",
            description="Test",
            created_by=developer_user.id,
        )
        session.add(dataset)
        session.commit()

        response = client.get(
            "/api/datasets",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        # Should only see their own dataset
        assert all(d["created_by"] == developer_user.id for d in data)

    def test_create_dataset(self, client: TestClient, admin_token: str) -> None:
        """Test creating a new dataset."""
        response = client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "name": "New Dataset",
                "description": "Test dataset",
                "tags": ["test", "api"],
                "metadata_json": {"key": "value"},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Dataset"
        assert data["description"] == "Test dataset"
        assert data["tags"] == ["test", "api"]
        # metadata_json is stored but not returned in read schema
        assert data["test_count"] == 0

    def test_create_dataset_without_permission(self, client: TestClient, viewer_token: str) -> None:
        """Test that viewers cannot create datasets."""
        response = client.post(
            "/api/datasets",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={
                "name": "New Dataset",
                "description": "Test dataset",
            },
        )
        assert response.status_code == 403

    def test_get_dataset_by_id(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test getting a dataset by ID."""
        response = client.get(
            f"/api/datasets/{test_dataset.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_dataset.id
        assert data["name"] == "Test Dataset"

    def test_get_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test getting non-existent dataset returns 404."""
        response = client.get(
            "/api/datasets/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_get_dataset_developer_cannot_access_others(
        self, client: TestClient, developer_token: str, test_dataset: Dataset
    ) -> None:
        """Test that developers cannot access datasets they don't own."""
        response = client.get(
            f"/api/datasets/{test_dataset.id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert response.status_code == 404

    def test_update_dataset(
        self, client: TestClient, admin_token: str, test_dataset: Dataset
    ) -> None:
        """Test updating a dataset."""
        response = client.patch(
            f"/api/datasets/{test_dataset.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "name": "Updated Dataset",
                "description": "Updated description",
                "tags": ["updated"],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Dataset"
        assert data["description"] == "Updated description"
        assert data["tags"] == ["updated"]

    def test_update_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test updating non-existent dataset returns 404."""
        response = client.patch(
            "/api/datasets/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": "Updated"},
        )
        assert response.status_code == 404

    def test_update_dataset_developer_cannot_update_others(
        self, client: TestClient, developer_token: str, test_dataset: Dataset
    ) -> None:
        """Test that developers cannot update datasets they don't own."""
        response = client.patch(
            f"/api/datasets/{test_dataset.id}",
            headers={"Authorization": f"Bearer {developer_token}"},
            json={"name": "Hacked"},
        )
        assert response.status_code == 404

    def test_delete_dataset(
        self, client: TestClient, admin_token: str, session: Session, admin_user: User
    ) -> None:
        """Test deleting a dataset."""
        # Create dataset with test cases
        dataset = Dataset(
            name="To Delete",
            description="Test",
            created_by=admin_user.id,
        )
        session.add(dataset)
        session.commit()
        session.refresh(dataset)

        # Add test cases
        assert dataset.id is not None
        for i in range(3):
            test_case = TestCase(
                dataset_id=dataset.id,
                name=f"Test {i}",
                tool="api_call",
                inputs={"test": i},
            )
            session.add(test_case)
        session.commit()

        response = client.delete(
            f"/api/datasets/{dataset.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Dataset deleted"
        assert data["test_cases_deleted"] == 3

    def test_delete_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test deleting non-existent dataset returns 404."""
        response = client.delete(
            "/api/datasets/99999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    def test_delete_dataset_developer_cannot_delete_others(
        self, client: TestClient, developer_token: str, test_dataset: Dataset
    ) -> None:
        """Test that developers cannot delete datasets they don't own."""
        assert test_dataset.id is not None
        response = client.delete(
            f"/api/datasets/{test_dataset.id}",
            headers={"Authorization": f"Bearer {developer_token}"},
        )
        assert response.status_code == 404
