"""Tests for Dataset models."""

from server.models.schemas import DatasetCreate, DatasetRead, DatasetUpdate, utc_now


class TestDatasetModels:
    """Test Dataset-related model classes."""

    def test_dataset_create(self):
        """Test DatasetCreate model."""
        dataset = DatasetCreate(
            name="Test Dataset",
            description="A test dataset",
            tags=["testing", "validation"],
            metadata_json={"version": "1.0"},
        )

        assert dataset.name == "Test Dataset"
        assert dataset.description == "A test dataset"
        assert dataset.tags == ["testing", "validation"]
        assert dataset.metadata_json == {"version": "1.0"}

    def test_dataset_create_minimal(self):
        """Test DatasetCreate with minimal fields."""
        dataset = DatasetCreate(name="Simple Dataset")

        assert dataset.name == "Simple Dataset"
        assert dataset.description is None
        assert dataset.tags is None

    def test_dataset_read(self):
        """Test DatasetRead model."""
        now = utc_now()
        dataset = DatasetRead(
            id=1,
            name="Test Dataset",
            description="A test dataset",
            tags=["testing"],
            test_count=10,
            last_run_at=now,
            last_run_pass_rate=0.95,
            created_at=now,
            updated_at=now,
            created_by=1,
        )

        assert dataset.id == 1
        assert dataset.test_count == 10
        assert dataset.last_run_pass_rate == 0.95

    def test_dataset_update(self):
        """Test DatasetUpdate model."""
        update = DatasetUpdate(
            name="Updated Dataset", description="Updated description", tags=["updated"]
        )

        assert update.name == "Updated Dataset"
        assert update.description == "Updated description"
