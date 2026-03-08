"""Tests for Pytest Export models."""

from server.models.schemas import PytestExportConfig, PytestExportResult


class TestPytestExportModels:
    """Test Pytest export model classes."""

    def test_pytest_export_config(self):
        """Test PytestExportConfig model."""
        config = PytestExportConfig(
            dataset_id=1,
            output_dir="tests/generated",
            file_prefix="test_",
            include_assertions=True,
            include_comments=True,
            async_tests=False,
        )

        assert config.dataset_id == 1
        assert config.output_dir == "tests/generated"
        assert config.include_assertions is True

    def test_pytest_export_config_defaults(self):
        """Test PytestExportConfig with defaults."""
        config = PytestExportConfig(dataset_id=1)

        assert config.dataset_id == 1
        assert config.output_dir == "tests/generated"
        assert config.file_prefix == "test_"
        assert config.include_assertions is True
        assert config.async_tests is False

    def test_pytest_export_result(self):
        """Test PytestExportResult model."""
        result = PytestExportResult(
            file_path="tests/generated/test_dataset.py",
            test_count=10,
            content="# Generated test file",
        )

        assert result.file_path == "tests/generated/test_dataset.py"
        assert result.test_count == 10
        assert "Generated" in result.content
