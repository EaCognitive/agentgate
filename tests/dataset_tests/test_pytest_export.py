"""Pytest export and generation tests."""

import ast

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Dataset, TestCase, TestCaseStatus
from server.routers.datasets_operations import (
    PytestExportConfig,
    _generate_assertion_code,
    _generate_test_name,
    generate_pytest_code,
)


class TestPytestExport:
    """Test pytest export functionality."""

    def test_export_pytest_basic(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test basic pytest export."""
        assert test_dataset.id is not None
        # Add active test case
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Test API Call",
            tool="api_call",
            inputs={"url": "https://example.com"},
            expected_output={"status": 200},
            status=TestCaseStatus.ACTIVE,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        code = response.text
        assert "import pytest" in code
        assert "from ea_agentgate import Agent" in code
        assert "def test_" in code

    def test_export_pytest_async(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test pytest export with async tests."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Async Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.ACTIVE,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest?async_tests=true",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        code = response.text
        assert "import asyncio" in code
        assert "@pytest.mark.asyncio" in code
        assert "async def test_" in code
        assert "await agent.acall" in code

    def test_export_pytest_without_assertions(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test pytest export without assertions."""
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
            f"/api/datasets/{test_dataset.id}/export/pytest?include_assertions=false",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        code = response.text
        # Should still have the test but without custom assertions
        assert "def test_" in code

    def test_export_pytest_with_comments(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test pytest export with comments."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Test",
            description="This is a test description",
            tool="api_call",
            inputs={},
            source_trace_id="trace_123",
            status=TestCaseStatus.ACTIVE,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest?include_comments=true",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        code = response.text
        assert "This is a test description" in code
        assert "Source trace: trace_123" in code

    def test_export_pytest_dataset_not_found(self, client: TestClient, admin_token: str) -> None:
        """Test pytest export for non-existent dataset returns 404."""
        response = client.post(
            "/api/datasets/99999/export/pytest",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 404

    def test_export_pytest_no_active_tests(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test pytest export with no active test cases returns 400."""
        assert test_dataset.id is not None
        # Add only disabled test case
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Disabled Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.DISABLED,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 400
        assert "no active test cases" in response.json()["detail"].lower()

    def test_export_pytest_with_assertions(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test pytest export with various assertion types."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name="Test with Assertions",
            tool="api_call",
            inputs={},
            assertions=[
                {"type": "equals", "expected": "success", "message": "Should equal success"},
                {"type": "contains", "expected": "ok", "field": "status"},
                {"type": "not_contains", "expected": "error"},
                {"type": "matches_regex", "pattern": "^[a-z]+$"},
                {"type": "type_check", "expected": "dict"},
            ],
            status=TestCaseStatus.ACTIVE,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest?include_assertions=true",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        code = response.text
        assert "assert result ==" in code or "Should equal success" in code

    def test_export_pytest_skips_non_active_tests(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Test that pytest export skips disabled/draft test cases."""
        assert test_dataset.id is not None
        # Add active and disabled test cases
        assert test_dataset.id is not None
        active_test = TestCase(
            dataset_id=test_dataset.id,
            name="Active Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.ACTIVE,
        )
        disabled_test = TestCase(
            dataset_id=test_dataset.id,
            name="Disabled Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.DISABLED,
        )
        session.add(active_test)
        session.add(disabled_test)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200
        code = response.text
        # Should only include the active test
        assert "test_active_test" in code.lower()
        assert "test_disabled_test" not in code.lower()

    def test_export_pytest_escapes_untrusted_docstring_content(
        self, client: TestClient, admin_token: str, test_dataset: Dataset, session: Session
    ) -> None:
        """Untrusted test names should not break generated Python syntax."""
        assert test_dataset.id is not None
        test_case = TestCase(
            dataset_id=test_dataset.id,
            name='Danger """\n__import__("os").system("echo owned")',
            tool="api_call",
            inputs={},
            status=TestCaseStatus.ACTIVE,
        )
        session.add(test_case)
        session.commit()

        response = client.post(
            f"/api/datasets/{test_dataset.id}/export/pytest",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200

        code = response.text
        # Generated file remains syntactically valid, and attacker-controlled text
        # is escaped into a literal docstring.
        ast.parse(code)
        assert '\\"\\"\\"' in code
        assert '\n__import__("os").system("echo owned")' not in code


class TestPytestGenerationHelpers:
    """Test pytest code generation helper functions."""

    def test_generate_pytest_code_with_inactive_tests(self, test_dataset: Dataset) -> None:
        """Test that generate_pytest_code skips non-active test cases."""
        assert test_dataset.id is not None

        # Create test cases with different statuses
        active_test = TestCase(
            dataset_id=test_dataset.id,
            name="Active Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.ACTIVE,
        )
        disabled_test = TestCase(
            dataset_id=test_dataset.id,
            name="Disabled Test",
            tool="api_call",
            inputs={},
            status=TestCaseStatus.DISABLED,
        )

        config = PytestExportConfig(
            dataset_id=test_dataset.id,
            async_tests=False,
            include_assertions=True,
            include_comments=True,
        )

        # Call generate_pytest_code directly with mixed test cases
        code = generate_pytest_code(test_dataset, [active_test, disabled_test], config)

        # Should only generate code for active test
        assert "test_active_test" in code.lower()
        assert "test_disabled_test" not in code.lower()

    def test_generate_test_name(self) -> None:
        """Test test name generation."""

        assert _generate_test_name("Simple Test") == "test_simple_test"
        # "Test" at beginning is stripped when adding test_ prefix
        assert _generate_test_name("Test with special chars") == "test_with_special_chars"
        # Function adds test_ prefix
        assert _generate_test_name("already_has_prefix").startswith("test_")
        # Multiple spaces become single underscores after stripping
        assert _generate_test_name("Multiple   Spaces").startswith("test_")

    def test_generate_assertion_code_equals(self) -> None:
        """Test generating equals assertion code."""

        assertion = {
            "type": "equals",
            "expected": "success",
            "message": "Should be success",
        }
        code = _generate_assertion_code(assertion)
        assert "assert result ==" in code
        assert "success" in code
        assert "Should be success" in code

    def test_generate_assertion_code_equals_with_field(self) -> None:
        """Test generating equals assertion with field."""

        assertion = {
            "type": "equals",
            "expected": 200,
            "field": "status_code",
        }
        code = _generate_assertion_code(assertion)
        assert 'result.get("status_code")' in code
        assert "200" in code

    def test_generate_assertion_code_contains(self) -> None:
        """Test generating contains assertion code."""

        assertion = {
            "type": "contains",
            "expected": "success",
        }
        code = _generate_assertion_code(assertion)
        assert "in str(result)" in code
        assert "success" in code

    def test_generate_assertion_code_contains_with_field(self) -> None:
        """Test generating contains assertion with field."""

        assertion = {
            "type": "contains",
            "expected": "ok",
            "field": "message",
        }
        code = _generate_assertion_code(assertion)
        assert 'result.get("message")' in code
        assert "ok" in code

    def test_generate_assertion_code_not_contains(self) -> None:
        """Test generating not_contains assertion code."""

        assertion = {
            "type": "not_contains",
            "expected": "error",
        }
        code = _generate_assertion_code(assertion)
        assert "not in str(result)" in code
        assert "error" in code

    def test_generate_assertion_code_not_contains_with_field(self) -> None:
        """Test generating not_contains assertion with field."""

        assertion = {
            "type": "not_contains",
            "expected": "fail",
            "field": "status",
        }
        code = _generate_assertion_code(assertion)
        assert 'result.get("status")' in code
        assert "not in" in code
        assert "fail" in code

    def test_generate_assertion_code_matches_regex(self) -> None:
        """Test generating regex assertion code."""

        assertion = {
            "type": "matches_regex",
            "pattern": "^[a-z]+$",
        }
        code = _generate_assertion_code(assertion)
        assert "re.search" in code
        assert "^[a-z]+$" in code

    def test_generate_assertion_code_type_check(self) -> None:
        """Test generating type check assertion code."""

        assertion = {
            "type": "type_check",
            "expected": "dict",
        }
        code = _generate_assertion_code(assertion)
        assert "isinstance" in code
        assert "dict" in code

    def test_generate_assertion_code_unknown_type(self) -> None:
        """Test that unknown assertion types return None."""

        assertion = {
            "type": "unknown_type",
            "expected": "value",
        }
        code = _generate_assertion_code(assertion)
        assert code is None
