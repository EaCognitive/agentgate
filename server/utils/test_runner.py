"""
Test execution engine for One-Click Evals.

Executes test cases from datasets and records results.

@author Erick | Founding Principal AI Architect
"""

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from ..models import (
    Dataset,
    TestCase,
    TestCaseStatus,
    TestRun,
    TestRunStatus,
    TestResult,
    TestResultStatus,
    AssertionType,
)
from .db import execute as db_execute, commit as db_commit


class TestExecutionError(Exception):
    """Raised when test execution fails catastrophically."""

    def __init__(self, message: str):
        """Initialize exception with message.

        Args:
            message: Error message
        """
        super().__init__(message)


class TestRunner:
    """
    Executes test cases and records results.

    This is a simplified test runner that validates assertions without
    actually calling external tools. In a production system, this would
    integrate with the actual tool execution framework.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    def get_session(self) -> AsyncSession:
        """Get the database session for this test runner.

        Returns:
            The AsyncSession used by this test runner
        """
        return self.session

    async def _get_test_run(self, run_id: str) -> TestRun:
        """Get test run by ID.

        Args:
            run_id: Test run ID

        Returns:
            Test run object

        Raises:
            TestExecutionError: If test run not found
        """
        result = await db_execute(
            self.session,
            select(TestRun).where(col(TestRun.run_id) == run_id),
        )
        test_run = result.scalar_one_or_none()
        if not test_run:
            raise TestExecutionError(f"Test run {run_id} not found")
        return test_run

    async def _initialize_run(self, test_run: TestRun) -> None:
        """Initialize test run status.

        Args:
            test_run: Test run to initialize
        """
        test_run.status = TestRunStatus.RUNNING
        test_run.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.session.add(test_run)
        await db_commit(self.session)

    async def _get_active_test_cases(self, dataset_id: int) -> list[TestCase]:
        """Get all active test cases for a dataset.

        Args:
            dataset_id: Dataset ID

        Returns:
            List of active test cases
        """
        result = await db_execute(
            self.session,
            select(TestCase)
            .where(col(TestCase.dataset_id) == dataset_id)
            .where(col(TestCase.status) == TestCaseStatus.ACTIVE),
        )
        return result.scalars().all()

    async def _execute_all_test_cases(
        self, test_cases: list[TestCase], run_id: str
    ) -> tuple[int, int, int]:
        """Execute all test cases and return counts.

        Args:
            test_cases: List of test cases to execute
            run_id: Test run ID for results

        Returns:
            Tuple of (passed_count, failed_count, error_count)
        """
        passed_count = 0
        failed_count = 0
        error_count = 0

        for test_case in test_cases:
            result_status, error_message, actual_output = await self._execute_test_case(test_case)
            if test_case.id is None:
                raise TestExecutionError("Cannot record result for test case without primary key")

            test_result = TestResult(
                run_id=run_id,
                test_case_id=test_case.id,
                status=result_status,
                actual_output=actual_output,
                error_message=error_message,
                duration_ms=0.0,  # Simplified: not timing individual tests
            )
            self.session.add(test_result)

            if result_status == TestResultStatus.PASSED:
                passed_count += 1
            elif result_status == TestResultStatus.FAILED:
                failed_count += 1
            elif result_status == TestResultStatus.ERROR:
                error_count += 1

        return passed_count, failed_count, error_count

    async def _finalize_run(
        self,
        test_run: TestRun,
        passed_count: int,
        failed_count: int,
        *,
        error_count: int,
        dataset_id: int,
    ) -> None:
        """Finalize test run with results.

        Args:
            test_run: Test run to finalize
            passed_count: Number of passed tests
            failed_count: Number of failed tests
            error_count: Number of errored tests
            dataset_id: Dataset ID for updates
        """
        test_run.status = TestRunStatus.COMPLETED
        test_run.passed_count = passed_count
        test_run.failed_count = failed_count
        test_run.error_count = error_count
        test_run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)

        if test_run.started_at:
            duration = (test_run.completed_at - test_run.started_at).total_seconds() * 1000
            test_run.duration_ms = duration

        self.session.add(test_run)

        result = await db_execute(
            self.session,
            select(Dataset).where(col(Dataset.id) == dataset_id),
        )
        dataset = result.scalar_one_or_none()

        if dataset:
            dataset.last_run_at = test_run.completed_at
            total = passed_count + failed_count + error_count
            dataset.last_run_pass_rate = (passed_count / total * 100) if total > 0 else 0
            self.session.add(dataset)

        await db_commit(self.session)

    async def run_dataset(self, dataset_id: int, run_id: str) -> None:
        """
        Execute all active test cases in a dataset.

        This runs asynchronously and updates the test run status as it progresses.
        """
        test_run = await self._get_test_run(run_id)
        await self._initialize_run(test_run)

        try:
            test_cases = await self._get_active_test_cases(dataset_id)

            if not test_cases:
                test_run.status = TestRunStatus.FAILED
                test_run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                self.session.add(test_run)
                await db_commit(self.session)
                return

            passed_count, failed_count, error_count = await self._execute_all_test_cases(
                test_cases, run_id
            )

            await self._finalize_run(
                test_run, passed_count, failed_count, error_count=error_count, dataset_id=dataset_id
            )

        except (ValueError, RuntimeError, KeyError) as e:
            # Mark run as failed
            test_run.status = TestRunStatus.FAILED
            test_run.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            self.session.add(test_run)
            await db_commit(self.session)
            raise TestExecutionError(f"Test run failed: {str(e)}") from e

    async def _execute_test_case(
        self, test_case: TestCase
    ) -> tuple[TestResultStatus, str | None, dict[str, Any] | None]:
        """
        Execute a single test case and return the result.

        When actual tool execution is not available, only assertion-based
        tests are evaluated. Tests that rely solely on expected_output
        comparison are marked as errors since we cannot verify them
        without real execution.

        Returns:
            Tuple of (status, error_message, actual_output)
        """
        if not test_case.inputs:
            return (TestResultStatus.ERROR, "Test case has no inputs defined", None)

        try:
            # Simulated execution: real agent integration is deferred to
            # the Agent class; here we validate assertions against a
            # placeholder output.
            actual_output = {"status": "simulated"}

            result_status, error_msg = await self._evaluate_test_case(test_case, actual_output)
            return (result_status, error_msg, actual_output)

        except (ValueError, RuntimeError, KeyError) as e:
            return (TestResultStatus.ERROR, f"Test execution error: {str(e)}", None)

    async def _evaluate_test_case(
        self, test_case: TestCase, actual_output: dict[str, Any]
    ) -> tuple[TestResultStatus, str | None]:
        """
        Evaluate test case assertions and output matching.

        Returns:
            Tuple of (status, error_message)
        """
        # Run assertions if defined
        if test_case.assertions:
            assertion_passed = await self._validate_assertions(test_case.assertions, actual_output)
            if not assertion_passed:
                return TestResultStatus.FAILED, "Assertion validation failed"
            return TestResultStatus.PASSED, None

        # Without real tool execution, we cannot verify expected_output.
        # Return an error instead of a false positive.
        if test_case.expected_output:
            return (
                TestResultStatus.ERROR,
                "Cannot verify expected output: tool execution not implemented",
            )

        # No assertions and no expected output - structural validation only
        return TestResultStatus.PASSED, None

    def _evaluate_single_assertion(
        self,
        assertion: dict[str, Any],
        output: dict[str, Any],
    ) -> bool:
        """Evaluate a single assertion against the output."""
        assertion_dispatch: dict[str, str] = {
            AssertionType.EQUALS.value: "_check_equals",
            AssertionType.CONTAINS.value: "_check_contains",
            AssertionType.NOT_CONTAINS.value: "_check_not_contains",
            AssertionType.MATCHES_REGEX.value: "_check_regex",
            AssertionType.TYPE_CHECK.value: "_check_type",
        }
        assertion_type = assertion.get("type")
        method_name = assertion_dispatch.get(assertion_type or "")
        if method_name is None:
            return True
        checker = getattr(self, method_name)
        return checker(assertion, output)

    async def _validate_assertions(
        self, assertions: list[dict[str, Any]], output: dict[str, Any]
    ) -> bool:
        """Validate all assertions against the output.

        Returns True if all assertions pass, False otherwise.
        """
        return all(self._evaluate_single_assertion(assertion, output) for assertion in assertions)

    def _check_equals(self, assertion: dict[str, Any], output: dict[str, Any]) -> bool:
        """Check equals assertion."""
        expected = assertion.get("expected")
        field = assertion.get("field")

        if field:
            actual = output.get(field)
        else:
            actual = output

        return actual == expected

    def _check_contains(self, assertion: dict[str, Any], output: dict[str, Any]) -> bool:
        """Check contains assertion."""
        expected = assertion.get("expected")
        field = assertion.get("field")

        if field:
            actual_str = str(output.get(field, ""))
        else:
            actual_str = str(output)

        return str(expected) in actual_str

    def _check_not_contains(self, assertion: dict[str, Any], output: dict[str, Any]) -> bool:
        """Check not-contains assertion."""
        expected = assertion.get("expected")
        field = assertion.get("field")

        if field:
            actual_str = str(output.get(field, ""))
        else:
            actual_str = str(output)

        return str(expected) not in actual_str

    def _check_regex(self, assertion: dict[str, Any], output: dict[str, Any]) -> bool:
        """Check regex assertion."""
        pattern = assertion.get("pattern")
        field = assertion.get("field")

        if not pattern:
            return False

        if field:
            actual_str = str(output.get(field, ""))
        else:
            actual_str = str(output)

        try:
            return re.search(pattern, actual_str) is not None
        except re.error:
            return False

    def _check_type(self, assertion: dict[str, Any], output: dict[str, Any]) -> bool:
        """Check type assertion."""
        expected_type = assertion.get("expected_type") or assertion.get("expected")
        if expected_type is None:
            return False

        expected_type = str(expected_type).strip().lower()
        type_map: dict[str, tuple[type, ...]] = {
            "object": (dict,),
            "dict": (dict,),
            "array": (list,),
            "list": (list,),
            "string": (str,),
            "str": (str,),
            "number": (int, float),
            "int": (int, float),
            "float": (int, float),
            "boolean": (bool,),
            "bool": (bool,),
        }
        expected_python_types = type_map.get(expected_type)
        return expected_python_types is not None and isinstance(output, expected_python_types)


async def run_tests_async(session: AsyncSession, dataset_id: int, run_id: str) -> None:
    """
    Background task to run tests asynchronously.

    This function should be called in a background task to avoid blocking
    the HTTP response.
    """
    runner = TestRunner(session)
    await runner.run_dataset(dataset_id, run_id)
