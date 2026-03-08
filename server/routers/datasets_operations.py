"""Dataset pytest export helpers and routes."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from ..models import (
    AuditEntry,
    Dataset,
    PytestExportConfig,
    TestCase,
    TestCaseStatus,
    User,
    get_session,
)
from ..utils.db import commit as db_commit
from ..utils.db import execute as db_execute
from .auth import get_current_user
from .dataset_helpers import get_dataset_or_404_with_ownership_check

router = APIRouter(tags=["datasets"])


def _sanitize_for_docstring(text: str) -> str:
    """Escape a string so it is safe to embed inside triple-quoted docstrings.

    Replaces literal triple-quote sequences and strips newlines so that
    attacker-controlled content cannot break out of a docstring boundary.
    """
    sanitized = text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return sanitized.replace("\n", " ").replace("\r", " ")


def _generate_module_header(dataset: Dataset, config: PytestExportConfig) -> list[str]:
    """Generate the module docstring and import lines for pytest export."""
    lines: list[str] = []
    lines.append('"""')
    lines.append(f"Auto-generated tests for dataset: {_sanitize_for_docstring(dataset.name)}")
    if dataset.description:
        lines.append(f"Description: {_sanitize_for_docstring(dataset.description)}")
    lines.append(f"Generated at: {datetime.now(timezone.utc).isoformat()}")
    lines.append('"""')
    lines.append("")
    lines.append("import pytest")
    if config.async_tests:
        lines.append("import asyncio")
    lines.append("from ea_agentgate import Agent")
    lines.append("")
    lines.append("")
    lines.append("@pytest.fixture")
    lines.append("def agent():")
    lines.append('    """Create test agent."""')
    lines.append("    return Agent()")
    lines.append("")
    lines.append("")
    return lines


def _generate_test_function(test_case: TestCase, config: PytestExportConfig) -> list[str]:
    """Generate the lines for a single test function from a test case."""
    lines: list[str] = []
    func_name = _generate_test_name(test_case.name)

    if config.include_comments and test_case.description:
        lines.append(f"# {test_case.description}")
    if test_case.source_trace_id:
        lines.append(f"# Source trace: {test_case.source_trace_id}")

    if config.async_tests:
        lines.append("@pytest.mark.asyncio")
        lines.append(f"async def {func_name}(agent):")
    else:
        lines.append(f"def {func_name}(agent):")

    safe_name = _sanitize_for_docstring(test_case.name)
    lines.append(f'    """Test: {safe_name}"""')

    inputs_str = json.dumps(test_case.inputs, indent=8)
    lines.append(f"    inputs = {inputs_str}")
    lines.append("")

    if config.async_tests:
        lines.append(f'    result = await agent.acall("{test_case.tool}", **inputs)')
    else:
        lines.append(f'    result = agent.call("{test_case.tool}", **inputs)')
    lines.append("")

    if config.include_assertions and test_case.assertions:
        for assertion in test_case.assertions:
            assertion_code = _generate_assertion_code(assertion)
            if assertion_code:
                lines.append(f"    {assertion_code}")
    elif test_case.expected_output:
        expected_str = json.dumps(test_case.expected_output)
        lines.append(f"    assert result == {expected_str}")

    lines.append("")
    lines.append("")
    return lines


def generate_pytest_code(
    dataset: Dataset,
    test_cases: list[TestCase],
    config: PytestExportConfig,
) -> str:
    """Generate pytest code from test cases."""
    lines = _generate_module_header(dataset, config)

    for test_case in test_cases:
        if test_case.status != TestCaseStatus.ACTIVE:
            continue
        lines.extend(_generate_test_function(test_case, config))

    return "\n".join(lines)


def _generate_test_name(name: str) -> str:
    """Convert test case name to a valid Python test function name."""
    clean = re.sub(r"[^a-zA-Z0-9_\s]", "", name)
    clean = re.sub(r"\s+", "_", clean)
    clean = clean.lower()
    if not clean.startswith("test_"):
        clean = f"test_{clean}"
    return clean


def _generate_assertion_code(assertion: dict) -> str | None:
    """Generate Python assertion code from assertion metadata."""
    assertion_type = assertion.get("type")
    expected = assertion.get("expected")
    field = assertion.get("field")
    pattern = assertion.get("pattern")
    message = assertion.get("message")

    msg_part = f', "{message}"' if message else ""
    result_expr = f'result.get("{field}")' if field else "result"
    rendered_expected = json.dumps(expected)
    assertion_templates = {
        "equals": f"assert {result_expr} == {rendered_expected}{msg_part}",
        "contains": f"assert {rendered_expected} in str({result_expr}){msg_part}",
        "not_contains": f"assert {rendered_expected} not in str({result_expr}){msg_part}",
        "type_check": f"assert isinstance(result, {expected}){msg_part}",
    }
    if assertion_type in assertion_templates:
        return assertion_templates[assertion_type]
    if assertion_type == "matches_regex" and pattern:
        return f're.search(r"{pattern}", str(result)) is not None{msg_part}'
    return None


@router.post("/{dataset_id}/export/pytest", response_class=PlainTextResponse)
async def export_pytest(
    dataset_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    *,
    async_tests: bool = False,
    include_assertions: bool = True,
    include_comments: bool = True,
) -> str:
    """Export active dataset tests as a runnable pytest module."""
    dataset = await get_dataset_or_404_with_ownership_check(session, dataset_id, current_user)

    result = await db_execute(
        session,
        select(TestCase)
        .where(TestCase.dataset_id == dataset_id)
        .where(TestCase.status == TestCaseStatus.ACTIVE),
    )
    test_cases = result.scalars().all()

    if not test_cases:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active test cases in dataset",
        )

    config = PytestExportConfig(
        dataset_id=dataset_id,
        async_tests=async_tests,
        include_assertions=include_assertions,
        include_comments=include_comments,
    )

    code = generate_pytest_code(dataset, list(test_cases), config)

    session.add(
        AuditEntry(
            event_type="pytest_export",
            actor=current_user.email,
            result="success",
            details={
                "dataset_id": dataset_id,
                "dataset_name": dataset.name,
                "test_count": len(test_cases),
            },
        )
    )
    await db_commit(session)

    return code


__all__ = [
    "router",
    "generate_pytest_code",
    "_generate_test_name",
    "_generate_assertion_code",
    "PytestExportConfig",
]
