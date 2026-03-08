"""
Dataset and Test Case management routes for One-Click Evals.

Implements C-03 from the architectural audit - fully async database operations.

@author Erick | Founding Principal AI Architect
"""

from datetime import datetime, timezone
from typing import Annotated
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from ..models import (
    User,
    Trace,
    TraceStatus,
    Dataset,
    DatasetCreate,
    DatasetRead,
    DatasetUpdate,
    TestCase,
    TestCaseCreate,
    TestCaseRead,
    TestCaseUpdate,
    TestCaseFromTrace,
    TestCaseStatus,
    TestRun,
    TestRunCreate,
    TestRunRead,
    TestResult,
    TestResultRead,
    TestResultStatus,
    AssertionType,
    AuditEntry,
    get_session,
    Permission,
)
from ..utils.db import (
    execute as db_execute,
    commit as db_commit,
    refresh as db_refresh,
    get as db_get,
    delete as db_delete,
)
from .auth import get_current_user, require_permission
from .datasets_operations import router as _datasets_operations_router
from ..utils import test_runner

router = APIRouter(prefix="/datasets", tags=["datasets"])


# =============================================================================
# Dataset CRUD
# =============================================================================


@router.get("", response_model=list[DatasetRead])
async def list_datasets(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(default=50, le=500),
    offset: int = 0,
):
    """List datasets. Admins/auditors see all, others see only their own."""
    query = select(Dataset).order_by(desc(col(Dataset.updated_at)))

    # Non-admin/auditor users can only see their own datasets
    if current_user.role not in ["admin", "auditor"]:
        query = query.where(Dataset.created_by == current_user.id)

    query = query.offset(offset).limit(limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@router.post("", response_model=DatasetRead, status_code=status.HTTP_201_CREATED)
async def create_dataset(
    data: DatasetCreate,
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_CREATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new dataset. Requires DATASET_CREATE permission."""
    dataset = Dataset(
        name=data.name,
        description=data.description,
        tags=data.tags,
        metadata_json=data.metadata_json,
        created_by=current_user.id,
    )
    session.add(dataset)

    # Audit log
    session.add(
        AuditEntry(
            event_type="dataset_create",
            actor=current_user.email,
            result="success",
            details={"dataset_name": data.name},
        )
    )
    await db_commit(session)
    await db_refresh(session, dataset)

    return dataset


@router.get("/{dataset_id}", response_model=DatasetRead)
async def get_dataset(
    dataset_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get a dataset by ID. Users can only access their own datasets unless admin/auditor."""
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Non-admin/auditor users can only access their own datasets
    if current_user.role not in ["admin", "auditor"]:
        if dataset.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dataset not found",
            )

    return dataset


@router.patch("/{dataset_id}", response_model=DatasetRead)
async def update_dataset(
    dataset_id: int,
    data: DatasetUpdate,
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_UPDATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Update a dataset. Requires DATASET_UPDATE permission and ownership."""
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Non-admin users can only update their own datasets
    if current_user.role not in ["admin", "auditor"]:
        if dataset.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dataset not found",
            )

    # Update fields
    if data.name is not None:
        dataset.name = data.name
    if data.description is not None:
        dataset.description = data.description
    if data.tags is not None:
        dataset.tags = data.tags

    dataset.updated_at = datetime.now(timezone.utc)
    session.add(dataset)
    await db_commit(session)
    await db_refresh(session, dataset)

    return dataset


@router.delete("/{dataset_id}")
async def delete_dataset(
    dataset_id: int,
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_DELETE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Delete a dataset and all its test cases. Requires DATASET_DELETE permission and ownership."""
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Non-admin users can only delete their own datasets
    if current_user.role not in ["admin", "auditor"]:
        if dataset.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dataset not found",
            )

    # Delete associated test cases
    result = await db_execute(session, select(TestCase).where(TestCase.dataset_id == dataset_id))
    test_cases = result.scalars().all()
    for tc in test_cases:
        await db_delete(session, tc)

    # Audit log
    session.add(
        AuditEntry(
            event_type="dataset_delete",
            actor=current_user.email,
            result="success",
            details={
                "dataset_id": dataset_id,
                "dataset_name": dataset.name,
                "test_cases_deleted": len(test_cases),
            },
        )
    )

    await db_delete(session, dataset)
    await db_commit(session)

    return {"message": "Dataset deleted", "test_cases_deleted": len(test_cases)}


# =============================================================================
# Test Case CRUD
# =============================================================================


@router.get("/{dataset_id}/tests", response_model=list[TestCaseRead])
async def list_test_cases(
    dataset_id: int,
    *,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: TestCaseStatus | None = None,
    tool: str | None = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
):
    """List test cases in a dataset."""
    _ = current_user  # Used for authentication only
    # Verify dataset exists
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    query = select(TestCase).where(TestCase.dataset_id == dataset_id)

    if status_filter:
        query = query.where(TestCase.status == status_filter)
    if tool:
        query = query.where(TestCase.tool == tool)

    query = query.order_by(desc(col(TestCase.created_at))).offset(offset).limit(limit)
    result = await db_execute(session, query)
    return result.scalars().all()


@router.post(
    "/{dataset_id}/tests", response_model=TestCaseRead, status_code=status.HTTP_201_CREATED
)
async def create_test_case(
    dataset_id: int,
    data: TestCaseCreate,
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_CREATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new test case. Requires DATASET_CREATE permission and dataset ownership."""
    # Verify dataset exists
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Non-admin/auditor users can only add tests to their own datasets
    if current_user.role not in ["admin", "auditor"]:
        if dataset.created_by != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dataset not found",
            )

    test_case = TestCase(
        dataset_id=dataset_id,
        name=data.name,
        description=data.description,
        tool=data.tool,
        inputs=data.inputs,
        expected_output=data.expected_output,
        assertions=data.assertions,
        source_trace_id=data.source_trace_id,
        tags=data.tags,
    )
    session.add(test_case)

    # Update dataset test count
    dataset.test_count = (dataset.test_count or 0) + 1
    dataset.updated_at = datetime.now(timezone.utc)
    session.add(dataset)

    await db_commit(session)
    await db_refresh(session, test_case)

    return test_case


@router.post(
    "/{dataset_id}/tests/from-trace",
    response_model=TestCaseRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_test_case_from_trace(
    dataset_id: int,
    data: TestCaseFromTrace,
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_CREATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Create a test case from an existing trace (One-Click Save). Requires DATASET_CREATE permission.

    This is the core "Save to Dataset" feature - converts a production
    trace into a reusable test case.
    """
    # Verify dataset exists
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Find the trace
    result = await db_execute(session, select(Trace).where(Trace.trace_id == data.trace_id))
    trace = result.scalar_one_or_none()

    if not trace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trace {data.trace_id} not found",
        )

    # Only successful traces can be converted
    if trace.status != TraceStatus.SUCCESS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Can only create test cases from successful traces"
                f" (trace status: {trace.status.value})"
            ),
        )

    # Generate name if not provided
    name = data.name or f"Test {trace.tool} ({trace.trace_id[:8]})"

    # Create default assertions if none provided
    assertions = data.assertions
    if not assertions and trace.output:
        # Default: check that output equals expected
        assertions = [
            {
                "type": AssertionType.EQUALS.value,
                "expected": trace.output,
                "message": "Output should match golden output",
            }
        ]

    test_case = TestCase(
        dataset_id=dataset_id,
        name=name,
        description=data.description or f"Generated from trace {trace.trace_id}",
        tool=trace.tool,
        inputs=trace.inputs or {},
        expected_output=trace.output,
        assertions=assertions,
        source_trace_id=trace.trace_id,
        tags=data.tags,
        metadata_json={
            "source_trace": {
                "trace_id": trace.trace_id,
                "duration_ms": trace.duration_ms,
                "cost": trace.cost,
                "created_at": trace.started_at.isoformat() if trace.started_at else None,
            }
        },
    )
    session.add(test_case)

    # Update dataset
    dataset.test_count = (dataset.test_count or 0) + 1
    dataset.updated_at = datetime.now(timezone.utc)
    session.add(dataset)

    # Audit log
    session.add(
        AuditEntry(
            event_type="test_case_from_trace",
            actor=current_user.email,
            tool=trace.tool,
            result="success",
            details={
                "trace_id": trace.trace_id,
                "dataset_id": dataset_id,
                "test_case_name": name,
            },
        )
    )

    await db_commit(session)
    await db_refresh(session, test_case)

    return test_case


@router.get("/{dataset_id}/tests/{test_id}", response_model=TestCaseRead)
async def get_test_case(
    dataset_id: int,
    test_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get a test case by ID."""
    _ = current_user  # Used for authentication only
    result = await db_execute(
        session,
        select(TestCase).where(
            TestCase.id == test_id,
            TestCase.dataset_id == dataset_id,
        ),
    )
    test_case = result.scalar_one_or_none()

    if not test_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test case not found",
        )

    return test_case


@router.patch("/{dataset_id}/tests/{test_id}", response_model=TestCaseRead)
async def update_test_case(
    dataset_id: int,
    test_id: int,
    data: TestCaseUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Update a test case."""
    _ = current_user  # Used for authentication only
    result = await db_execute(
        session,
        select(TestCase).where(
            TestCase.id == test_id,
            TestCase.dataset_id == dataset_id,
        ),
    )
    test_case = result.scalar_one_or_none()

    if not test_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test case not found",
        )

    # Update fields
    if data.name is not None:
        test_case.name = data.name
    if data.description is not None:
        test_case.description = data.description
    if data.inputs is not None:
        test_case.inputs = data.inputs
    if data.expected_output is not None:
        test_case.expected_output = data.expected_output
    if data.assertions is not None:
        test_case.assertions = data.assertions
    if data.status is not None:
        test_case.status = data.status
    if data.tags is not None:
        test_case.tags = data.tags

    test_case.updated_at = datetime.now(timezone.utc)
    session.add(test_case)
    await db_commit(session)
    await db_refresh(session, test_case)

    return test_case


@router.delete("/{dataset_id}/tests/{test_id}")
async def delete_test_case(
    dataset_id: int,
    test_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Delete a test case."""
    _ = current_user  # Used for authentication only
    result = await db_execute(
        session,
        select(TestCase).where(
            TestCase.id == test_id,
            TestCase.dataset_id == dataset_id,
        ),
    )
    test_case = result.scalar_one_or_none()

    if not test_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test case not found",
        )

    # Update dataset count
    dataset = await db_get(session, Dataset, dataset_id)
    if dataset:
        dataset.test_count = max(0, (dataset.test_count or 0) - 1)
        dataset.updated_at = datetime.now(timezone.utc)
        session.add(dataset)

    await db_delete(session, test_case)
    await db_commit(session)

    return {"message": "Test case deleted"}


# =============================================================================
# Bulk Operations
# =============================================================================


@router.post("/{dataset_id}/tests/bulk-from-traces", response_model=list[TestCaseRead])
async def bulk_create_from_traces(
    dataset_id: int,
    trace_ids: list[str],
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_CREATE))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create multiple test cases from traces. Requires DATASET_CREATE permission."""
    _ = current_user  # Used for permission check
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    created = []
    for trace_id in trace_ids:
        result = await db_execute(session, select(Trace).where(Trace.trace_id == trace_id))
        trace = result.scalar_one_or_none()

        if not trace or trace.status != TraceStatus.SUCCESS:
            continue

        test_case = TestCase(
            dataset_id=dataset_id,
            name=f"Test {trace.tool} ({trace.trace_id[:8]})",
            description=f"Generated from trace {trace.trace_id}",
            tool=trace.tool,
            inputs=trace.inputs or {},
            expected_output=trace.output,
            assertions=[
                {
                    "type": "equals",
                    "expected": trace.output,
                }
            ]
            if trace.output
            else None,
            source_trace_id=trace.trace_id,
        )
        session.add(test_case)
        created.append(test_case)

    # Update dataset count
    dataset.test_count = (dataset.test_count or 0) + len(created)
    dataset.updated_at = datetime.now(timezone.utc)
    session.add(dataset)

    await db_commit(session)

    for tc in created:
        await db_refresh(session, tc)

    return created


# =============================================================================
# Test Run Management
# =============================================================================


@router.get("/{dataset_id}/runs", response_model=list[TestRunRead])
async def list_test_runs(
    dataset_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(default=20, le=100),
    offset: int = 0,
):
    """List test runs for a dataset."""
    _ = current_user  # Used for authentication only
    query = (
        select(TestRun)
        .where(TestRun.dataset_id == dataset_id)
        .order_by(desc(col(TestRun.created_at)))
        .offset(offset)
        .limit(limit)
    )
    result = await db_execute(session, query)
    return result.scalars().all()


@router.post("/{dataset_id}/runs", response_model=TestRunRead, status_code=status.HTTP_201_CREATED)
async def create_test_run(
    dataset_id: int,
    data: TestRunCreate,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(require_permission(Permission.DATASET_RUN))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new test run. Requires DATASET_RUN permission."""
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Count active test cases.
    result = await db_execute(
        session,
        select(TestCase.id)
        .where(TestCase.dataset_id == dataset_id)
        .where(TestCase.status == TestCaseStatus.ACTIVE),
    )
    test_count = len(result.scalars().all())

    run = TestRun(
        run_id=f"run_{uuid.uuid4().hex[:12]}",
        dataset_id=dataset_id,
        name=data.name,
        triggered_by=current_user.id,
        total_tests=test_count,
        config=data.config,
    )
    session.add(run)
    await db_commit(session)
    await db_refresh(session, run)

    background_tasks.add_task(test_runner.run_tests_async, session, dataset_id, run.run_id)

    return run


@router.get("/{dataset_id}/runs/{run_id}", response_model=TestRunRead)
async def get_test_run(
    dataset_id: int,
    run_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get a test run by ID."""
    _ = current_user  # Used for authentication only
    result = await db_execute(
        session,
        select(TestRun).where(
            TestRun.run_id == run_id,
            TestRun.dataset_id == dataset_id,
        ),
    )
    run = result.scalar_one_or_none()

    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test run not found",
        )

    return run


@router.get("/{dataset_id}/runs/{run_id}/results", response_model=list[TestResultRead])
async def get_test_run_results(
    dataset_id: int,
    run_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: TestResultStatus | None = None,
):
    """Get results for a test run."""
    _ = current_user  # Used for authentication only
    # Verify run exists
    result = await db_execute(
        session,
        select(TestRun).where(
            TestRun.run_id == run_id,
            TestRun.dataset_id == dataset_id,
        ),
    )
    run = result.scalar_one_or_none()

    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Test run not found",
        )

    query = select(TestResult).where(TestResult.run_id == run_id)
    if status_filter:
        query = query.where(TestResult.status == status_filter)

    result = await db_execute(session, query)
    return result.scalars().all()


# =============================================================================
# Statistics
# =============================================================================


@router.get("/{dataset_id}/stats")
async def get_dataset_stats(
    dataset_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get statistics for a dataset."""
    _ = current_user  # Used for authentication only
    dataset = await db_get(session, Dataset, dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found",
        )

    # Count by status and tool.
    result = await db_execute(
        session,
        select(TestCase).where(TestCase.dataset_id == dataset_id),
    )
    dataset_test_cases = result.scalars().all()
    status_counts = {status.value: 0 for status in TestCaseStatus}
    tool_counts: dict[str, int] = {}
    for test_case in dataset_test_cases:
        status_counts[test_case.status.value] = status_counts.get(test_case.status.value, 0) + 1
        tool_name = test_case.tool or "unknown"
        tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1

    # Recent runs
    result = await db_execute(
        session,
        select(TestRun)
        .where(TestRun.dataset_id == dataset_id)
        .order_by(desc(col(TestRun.created_at)))
        .limit(5),
    )
    recent_runs = result.scalars().all()

    return {
        "dataset_id": dataset_id,
        "name": dataset.name,
        "total_tests": dataset.test_count,
        "by_status": status_counts,
        "by_tool": tool_counts,
        "recent_runs": [
            {
                "run_id": r.run_id,
                "status": r.status.value,
                "passed": r.passed_count,
                "failed": r.failed_count,
                "created_at": r.created_at.isoformat(),
            }
            for r in recent_runs
        ],
        "last_run_pass_rate": dataset.last_run_pass_rate,
    }


router.include_router(_datasets_operations_router)
