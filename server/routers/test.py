"""Test data seeding routes.

Implements C-03 from the architectural audit: Async database patterns.
"""

import logging
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .auth import require_admin  # noqa: F401 - used in Depends()
from ..models import (
    Trace,
    TraceStatus,
    Approval,
    ApprovalStatus,
    AuditEntry,
    get_session,
    # Dataset models
    Dataset,
    TestCase,
    TestCaseStatus,
    TestRun,
    TestRunStatus,
    PIIAuditEntry,
    PIISession,
    EncryptionKeyRecord,
    User,
    UserPIIPermissions,
    PIIPermission,
)
from ..utils.db import execute as db_execute, commit as db_commit, flush as db_flush

router = APIRouter(prefix="/test", tags=["test"])
logger = logging.getLogger(__name__)

# Sample tool names for realistic data
TOOLS = [
    "bash",
    "file_read",
    "file_write",
    "web_search",
    "code_execute",
    "database_query",
    "api_call",
    "send_email",
]

AGENTS = ["agent-alpha", "agent-beta", "agent-gamma", "agent-delta"]
SESSIONS = [f"session-{i}" for i in range(1, 6)]

SAMPLE_INPUTS = {
    "bash": [
        {"command": "ls -la /home/user"},
        {"command": "cat /etc/passwd"},
        {"command": "rm -rf /tmp/cache"},
        {"command": "curl https://api.example.com/data"},
    ],
    "file_read": [
        {"path": "/home/user/documents/report.pdf"},
        {"path": "/var/log/application.log"},
        {"path": "~/.ssh/id_rsa"},
    ],
    "file_write": [
        {"path": "/home/user/output.txt", "content": "Results..."},
        {"path": "/home/user/config.json", "content": "{}"},
    ],
    "web_search": [
        {"query": "latest AI research papers"},
        {"query": "python async best practices"},
    ],
    "code_execute": [
        {"language": "python", "code": "print('Hello World')"},
        {"language": "javascript", "code": "console.log('test')"},
    ],
    "database_query": [
        {"query": "SELECT * FROM users WHERE role='admin'"},
        {"query": "DELETE FROM logs WHERE date < '2024-01-01'"},
    ],
    "api_call": [
        {"url": "https://api.stripe.com/v1/charges", "method": "POST"},
        {"url": "https://api.openai.com/v1/completions", "method": "POST"},
    ],
    "send_email": [
        {"to": "user@example.com", "subject": "Report Ready"},
        {"to": "admin@company.com", "subject": "Alert: High CPU Usage"},
    ],
}


@dataclass
class _TestRunParams:
    """Parameters for test run creation."""

    passed: int
    failed: int
    started: datetime
    duration: int
    test_count: int


@dataclass
class _DatasetConfig:
    """Configuration for a dataset."""

    name: str
    description: str
    tags: list[str]


def _get_test_case_templates() -> dict[str, list[tuple[str, dict[str, Any], dict[str, Any]]]]:
    """Get predefined test case templates for seeding."""
    return {
        "bash": [
            ("Test safe command execution", {"command": "echo 'hello'"}, {"output": "hello"}),
            ("Test directory listing", {"command": "ls /tmp"}, {"output": "files..."}),
        ],
        "file_read": [
            ("Read config file", {"path": "/app/config.json"}, {"content": "{}"}),
            ("Read log file", {"path": "/var/log/app.log"}, {"content": "logs..."}),
        ],
        "api_call": [
            (
                "Fetch user data",
                {"url": "https://api.example.com/users/1", "method": "GET"},
                {"user": {"id": 1}},
            ),
            (
                "Create resource",
                {"url": "https://api.example.com/items", "method": "POST"},
                {"created": True},
            ),
        ],
        "web_search": [
            ("Search documentation", {"query": "python async await"}, {"results": []}),
        ],
        "database_query": [
            ("Select users", {"query": "SELECT id, name FROM users LIMIT 10"}, {"rows": []}),
        ],
    }


async def _create_test_case(
    session: AsyncSession,
    dataset: Dataset,
    *,
    tool: str,
    template_name: str,
    inputs: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    """Create a single test case and add to session."""
    if dataset.id is None:
        raise ValueError("Dataset ID must be set before creating test cases")
    test_case = TestCase(
        dataset_id=dataset.id,
        name=f"{template_name} ({dataset.name[:10]})",
        tool=tool,
        inputs=inputs,
        expected_output=expected,
        assertions=[
            {
                "type": "type_check",
                "expected_type": "object",
                "description": "Output should be object",
            },
        ],
        status=random.choice([TestCaseStatus.ACTIVE, TestCaseStatus.ACTIVE, TestCaseStatus.DRAFT]),
        tags=[tool, "auto-generated"],
        created_at=random_datetime(168),
        updated_at=random_datetime(24),
    )
    session.add(test_case)


async def _create_test_run(
    session: AsyncSession,
    dataset: Dataset,
    test_count: int,
) -> bool:
    """Create a test run for a dataset if conditions are met."""
    if random.random() <= 0.3:
        return False
    if dataset.id is None:
        raise ValueError("Dataset ID must be set before creating test runs")

    passed = random.randint(1, test_count)
    failed = test_count - passed
    started = random_datetime(48)
    duration = random.randint(5000, 60000)
    completed = started + timedelta(milliseconds=duration)

    test_run = TestRun(
        run_id=f"run_{uuid.uuid4().hex[:12]}",
        dataset_id=dataset.id,
        name=f"Test Run {random.randint(1, 100)}",
        status=TestRunStatus.COMPLETED,
        total_tests=test_count,
        passed_count=passed,
        failed_count=failed,
        error_count=0,
        skipped_count=0,
        started_at=started,
        completed_at=completed,
        duration_ms=duration,
    )
    session.add(test_run)

    # Update dataset last run info
    dataset.last_run_at = completed
    dataset.last_run_pass_rate = (passed / test_count * 100) if test_count > 0 else 0
    return True


@dataclass
class _TestCaseTemplate:
    """Unpacked test case template."""

    name: str
    inputs: dict[str, Any]
    expected: dict[str, Any]


def random_datetime(hours_back: int = 168) -> datetime:
    """Generate random datetime within the last N hours."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    delta = timedelta(hours=random.randint(0, hours_back))
    return now - delta


async def _seed_traces(session: AsyncSession) -> int:
    """Seed database with trace records."""
    traces_created = 0

    # Generate traces over the past week
    for _ in range(150):
        tool = random.choice(TOOLS)
        status = random.choices(
            [TraceStatus.SUCCESS, TraceStatus.FAILED, TraceStatus.BLOCKED],
            weights=[0.75, 0.10, 0.15],
        )[0]

        started_at = random_datetime(168)
        duration = random.uniform(50, 5000)
        cost = (
            random.uniform(0.0001, 0.05)
            if tool in ["code_execute", "api_call", "web_search"]
            else 0
        )

        inputs = random.choice(SAMPLE_INPUTS.get(tool, [{"input": "test"}]))

        trace = Trace(
            trace_id=str(uuid.uuid4()),
            tool=tool,
            inputs=inputs,
            output={"result": "success"} if status == TraceStatus.SUCCESS else None,
            status=status,
            error="Permission denied" if status == TraceStatus.FAILED else None,
            blocked_by="security_policy" if status == TraceStatus.BLOCKED else None,
            duration_ms=duration,
            cost=cost,
            agent_id=random.choice(AGENTS),
            session_id=random.choice(SESSIONS),
            metadata_json={"source": "test_seed"},
            started_at=started_at,
            ended_at=started_at + timedelta(milliseconds=duration),
        )
        session.add(trace)
        traces_created += 1

    return traces_created


async def _seed_approvals(session: AsyncSession) -> int:
    """Seed database with approval records."""
    approvals_created = 0
    pending_tools = ["bash", "file_write", "database_query", "send_email"]

    # Generate some pending approvals for interactive demo
    for tool in pending_tools:
        inputs = random.choice(SAMPLE_INPUTS.get(tool, [{"input": "test"}]))
        approval = Approval(
            approval_id=str(uuid.uuid4()),
            tool=tool,
            inputs=inputs,
            agent_id=random.choice(AGENTS),
            session_id=random.choice(SESSIONS),
            context={
                "reason": f"Agent requested to execute {tool}",
                "risk_level": "high" if tool in ["bash", "database_query"] else "medium",
                "source": "test_seed",
            },
            status=ApprovalStatus.PENDING,
            created_at=random_datetime(2),  # Recent
        )
        session.add(approval)
        approvals_created += 1

    # Generate some historical approvals
    for _ in range(20):
        tool = random.choice(pending_tools)
        approval_status = random.choice([ApprovalStatus.APPROVED, ApprovalStatus.DENIED])
        created = random_datetime(72)

        approval = Approval(
            approval_id=str(uuid.uuid4()),
            tool=tool,
            inputs=random.choice(SAMPLE_INPUTS.get(tool, [{"input": "test"}])),
            agent_id=random.choice(AGENTS),
            session_id=random.choice(SESSIONS),
            context={"source": "test_seed"},
            status=approval_status,
            decided_by="admin@test.com",
            decision_reason="Approved for testing"
            if approval_status == ApprovalStatus.APPROVED
            else "Potentially dangerous",
            created_at=created,
            decided_at=created + timedelta(minutes=random.randint(1, 30)),
        )
        session.add(approval)
        approvals_created += 1

    return approvals_created


async def _seed_audit_entries(session: AsyncSession) -> int:
    """Seed database with audit log entries."""
    audit_created = 0
    event_types = ["tool_execution", "approval_decision", "login", "policy_violation"]

    for _ in range(50):
        event_type = random.choice(event_types)
        audit = AuditEntry(
            event_type=event_type,
            actor=random.choice(["admin@test.com", "system", random.choice(AGENTS)]),
            tool=random.choice(TOOLS)
            if event_type in ["tool_execution", "policy_violation"]
            else None,
            result=random.choice(["success", "blocked", "failed"]),
            details={"source": "test_seed"},
            timestamp=random_datetime(168),
        )
        session.add(audit)
        audit_created += 1

    return audit_created


async def _seed_datasets_and_tests(session: AsyncSession) -> tuple[int, int, int]:
    """Seed database with datasets, test cases, and test runs."""
    # Define dataset configurations
    dataset_configs = [
        _DatasetConfig(
            name="API Integration Tests",
            description="Tests for external API integrations",
            tags=["api", "integration"],
        ),
        _DatasetConfig(
            name="Security Validation",
            description="Security-related test cases",
            tags=["security", "validation"],
        ),
        _DatasetConfig(
            name="Performance Benchmarks",
            description="Performance and load testing",
            tags=["performance", "benchmark"],
        ),
    ]

    # Get test case templates
    test_templates = _get_test_case_templates()

    # Counters for tracking created resources
    datasets_created = 0
    test_cases_created = 0
    test_runs_created = 0

    # Create datasets
    created_datasets = []
    for config in dataset_configs:
        dataset = Dataset(
            name=config.name,
            description=config.description,
            tags=config.tags,
            metadata_json={"source": "test_seed"},
            test_count=0,
            created_at=random_datetime(720),  # Within last month
            updated_at=random_datetime(48),
        )
        session.add(dataset)
        await db_flush(session)  # Get the ID
        created_datasets.append(dataset)
        datasets_created += 1

    # Create test cases and test runs for each dataset
    for dataset in created_datasets:
        # Add 3-8 test cases per dataset
        num_cases = random.randint(3, 8)
        tools = random.sample(list(test_templates.keys()), min(num_cases, len(test_templates)))

        for tool in tools:
            template_name, inputs, expected = random.choice(test_templates[tool])
            await _create_test_case(
                session,
                dataset,
                tool=tool,
                template_name=template_name,
                inputs=inputs,
                expected=expected,
            )
            test_cases_created += 1
            dataset.test_count += 1

        # Create a test run for this dataset
        if await _create_test_run(session, dataset, dataset.test_count):
            test_runs_created += 1

    return datasets_created, test_cases_created, test_runs_created


async def _seed_pii_data(session: AsyncSession) -> tuple[int, int]:
    """Seed database with PII vault data."""
    pii_sessions_created = 0
    pii_audits_created = 0

    pii_data_types = ["ssn", "credit_card", "email", "phone", "address"]
    pii_actions = [
        "pii_store",
        "pii_retrieve",
        "pii_delete",
        "access_denied",
        "pii_integrity_failure",
    ]

    # Create some PII sessions
    for _ in range(10):
        created = random_datetime(72)
        pii_session = PIISession(
            session_id=str(uuid.uuid4()),
            user_id=f"user-{random.randint(1, 5)}",
            purpose="Test data processing",
            agent_id=random.choice(AGENTS),
            metadata_json={"source": "test_seed"},
            created_at=created,
            expires_at=created + timedelta(hours=random.randint(1, 24))
            if random.random() > 0.3
            else None,
            store_count=random.randint(0, 20),
            retrieve_count=random.randint(0, 50),
            last_activity_at=random_datetime(24) if random.random() > 0.3 else None,
            is_active=random.random() > 0.5,
        )
        session.add(pii_session)
        pii_sessions_created += 1

    # Create PII audit entries
    for _ in range(30):
        pii_audit = PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type=random.choice(pii_actions),
            user_id=str(random.choice([1, 2])) if random.random() > 0.3 else None,
            session_id=f"test_seed_{uuid.uuid4()}",  # Prefix for identification
            data_classification=random.choice(pii_data_types),
            pii_type=random.choice(pii_data_types),
            success=random.random() > 0.1,  # 90% success rate
            source_ip=f"192.168.1.{random.randint(1, 254)}",
            timestamp=random_datetime(168),
        )
        session.add(pii_audit)
        pii_audits_created += 1

    # Create encryption key for compliance checks
    encryption_key = EncryptionKeyRecord(
        key_id=f"test_seed_{uuid.uuid4()}",  # Prefix for identification
        algorithm="AES-256-GCM",
        created_at=random_datetime(30),  # Created within last 30 days
        is_active=True,
        usage_count=random.randint(100, 1000),
        last_used_at=random_datetime(2),
    )
    session.add(encryption_key)

    return pii_sessions_created, pii_audits_created


async def _grant_admin_pii_permissions(session: AsyncSession) -> int:
    """Grant all PII permissions to the admin user."""
    # Find admin user by email - try common admin emails
    admin_emails = ["admin@example.com", "admin@test.com"]
    admin_user = None

    for email in admin_emails:
        result = await db_execute(session, select(User).where(User.email == email))
        admin_user = result.scalar_one_or_none()
        if admin_user:
            break

    # If no admin found by email, try finding by role
    if not admin_user:
        result = await db_execute(session, select(User).where(User.role == "admin"))
        admin_user = result.scalar_one_or_none()

    if not admin_user:
        logger.warning("No admin user found to grant PII permissions")
        return 0

    permissions_granted = 0

    # Grant all PII permissions to admin
    for permission in PIIPermission:
        # Check if permission already exists
        result = await db_execute(
            session,
            select(UserPIIPermissions).where(
                UserPIIPermissions.user_id == admin_user.id,
                UserPIIPermissions.permission == permission.value,
            ),
        )
        existing = result.scalar_one_or_none()

        if not existing:
            pii_permission = UserPIIPermissions(
                user_id=admin_user.id,
                permission=permission.value,
                granted_by=admin_user.id,  # Self-granted for seed
                reason="Test seed - auto-granted PII permissions",
            )
            session.add(pii_permission)
            permissions_granted += 1

    return permissions_granted


@router.post("/seed")
async def seed_test_data(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin_user: Annotated[object, Depends(require_admin)],
):
    """Seed database with realistic test data.

    SECURITY: Admin authentication required.
    This endpoint can create large amounts of test data.
    Should only be accessible to administrators.
    """
    # Seed each feature independently
    traces_created = await _seed_traces(session)
    approvals_created = await _seed_approvals(session)
    audit_created = await _seed_audit_entries(session)
    datasets_created, test_cases_created, test_runs_created = await _seed_datasets_and_tests(
        session
    )
    pii_sessions_created, pii_audits_created = await _seed_pii_data(session)

    # Grant PII permissions to admin user
    pii_permissions_granted = await _grant_admin_pii_permissions(session)

    await db_commit(session)

    return {
        "success": True,
        "message": "Test data seeded successfully",
        "traces_created": traces_created,
        "approvals_created": approvals_created,
        "audit_entries_created": audit_created,
        "datasets_created": datasets_created,
        "test_cases_created": test_cases_created,
        "test_runs_created": test_runs_created,
        "pii_sessions_created": pii_sessions_created,
        "pii_audits_created": pii_audits_created,
        "pii_permissions_granted": pii_permissions_granted,
    }


@router.delete("/clear")
async def clear_test_data(
    session: Annotated[AsyncSession, Depends(get_session)],
    _admin_user: Annotated[object, Depends(require_admin)],
):
    """Clear only test-seeded data from database.

    SECURITY: Admin authentication required.
    Only deletes records that were created by the seed endpoint (marked with source=test_seed).
    """
    # Clear traces marked as test data (using raw SQL for JSON operations)
    await db_execute(
        session, text("DELETE FROM traces WHERE metadata_json->>'source' = 'test_seed'")
    )

    # Clear approvals marked as test data
    await db_execute(session, text("DELETE FROM approvals WHERE context->>'source' = 'test_seed'"))

    # Clear audit entries marked as test data
    await db_execute(session, text("DELETE FROM audit_log WHERE details->>'source' = 'test_seed'"))

    # Get IDs of test datasets first (for cascading deletes)
    result = await db_execute(
        session, text("SELECT id FROM datasets WHERE metadata_json->>'source' = 'test_seed'")
    )
    test_dataset_ids = [row[0] for row in result.fetchall()]

    if test_dataset_ids:
        # Clear related test results first (via test runs)
        delete_test_results = text(
            "DELETE FROM test_results WHERE run_id IN "
            "(SELECT run_id FROM test_runs WHERE dataset_id IN :dataset_ids)"
        ).bindparams(bindparam("dataset_ids", expanding=True, value=test_dataset_ids))
        await db_execute(session, delete_test_results)

        # Clear test runs
        delete_test_runs = text(
            "DELETE FROM test_runs WHERE dataset_id IN :dataset_ids"
        ).bindparams(bindparam("dataset_ids", expanding=True, value=test_dataset_ids))
        await db_execute(session, delete_test_runs)

        # Clear test cases
        delete_test_cases = text(
            "DELETE FROM test_cases WHERE dataset_id IN :dataset_ids"
        ).bindparams(bindparam("dataset_ids", expanding=True, value=test_dataset_ids))
        await db_execute(session, delete_test_cases)

        # Clear datasets
        delete_datasets = text("DELETE FROM datasets WHERE id IN :dataset_ids").bindparams(
            bindparam("dataset_ids", expanding=True, value=test_dataset_ids)
        )
        await db_execute(session, delete_datasets)

    # Clear PII audit entries with test prefix
    await db_execute(session, text("DELETE FROM pii_audit_log WHERE session_id LIKE 'test_seed_%'"))

    # Clear PII sessions marked as test data
    await db_execute(
        session,
        text("DELETE FROM pii_sessions WHERE metadata_json->>'source' = 'test_seed'"),
    )

    # Clear encryption keys with test prefix
    await db_execute(session, text("DELETE FROM encryption_keys WHERE key_id LIKE 'test_seed_%'"))

    # Clear PII permissions granted by seed (marked with specific reason)
    pii_reason = "Test seed - auto-granted PII permissions"
    await db_execute(
        session,
        text("DELETE FROM user_pii_permissions WHERE reason = :reason").bindparams(
            reason=pii_reason
        ),
    )

    await db_commit(session)

    return {"success": True, "message": "Test data cleared"}
