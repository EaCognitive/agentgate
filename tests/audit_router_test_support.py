"""Shared fixtures for audit router coverage tests."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session

from server.models import AuditEntry, User
from tests.router_test_support import bearer_token, create_test_user


@pytest.fixture(name="admin_user")
def fixture_admin_user(session: Session) -> User:
    """Create an admin user with all audit permissions."""
    return create_test_user(
        session,
        email="admin@test.com",
        name="Admin User",
        password="admin123",
        role="admin",
        is_active=True,
    )


@pytest.fixture(name="auditor_user")
def fixture_auditor_user(session: Session) -> User:
    """Create an auditor user with read and export permissions."""
    return create_test_user(
        session,
        email="auditor@test.com",
        name="Auditor User",
        password="auditor123",
        role="auditor",
        is_active=True,
    )


@pytest.fixture(name="viewer_user")
def fixture_viewer_user(session: Session) -> User:
    """Create a viewer user without audit permissions."""
    return create_test_user(
        session,
        email="viewer@test.com",
        name="Viewer User",
        password="viewer123",
        role="viewer",
        is_active=True,
    )


@pytest.fixture(name="admin_token")
def fixture_admin_token(admin_user: User) -> str:
    """Create an authentication token for the admin user."""
    return bearer_token(admin_user, expires_delta=timedelta(minutes=15))


@pytest.fixture(name="auditor_token")
def fixture_auditor_token(auditor_user: User) -> str:
    """Create an authentication token for the auditor user."""
    return bearer_token(auditor_user, expires_delta=timedelta(minutes=15))


@pytest.fixture(name="viewer_token")
def fixture_viewer_token(viewer_user: User) -> str:
    """Create an authentication token for the viewer user."""
    return bearer_token(viewer_user, expires_delta=timedelta(minutes=15))


@pytest.fixture(name="sample_audit_entries")
def fixture_sample_audit_entries(session: Session) -> list[AuditEntry]:
    """Create sample audit entries for coverage and export tests."""
    now = datetime.now(timezone.utc)
    entries = [
        AuditEntry(
            event_type="tool.execute",
            actor="user1@test.com",
            tool="read_file",
            result="success",
            details={"file": "/etc/passwd"},
            timestamp=now - timedelta(hours=2),
        ),
        AuditEntry(
            event_type="tool.execute",
            actor="user2@test.com",
            tool="write_file",
            result="failure",
            details={"error": "Permission denied"},
            timestamp=now - timedelta(hours=1),
        ),
        AuditEntry(
            event_type="user.login",
            actor="admin@test.com",
            result="success",
            timestamp=now - timedelta(minutes=30),
        ),
        AuditEntry(
            event_type="tool.execute",
            actor="user1@test.com",
            tool="read_file",
            result="success",
            details={"file": "/var/log/app.log"},
            timestamp=now - timedelta(minutes=10),
        ),
        AuditEntry(
            event_type="user.logout",
            actor="user2@test.com",
            result="success",
            timestamp=now - timedelta(minutes=5),
        ),
    ]
    for entry in entries:
        session.add(entry)
    session.commit()
    for entry in entries:
        session.refresh(entry)
    return entries
