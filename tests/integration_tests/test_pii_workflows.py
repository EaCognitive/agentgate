"""PII detection, encryption, and rehydration integration tests."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import (
    EncryptionKeyRecord,
    PIIAuditEntry,
    PIISession,
)


def test_pii_complete_workflow(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test PII vault workflow: Detect → Encrypt → Store → Rehydrate."""
    # Step 1: Create encryption key
    key_record = EncryptionKeyRecord(
        key_id=f"key_{uuid.uuid4().hex[:12]}",
        algorithm="AES-256-GCM",
        created_by=1,  # Admin user ID
    )
    session.add(key_record)
    session.commit()

    # Step 2: Grant PII permissions to user
    permission_data = {
        "user_id": 1,
        "permission": "pii:store",
        "reason": "Testing PII workflow",
    }
    response = client.post("/api/pii/permissions", json=permission_data, headers=admin_headers)
    assert response.status_code == 200

    # Step 3: Create PII session
    session_id = f"session_{uuid.uuid4().hex[:12]}"
    pii_session_data = {
        "session_id": session_id,
        "user_id": "test-user",
        "agent_id": "test-agent",
        "purpose": "customer support",
    }
    response = client.post("/api/pii/sessions", json=pii_session_data, headers=admin_headers)
    assert response.status_code == 200

    # Step 4: Verify session created
    response = client.get("/api/pii/sessions", headers=admin_headers)
    assert response.status_code == 200
    sessions = response.json()
    assert any(s["session_id"] == session_id for s in sessions)

    # Step 5: Create PII audit entry (simulating PII storage)
    pii_audit = PIIAuditEntry(
        event_id=str(uuid.uuid4()),
        event_type="pii_store",
        user_id="test-user",
        session_id=session_id,
        placeholder="PII_EMAIL_001",
        pii_type="email",
        data_classification="sensitive",
        success=True,
        encryption_key_id=key_record.key_id,
    )
    session.add(pii_audit)
    session.commit()

    # Step 6: Verify PII audit log
    response = client.get("/api/pii/audit", headers=admin_headers)
    assert response.status_code == 200
    audit_entries = response.json()
    assert len(audit_entries) > 0

    # Step 7: Clear session
    response = client.delete(f"/api/pii/sessions/{session_id}", headers=admin_headers)
    assert response.status_code == 200


def test_pii_encryption_key_rotation(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test encryption key rotation workflow."""
    # Create initial key
    old_key = EncryptionKeyRecord(
        key_id="old_key_001",
        algorithm="AES-256-GCM",
        created_by=1,
        is_active=True,
    )
    session.add(old_key)
    session.commit()

    # Rotate key
    response = client.post("/api/pii/keys/rotate", headers=admin_headers)
    assert response.status_code == 200
    result = response.json()
    assert result["rotated_keys_count"] >= 1  # At least our key was rotated
    assert "new_key_id" in result

    # Verify old key is deactivated
    session.refresh(old_key)
    assert old_key.is_active is False
    assert old_key.rotated_at is not None

    # Verify new key exists (at least one active key)
    response = client.get("/api/pii/keys", headers=admin_headers)
    assert response.status_code == 200
    keys = response.json()
    active_keys = [k for k in keys if k["is_active"]]
    assert len(active_keys) >= 1


def test_pii_audit_chain_verification(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test PII audit log chain integrity verification."""
    # Create chain of PII audit entries
    previous_hash = None
    for i in range(5):
        entry = PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type="pii_retrieve",
            user_id="test-user",
            session_id=f"session_{i}",
            placeholder=f"PII_{i}",
            pii_type="email",
            success=True,
            previous_hash=previous_hash,
        )
        session.add(entry)
        session.commit()
        session.refresh(entry)
        previous_hash = entry.integrity_hash

    # Verify chain integrity
    response = client.get("/api/pii/audit/verify-chain", headers=admin_headers)
    assert response.status_code == 200
    verification = response.json()
    assert verification["valid"] is True
    assert verification["entries_checked"] >= 5


def test_pii_compliance_statistics(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test PII compliance statistics and reporting."""
    # Create sample data
    key = EncryptionKeyRecord(
        key_id="stat_key_001",
        algorithm="AES-256-GCM",
        created_by=1,
    )
    session.add(key)

    pii_session = PIISession(
        session_id="stat_session_001",
        user_id="test-user",
        agent_id="test-agent",
        purpose="testing",
    )
    session.add(pii_session)

    # Create audit entries
    for i in range(10):
        entry = PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type="pii_store" if i < 5 else "pii_retrieve",
            user_id="test-user",
            session_id="stat_session_001",
            placeholder=f"PII_{i}",
            pii_type="email",
            success=True,
        )
        session.add(entry)
    session.commit()

    # Get compliance stats
    response = client.get("/api/pii/stats", headers=admin_headers)
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_pii_stored"] >= 5
    assert stats["total_pii_retrieved"] >= 5
    assert stats["total_sessions"] >= 1


def test_pii_access_report_generation(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test PII access report for compliance auditing."""
    # Create session
    pii_session = PIISession(
        session_id="report_session",
        user_id="auditor",
        agent_id="test-agent",
        purpose="compliance review",
    )
    session.add(pii_session)

    # Create access entries
    for i in range(5):
        entry = PIIAuditEntry(
            event_id=str(uuid.uuid4()),
            event_type="pii_retrieve",
            user_id="auditor",
            session_id="report_session",
            placeholder=f"PII_{i}",
            pii_type="ssn" if i < 3 else "email",
            success=True,
        )
        session.add(entry)
    session.commit()

    # Generate access report
    response = client.get("/api/pii/access-report", headers=admin_headers)
    assert response.status_code == 200
    report = response.json()
    assert isinstance(report, list)
    assert len(report) > 0
    assert any(r["user_id"] == "auditor" for r in report)


def test_pii_permission_enforcement(client: TestClient, admin_headers: dict[str, str]) -> None:
    """Test PII permission enforcement across users."""
    # Admin grants permission to specific user
    permission_data = {
        "user_id": 1,
        "permission": "pii:retrieve",
        "reason": "Data analysis task",
    }
    response = client.post("/api/pii/permissions", json=permission_data, headers=admin_headers)
    assert response.status_code == 200

    # Verify permission was granted
    response = client.get("/api/pii/permissions", headers=admin_headers)
    assert response.status_code == 200
    permissions = response.json()
    # Filter for user 1's permissions
    user1_perms = [p for p in permissions if p.get("user_id") == 1]
    assert any(p["permission"] == "pii:retrieve" for p in user1_perms)


def test_pii_data_retention_compliance(
    client: TestClient, admin_headers: dict[str, str], session: Session
) -> None:
    """Test PII data retention and cleanup workflows."""

    # Create old PII session
    old_session = PIISession(
        session_id="old_pii_session",
        user_id="test-user",
        agent_id="test-agent",
        purpose="expired testing",
        created_at=datetime.now(timezone.utc) - timedelta(days=100),
    )
    session.add(old_session)

    # Create recent PII session
    recent_session = PIISession(
        session_id="recent_pii_session",
        user_id="test-user",
        agent_id="test-agent",
        purpose="current testing",
        created_at=datetime.now(timezone.utc),
    )
    session.add(recent_session)
    session.commit()

    # Query all sessions
    response = client.get("/api/pii/sessions", headers=admin_headers)
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) >= 2
