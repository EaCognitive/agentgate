"""Tests for PII models."""

from datetime import timedelta

from server.models.schemas import (
    PIIAccessReport,
    PIIAuditEntryCreate,
    PIIComplianceStats,
    PIIEventType,
    PIIPermission,
    PIISessionCreate,
    UserPIIPermissionCreate,
    utc_now,
)


class TestPIIModels:
    """Test PII-related model classes."""

    def test_pii_audit_entry_create(self):
        """Test PIIAuditEntryCreate model."""
        entry = PIIAuditEntryCreate(
            event_id="evt-123",
            event_type=PIIEventType.PII_STORE.value,
            user_id="user-123",
            session_id="session-123",
            agent_id="agent-1",
            source_ip="192.168.1.1",
            placeholder="<PERSON_1>",
            pii_type="PERSON",
            data_classification="confidential",
            success=True,
            encryption_key_id="key-123",
            integrity_hash="hash123",
        )

        assert entry.event_id == "evt-123"
        assert entry.event_type == PIIEventType.PII_STORE.value
        assert entry.placeholder == "<PERSON_1>"
        assert entry.success is True

    def test_pii_session_create(self):
        """Test PIISessionCreate model."""
        session = PIISessionCreate(
            session_id="session-123",
            user_id="user-123",
            agent_id="agent-1",
            purpose="data processing",
            expires_at=utc_now() + timedelta(hours=1),
        )

        assert session.session_id == "session-123"
        assert session.user_id == "user-123"
        assert session.purpose == "data processing"

    def test_user_pii_permission_create(self):
        """Test UserPIIPermissionCreate model."""
        permission = UserPIIPermissionCreate(
            user_id=1,
            permission=PIIPermission.PII_RETRIEVE.value,
            reason="Required for job function",
            expires_at=utc_now() + timedelta(days=90),
        )

        assert permission.user_id == 1
        assert permission.permission == PIIPermission.PII_RETRIEVE.value
        assert permission.reason == "Required for job function"

    def test_pii_compliance_stats(self):
        """Test PIIComplianceStats model."""
        stats = PIIComplianceStats(
            total_pii_stored=100,
            total_pii_retrieved=500,
            total_sessions=50,
            active_sessions=10,
            integrity_failures=0,
            access_denied_count=5,
            encryption_key_age_days=30,
            last_key_rotation=utc_now(),
        )

        assert stats.total_pii_stored == 100
        assert stats.active_sessions == 10
        assert stats.integrity_failures == 0

    def test_pii_access_report(self):
        """Test PIIAccessReport model."""
        now = utc_now()
        report = PIIAccessReport(
            user_id="user-123",
            session_id="session-123",
            access_count=10,
            pii_types_accessed=["PERSON", "EMAIL"],
            first_access=now - timedelta(hours=1),
            last_access=now,
            purposes=["data processing", "analytics"],
        )

        assert report.user_id == "user-123"
        assert report.access_count == 10
        assert "PERSON" in report.pii_types_accessed
