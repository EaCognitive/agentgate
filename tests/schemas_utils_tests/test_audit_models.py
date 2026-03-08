"""Tests for Audit models."""

from server.models.schemas import AuditEntryCreate, AuditEntryRead, utc_now


class TestAuditModels:
    """Test Audit-related model classes."""

    def test_audit_entry_create(self):
        """Test AuditEntryCreate model."""
        audit = AuditEntryCreate(
            event_type="user_login",
            actor="test@example.com",
            tool="auth",
            result="success",
            ip_address="192.168.1.1",
        )

        assert audit.event_type == "user_login"
        assert audit.actor == "test@example.com"
        assert audit.ip_address == "192.168.1.1"

    def test_audit_entry_read(self):
        """Test AuditEntryRead model."""
        now = utc_now()
        audit = AuditEntryRead(
            id=1,
            timestamp=now,
            event_type="user_login",
            actor="test@example.com",
            tool="auth",
            result="success",
            details={"method": "password"},
        )

        assert audit.id == 1
        assert audit.event_type == "user_login"
        assert audit.details == {"method": "password"}
