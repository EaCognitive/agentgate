"""Tests for Approval models."""

from datetime import timedelta

from server.models.schemas import (
    ApprovalCreate,
    ApprovalDecision,
    ApprovalRead,
    ApprovalStatus,
    utc_now,
)


class TestApprovalModels:
    """Test Approval-related model classes."""

    def test_approval_create(self, sample_approval_data):
        """Test ApprovalCreate model."""
        approval = ApprovalCreate(**sample_approval_data)

        assert approval.approval_id == "approval-123"
        assert approval.tool == "dangerous_tool"
        assert approval.inputs == {"action": "delete"}
        assert approval.trace_id == "trace-123"

    def test_approval_read_structure(self):
        """Test ApprovalRead model structure."""
        now = utc_now()
        approval = ApprovalRead(
            id=1,
            approval_id="approval-123",
            tool="dangerous_tool",
            inputs={"action": "delete"},
            status=ApprovalStatus.APPROVED,
            created_by_user_id=1,
            created_by_email="user@example.com",
            decided_by="admin@example.com",
            decision_reason="Approved for testing",
            created_at=now,
            decided_at=now + timedelta(minutes=5),
        )

        assert approval.id == 1
        assert approval.status == ApprovalStatus.APPROVED
        assert approval.decided_by == "admin@example.com"

    def test_approval_decision(self):
        """Test ApprovalDecision model."""
        decision = ApprovalDecision(approved=True, reason="Looks good")

        assert decision.approved is True
        assert decision.reason == "Looks good"

    def test_approval_decision_minimal(self):
        """Test ApprovalDecision with minimal fields."""
        decision = ApprovalDecision(approved=False)

        assert decision.approved is False
        assert decision.reason is None
