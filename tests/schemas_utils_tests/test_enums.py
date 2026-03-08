"""Tests for Enum classes."""

from server.models.schemas import (
    ROLE_PERMISSIONS,
    ApprovalStatus,
    AssertionType,
    Permission,
    PIIDataClassification,
    PIIEventType,
    PIIPermission,
    TestCaseStatus,
    TestResultStatus,
    TestRunStatus,
    TraceStatus,
    UserRole,
)


class TestEnums:
    """Test all enum classes and their values."""

    def test_trace_status_enum(self):
        """Test TraceStatus enum values."""
        assert TraceStatus.PENDING.value == "pending"
        assert TraceStatus.RUNNING.value == "running"
        assert TraceStatus.SUCCESS.value == "success"
        assert TraceStatus.FAILED.value == "failed"
        assert TraceStatus.BLOCKED.value == "blocked"
        assert TraceStatus.AWAITING_APPROVAL.value == "awaiting_approval"
        assert TraceStatus.DENIED.value == "denied"
        assert TraceStatus.COMPENSATED.value == "compensated"

        # Test enum members
        assert len(TraceStatus) == 8

    def test_approval_status_enum(self):
        """Test ApprovalStatus enum values."""
        assert ApprovalStatus.PENDING.value == "pending"
        assert ApprovalStatus.APPROVED.value == "approved"
        assert ApprovalStatus.DENIED.value == "denied"
        assert ApprovalStatus.EXPIRED.value == "expired"

        assert len(ApprovalStatus) == 4

    def test_user_role_enum(self):
        """Test UserRole enum values."""
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.SECURITY_ADMIN.value == "security_admin"
        assert UserRole.APPROVER.value == "approver"
        assert UserRole.AUDITOR.value == "auditor"
        assert UserRole.DEVELOPER.value == "developer"
        assert UserRole.AGENT_OPERATOR.value == "agent_operator"
        assert UserRole.SERVICE_AGENT.value == "service_agent"
        assert UserRole.VIEWER.value == "viewer"

        assert len(UserRole) == 8

    def test_permission_enum(self):
        """Test Permission enum values."""
        # User permissions
        assert Permission.USER_CREATE.value == "user:create"
        assert Permission.USER_READ.value == "user:read"
        assert Permission.USER_UPDATE.value == "user:update"
        assert Permission.USER_DELETE.value == "user:delete"

        # Trace permissions
        assert Permission.TRACE_READ.value == "trace:read"
        assert Permission.TRACE_READ_ALL.value == "trace:read_all"
        assert Permission.TRACE_DELETE.value == "trace:delete"

        # Approval permissions
        assert Permission.APPROVAL_READ.value == "approval:read"
        assert Permission.APPROVAL_DECIDE.value == "approval:decide"

        # Audit permissions
        assert Permission.AUDIT_READ.value == "audit:read"
        assert Permission.AUDIT_EXPORT.value == "audit:export"

        # Dataset permissions
        assert Permission.DATASET_CREATE.value == "dataset:create"
        assert Permission.DATASET_READ.value == "dataset:read"
        assert Permission.DATASET_UPDATE.value == "dataset:update"
        assert Permission.DATASET_DELETE.value == "dataset:delete"
        assert Permission.DATASET_RUN.value == "dataset:run"

        # Cost permissions
        assert Permission.COST_READ.value == "cost:read"
        assert Permission.COST_LIMIT.value == "cost:limit"

        # Config permissions
        assert Permission.CONFIG_READ.value == "config:read"
        assert Permission.CONFIG_UPDATE.value == "config:update"

    def test_test_case_status_enum(self):
        """Test TestCaseStatus enum values."""
        assert TestCaseStatus.ACTIVE.value == "active"
        assert TestCaseStatus.DISABLED.value == "disabled"
        assert TestCaseStatus.DRAFT.value == "draft"

        assert len(TestCaseStatus) == 3

    def test_assertion_type_enum(self):
        """Test AssertionType enum values."""
        assert AssertionType.EQUALS.value == "equals"
        assert AssertionType.CONTAINS.value == "contains"
        assert AssertionType.NOT_CONTAINS.value == "not_contains"
        assert AssertionType.MATCHES_REGEX.value == "matches_regex"
        assert AssertionType.JSON_PATH.value == "json_path"
        assert AssertionType.TYPE_CHECK.value == "type_check"

        # CUSTOM is deprecated and should not exist
        assert len(AssertionType) == 6

    def test_test_run_status_enum(self):
        """Test TestRunStatus enum values."""
        assert TestRunStatus.PENDING.value == "pending"
        assert TestRunStatus.RUNNING.value == "running"
        assert TestRunStatus.COMPLETED.value == "completed"
        assert TestRunStatus.FAILED.value == "failed"
        assert TestRunStatus.CANCELLED.value == "cancelled"

        assert len(TestRunStatus) == 5

    def test_test_result_status_enum(self):
        """Test TestResultStatus enum values."""
        assert TestResultStatus.PASSED.value == "passed"
        assert TestResultStatus.FAILED.value == "failed"
        assert TestResultStatus.ERROR.value == "error"
        assert TestResultStatus.SKIPPED.value == "skipped"

        assert len(TestResultStatus) == 4

    def test_pii_data_classification_enum(self):
        """Test PIIDataClassification enum values."""
        assert PIIDataClassification.PUBLIC.value == "public"
        assert PIIDataClassification.INTERNAL.value == "internal"
        assert PIIDataClassification.CONFIDENTIAL.value == "confidential"
        assert PIIDataClassification.RESTRICTED.value == "restricted"

        assert len(PIIDataClassification) == 4

    def test_pii_event_type_enum(self):
        """Test PIIEventType enum values."""
        assert PIIEventType.PII_STORE.value == "pii_store"
        assert PIIEventType.PII_RETRIEVE.value == "pii_retrieve"
        assert PIIEventType.PII_DELETE.value == "pii_delete"
        assert PIIEventType.PII_BULK_RETRIEVE.value == "pii_bulk_retrieve"
        assert PIIEventType.PII_CLEAR_SESSION.value == "pii_clear_session"
        assert PIIEventType.PII_INTEGRITY_FAILURE.value == "pii_integrity_failure"
        assert PIIEventType.PII_DECRYPTION_FAILURE.value == "pii_decryption_failure"
        assert PIIEventType.ACCESS_DENIED.value == "access_denied"
        assert PIIEventType.KEY_ROTATION.value == "key_rotation"

        assert len(PIIEventType) == 9

    def test_pii_permission_enum(self):
        """Test PIIPermission enum values."""
        assert PIIPermission.PII_STORE.value == "pii:store"
        assert PIIPermission.PII_RETRIEVE.value == "pii:retrieve"
        assert PIIPermission.PII_DELETE.value == "pii:delete"
        assert PIIPermission.PII_BULK_RETRIEVE.value == "pii:bulk_retrieve"
        assert PIIPermission.PII_CLEAR_SESSION.value == "pii:clear_session"
        assert PIIPermission.PII_CLEAR_ALL.value == "pii:clear_all"
        assert PIIPermission.PII_EXPORT.value == "pii:export"
        assert PIIPermission.PII_AUDIT_READ.value == "pii:audit_read"
        assert PIIPermission.KEY_ROTATE.value == "key:rotate"
        assert PIIPermission.KEY_VIEW.value == "key:view"
        assert PIIPermission.CONFIG_VIEW.value == "config:view"
        assert PIIPermission.CONFIG_MODIFY.value == "config:modify"

        assert len(PIIPermission) == 12


class TestRolePermissions:
    """Test role to permissions mapping."""

    def test_role_permissions_structure(self):
        """Test ROLE_PERMISSIONS dictionary structure."""
        assert isinstance(ROLE_PERMISSIONS, dict)
        assert len(ROLE_PERMISSIONS) == 9

        # All roles should be present
        assert "admin" in ROLE_PERMISSIONS
        assert "security_admin" in ROLE_PERMISSIONS
        assert "approver" in ROLE_PERMISSIONS
        assert "auditor" in ROLE_PERMISSIONS
        assert "developer" in ROLE_PERMISSIONS
        assert "agent_operator" in ROLE_PERMISSIONS
        assert "service_agent" in ROLE_PERMISSIONS
        assert "viewer" in ROLE_PERMISSIONS
        assert "operator" in ROLE_PERMISSIONS

    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions."""
        admin_perms = ROLE_PERMISSIONS["admin"]
        # Admin should have all 23 permissions (4 user + 3 trace + 2 approval + 2 audit +
        # 5 dataset + 3 cost + 2 config + 2 security threat)
        assert len(admin_perms) == 23

        # Check specific permissions
        assert Permission.USER_CREATE in admin_perms
        assert Permission.USER_DELETE in admin_perms
        assert Permission.CONFIG_UPDATE in admin_perms

    def test_approver_permissions(self):
        """Test approver role permissions."""
        approver_perms = ROLE_PERMISSIONS["approver"]

        # Should have approval permissions
        assert Permission.APPROVAL_DECIDE in approver_perms
        assert Permission.TRACE_READ_ALL in approver_perms

        # Should not have user management
        assert Permission.USER_CREATE not in approver_perms
        assert Permission.USER_DELETE not in approver_perms

    def test_auditor_permissions(self):
        """Test auditor role permissions."""
        auditor_perms = ROLE_PERMISSIONS["auditor"]

        # Should have read-only permissions
        assert Permission.AUDIT_READ in auditor_perms
        assert Permission.AUDIT_EXPORT in auditor_perms
        assert Permission.TRACE_READ_ALL in auditor_perms

        # Should not have write permissions
        assert Permission.APPROVAL_DECIDE not in auditor_perms
        assert Permission.CONFIG_UPDATE not in auditor_perms

    def test_developer_permissions(self):
        """Test developer role permissions."""
        developer_perms = ROLE_PERMISSIONS["developer"]

        # Should have dataset permissions
        assert Permission.DATASET_CREATE in developer_perms
        assert Permission.DATASET_RUN in developer_perms
        assert Permission.TRACE_READ_ALL in developer_perms

        # Should not have approval or config permissions
        assert Permission.APPROVAL_DECIDE not in developer_perms
        assert Permission.CONFIG_UPDATE not in developer_perms

    def test_viewer_permissions(self):
        """Test viewer role permissions (most restricted)."""
        viewer_perms = ROLE_PERMISSIONS["viewer"]

        # Should have minimal read permissions
        assert Permission.USER_READ in viewer_perms
        assert Permission.TRACE_READ in viewer_perms
        assert Permission.DATASET_READ in viewer_perms

        # Should not have write or management permissions
        assert Permission.TRACE_DELETE not in viewer_perms
        assert Permission.DATASET_CREATE not in viewer_perms
        assert Permission.APPROVAL_DECIDE not in viewer_perms
