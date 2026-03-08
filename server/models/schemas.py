"""Database models for AgentGate dashboard.

This module re-exports all schemas from specialized modules for backward compatibility.
Models are organized into separate modules by domain:
- user_schemas: User accounts, roles, permissions, and sessions
- trace_schemas: Tool execution traces
- approval_schemas: Tool execution approval requests
- audit_schemas: Audit logs, security threats, system settings, cost tracking, and dashboard stats
- dataset_schemas: Test datasets, test cases, test runs, and pytest export
- pii_schemas: PII vault compliance, encryption keys, and compliance reports
"""

from datetime import datetime, timezone

# Import from common_enums for single source of truth
from server.models.common_enums import TraceStatus

# Import from specialized modules
from server.models.user_schemas import (
    UserRole,
    Permission,
    ROLE_PERMISSIONS,
    UserBase,
    User,
    RefreshToken,
    UserCreate,
    UserRead,
    UserSession,
    UserSessionRead,
)

from server.models.trace_schemas import (
    Trace,
    TraceCreate,
    TraceRead,
)

from server.models.approval_schemas import (
    ApprovalStatus,
    Approval,
    ApprovalCreate,
    ApprovalRead,
    ApprovalDecision,
)

from server.models.audit_schemas import (
    ThreatStatus,
    SecurityThreat,
    SecurityThreatRead,
    SystemSetting,
    SystemSettingRead,
    AuditEntry,
    AuditEntryCreate,
    AuditEntryRead,
    CostRecord,
    OverviewStats,
    CostBreakdown,
    BlockBreakdown,
)

from server.models.dataset_schemas import (
    TestCaseStatus,
    AssertionType,
    Dataset,
    DatasetCreate,
    DatasetRead,
    DatasetUpdate,
    TestCase,
    TestCaseCreate,
    TestCaseRead,
    TestCaseUpdate,
    TestCaseFromTrace,
    Assertion,
    TestRunStatus,
    TestResultStatus,
    TestRun,
    TestRunCreate,
    TestRunRead,
    TestResult,
    TestResultRead,
    PytestExportConfig,
    PytestExportResult,
)

from server.models.pii_schemas import (
    PIIDataClassification,
    PIIEventType,
    PIIAuditEntry,
    PIIAuditEntryCreate,
    PIIAuditEntryRead,
    PIISession,
    PIISessionCreate,
    PIISessionRead,
    PIIHumanMapping,
    PIIAIConversationToken,
    UserPIIPermissions,
    UserPIIPermissionCreate,
    UserPIIPermissionRead,
    EncryptionKeyRecord,
    EncryptionKeyRecordRead,
    PIIComplianceStats,
    PIIAccessReport,
)
from server.models.common_enums import PIIPermission
from server.models.governance_schemas import (
    AIChangeProposal,
    AIValidationFailure,
)
from server.models.identity_schemas import (
    PrincipalType,
    PrincipalRiskLevel,
    SessionAssuranceLevel,
    ChannelTrustLevel,
    ActionSensitivityLevel,
    RuntimeThreatLevel,
    PIIObligationProfile,
    IdentityPrincipal,
    IdentityLink,
    RoleBinding,
    RiskProfile,
    SessionAssuranceEvent,
    PolicyDecisionRecord,
    VerificationGrant,
    AuthorizationContext,
    PolicyDecision,
)


def utc_now() -> datetime:
    """Get current UTC time as timezone-naive (for TIMESTAMP WITHOUT TIME ZONE columns)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Re-export all imports for backward compatibility
__all__ = [
    # Utilities
    "utc_now",
    # User schemas
    "UserRole",
    "Permission",
    "ROLE_PERMISSIONS",
    "UserBase",
    "User",
    "RefreshToken",
    "UserCreate",
    "UserRead",
    "UserSession",
    "UserSessionRead",
    # Trace schemas
    "TraceStatus",
    "Trace",
    "TraceCreate",
    "TraceRead",
    # Approval schemas
    "ApprovalStatus",
    "Approval",
    "ApprovalCreate",
    "ApprovalRead",
    "ApprovalDecision",
    # Audit schemas
    "ThreatStatus",
    "SecurityThreat",
    "SecurityThreatRead",
    "SystemSetting",
    "SystemSettingRead",
    "AuditEntry",
    "AuditEntryCreate",
    "AuditEntryRead",
    "CostRecord",
    "OverviewStats",
    "CostBreakdown",
    "BlockBreakdown",
    # Dataset schemas
    "TestCaseStatus",
    "AssertionType",
    "Dataset",
    "DatasetCreate",
    "DatasetRead",
    "DatasetUpdate",
    "TestCase",
    "TestCaseCreate",
    "TestCaseRead",
    "TestCaseUpdate",
    "TestCaseFromTrace",
    "Assertion",
    "TestRunStatus",
    "TestResultStatus",
    "TestRun",
    "TestRunCreate",
    "TestRunRead",
    "TestResult",
    "TestResultRead",
    "PytestExportConfig",
    "PytestExportResult",
    # PII schemas
    "PIIDataClassification",
    "PIIEventType",
    "PIIAuditEntry",
    "PIIAuditEntryCreate",
    "PIIAuditEntryRead",
    "PIISession",
    "PIISessionCreate",
    "PIISessionRead",
    "PIIHumanMapping",
    "PIIAIConversationToken",
    "PIIPermission",
    "UserPIIPermissions",
    "UserPIIPermissionCreate",
    "UserPIIPermissionRead",
    "EncryptionKeyRecord",
    "EncryptionKeyRecordRead",
    "PIIComplianceStats",
    "PIIAccessReport",
    # AI governance schemas
    "AIChangeProposal",
    "AIValidationFailure",
    # Identity and risk schemas
    "PrincipalType",
    "PrincipalRiskLevel",
    "SessionAssuranceLevel",
    "ChannelTrustLevel",
    "ActionSensitivityLevel",
    "RuntimeThreatLevel",
    "PIIObligationProfile",
    "IdentityPrincipal",
    "IdentityLink",
    "RoleBinding",
    "RiskProfile",
    "SessionAssuranceEvent",
    "PolicyDecisionRecord",
    "VerificationGrant",
    "AuthorizationContext",
    "PolicyDecision",
]

SCHEMA_EXPORTS = tuple(__all__)
