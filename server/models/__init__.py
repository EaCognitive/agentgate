"""Database models."""

from sqlalchemy.ext.asyncio import AsyncSession

from . import schemas as _schemas
from .database import (
    engine,
    init_db,
    get_session,
    get_session_context,
    close_db,
    # Sync fallbacks for migrations (lazy-loaded to avoid psycopg2 at import time)
    get_sync_engine,
    get_sync_session,
    init_db_sync,
)

# Import all schemas for re-export
from .security_policy_schemas import SecurityPolicy, SecurityPolicyRead

from .prompt_schemas import (
    PromptCategory,
    PromptTemplate,
    PromptTemplateCreate,
    PromptTemplateUpdate,
    PromptTemplateRead,
    PromptTemplateUsageStats,
)
from .formal_security_schemas import (
    DelegationGrant,
    DelegationRevocation,
    DecisionCertificateRecord,
    ExecutionEvidenceChain,
    CounterexampleTrace,
    ProofVerificationRun,
    DelegationGrantRead,
    DecisionCertificateRecordRead,
)

SCHEMA_EXPORTS = tuple(_schemas.__all__)
utc_now = _schemas.utc_now
UserRole = _schemas.UserRole
Permission = _schemas.Permission
ROLE_PERMISSIONS = _schemas.ROLE_PERMISSIONS
UserBase = _schemas.UserBase
User = _schemas.User
RefreshToken = _schemas.RefreshToken
UserCreate = _schemas.UserCreate
UserRead = _schemas.UserRead
UserSession = _schemas.UserSession
UserSessionRead = _schemas.UserSessionRead
TraceStatus = _schemas.TraceStatus
Trace = _schemas.Trace
TraceCreate = _schemas.TraceCreate
TraceRead = _schemas.TraceRead
ApprovalStatus = _schemas.ApprovalStatus
Approval = _schemas.Approval
ApprovalCreate = _schemas.ApprovalCreate
ApprovalRead = _schemas.ApprovalRead
ApprovalDecision = _schemas.ApprovalDecision
ThreatStatus = _schemas.ThreatStatus
SecurityThreat = _schemas.SecurityThreat
SecurityThreatRead = _schemas.SecurityThreatRead
SystemSetting = _schemas.SystemSetting
SystemSettingRead = _schemas.SystemSettingRead
AuditEntry = _schemas.AuditEntry
AuditEntryCreate = _schemas.AuditEntryCreate
AuditEntryRead = _schemas.AuditEntryRead
CostRecord = _schemas.CostRecord
OverviewStats = _schemas.OverviewStats
CostBreakdown = _schemas.CostBreakdown
BlockBreakdown = _schemas.BlockBreakdown
TestCaseStatus = _schemas.TestCaseStatus
AssertionType = _schemas.AssertionType
Dataset = _schemas.Dataset
DatasetCreate = _schemas.DatasetCreate
DatasetRead = _schemas.DatasetRead
DatasetUpdate = _schemas.DatasetUpdate
TestCase = _schemas.TestCase
TestCaseCreate = _schemas.TestCaseCreate
TestCaseRead = _schemas.TestCaseRead
TestCaseUpdate = _schemas.TestCaseUpdate
TestCaseFromTrace = _schemas.TestCaseFromTrace
Assertion = _schemas.Assertion
TestRunStatus = _schemas.TestRunStatus
TestResultStatus = _schemas.TestResultStatus
TestRun = _schemas.TestRun
TestRunCreate = _schemas.TestRunCreate
TestRunRead = _schemas.TestRunRead
TestResult = _schemas.TestResult
TestResultRead = _schemas.TestResultRead
PytestExportConfig = _schemas.PytestExportConfig
PytestExportResult = _schemas.PytestExportResult
PIIDataClassification = _schemas.PIIDataClassification
PIIEventType = _schemas.PIIEventType
PIIAuditEntry = _schemas.PIIAuditEntry
PIIAuditEntryCreate = _schemas.PIIAuditEntryCreate
PIIAuditEntryRead = _schemas.PIIAuditEntryRead
PIISession = _schemas.PIISession
PIISessionCreate = _schemas.PIISessionCreate
PIISessionRead = _schemas.PIISessionRead
PIIHumanMapping = _schemas.PIIHumanMapping
PIIAIConversationToken = _schemas.PIIAIConversationToken
PIIPermission = _schemas.PIIPermission
UserPIIPermissions = _schemas.UserPIIPermissions
UserPIIPermissionCreate = _schemas.UserPIIPermissionCreate
UserPIIPermissionRead = _schemas.UserPIIPermissionRead
EncryptionKeyRecord = _schemas.EncryptionKeyRecord
EncryptionKeyRecordRead = _schemas.EncryptionKeyRecordRead
PIIComplianceStats = _schemas.PIIComplianceStats
PIIAccessReport = _schemas.PIIAccessReport
AIChangeProposal = _schemas.AIChangeProposal
AIValidationFailure = _schemas.AIValidationFailure
PrincipalType = _schemas.PrincipalType
PrincipalRiskLevel = _schemas.PrincipalRiskLevel
SessionAssuranceLevel = _schemas.SessionAssuranceLevel
ChannelTrustLevel = _schemas.ChannelTrustLevel
ActionSensitivityLevel = _schemas.ActionSensitivityLevel
RuntimeThreatLevel = _schemas.RuntimeThreatLevel
PIIObligationProfile = _schemas.PIIObligationProfile
IdentityPrincipal = _schemas.IdentityPrincipal
IdentityLink = _schemas.IdentityLink
RoleBinding = _schemas.RoleBinding
RiskProfile = _schemas.RiskProfile
SessionAssuranceEvent = _schemas.SessionAssuranceEvent
PolicyDecisionRecord = _schemas.PolicyDecisionRecord
VerificationGrant = _schemas.VerificationGrant
AuthorizationContext = _schemas.AuthorizationContext
PolicyDecision = _schemas.PolicyDecision

# Build __all__ by combining database exports with schema exports
__all__ = [
    # Database
    "engine",
    "init_db",
    "get_session",
    "get_session_context",
    "close_db",
    "AsyncSession",
    # Sync fallbacks (lazy-loaded)
    "get_sync_engine",
    "get_sync_session",
    "init_db_sync",
    *SCHEMA_EXPORTS,
    # Security policy schemas
    "SecurityPolicy",
    "SecurityPolicyRead",
    # Prompt template schemas
    "PromptCategory",
    "PromptTemplate",
    "PromptTemplateCreate",
    "PromptTemplateUpdate",
    "PromptTemplateRead",
    "PromptTemplateUsageStats",
    # Formal security and delegation schemas
    "DelegationGrant",
    "DelegationRevocation",
    "DecisionCertificateRecord",
    "ExecutionEvidenceChain",
    "CounterexampleTrace",
    "ProofVerificationRun",
    "DelegationGrantRead",
    "DecisionCertificateRecordRead",
]
