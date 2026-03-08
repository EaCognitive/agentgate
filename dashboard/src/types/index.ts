/**
 * Core TypeScript interfaces and types for the AgentGate dashboard
 */

/**
 * User role enumeration
 */
export enum UserRole {
  Admin = 'admin',
  SecurityAdmin = 'security_admin',
  Approver = 'approver',
  Auditor = 'auditor',
  Developer = 'developer',
  AgentOperator = 'agent_operator',
  ServiceAgent = 'service_agent',
  Viewer = 'viewer',
  // Backward-compatible alias during role migration window.
  Operator = 'operator',
}

/**
 * User interface representing an authenticated user
 */
export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
}

/**
 * TraceStatus enumeration for execution state
 */
export enum TraceStatus {
  Pending = 'pending',
  Running = 'running',
  Success = 'success',
  Failed = 'failed',
  Blocked = 'blocked',
}

/**
 * Trace interface representing an agent tool execution
 */
export interface Trace {
  id: string;
  trace_id: string;
  tool: string;
  inputs: Record<string, unknown>;
  output?: Record<string, unknown>;
  status: TraceStatus;
  error?: string;
  blocked_by?: string;
  duration_ms: number;
  cost: number;
  started_at: string;
  ended_at?: string;
}

/**
 * ApprovalStatus enumeration for approval workflow
 */
export enum ApprovalStatus {
  Pending = 'pending',
  Approved = 'approved',
  Denied = 'denied',
  Expired = 'expired',
}

/**
 * Approval interface representing a tool execution requiring approval
 */
export interface Approval {
  id: string;
  approval_id: string;
  tool: string;
  inputs: Record<string, unknown>;
  status: ApprovalStatus;
  created_at: string;
  decided_by?: string;
  decided_at?: string;
}

/**
 * EventType enumeration for audit log entries
 */
export enum AuditEventType {
  Login = 'login',
  LoginFailed = 'login_failed',
  TokenRefresh = 'token_refresh',
  PlaygroundChat = 'playground_chat',
  PlaygroundBlocked = 'playground_blocked',
  TraceCreated = 'trace_created',
  TraceCompleted = 'trace_completed',
  TraceFailed = 'trace_failed',
  TraceBlocked = 'trace_blocked',
  ApprovalRequested = 'approval_requested',
  ApprovalApproved = 'approval_approved',
  ApprovalDenied = 'approval_denied',
  ApprovalExpired = 'approval_expired',
  ConfigChanged = 'config_changed',
  AccessGrant = 'access_grant',
  AccessRevoke = 'access_revoke',
}

/**
 * AuditEntry interface for audit log records
 */
export interface AuditEntry {
  id: string;
  timestamp: string;
  event_type: AuditEventType;
  actor: string;
  tool: string;
  result: 'success' | 'failure';
  details: Record<string, unknown>;
}

/**
 * CostBreakdown interface for per-tool cost analytics
 */
export interface CostBreakdown {
  tool: string;
  call_count: number;
  total_cost: number;
  average_cost: number;
  success_count: number;
  failed_count: number;
  blocked_count: number;
}

/**
 * CostSummary interface for overall cost analytics
 */
export interface CostSummary {
  period_start: string;
  period_end: string;
  total_cost: number;
  total_calls: number;
  average_cost_per_call: number;
  breakdown: CostBreakdown[];
}

/**
 * OverviewStats interface for dashboard statistics
 */
export interface OverviewStats {
  total_calls: number;
  success_count: number;
  blocked_count: number;
  failed_count: number;
  success_rate: number;
  total_cost: number;
  pending_approvals: number;
}

/**
 * TraceTimeline interface for time-series trace data
 */
export interface TraceTimeline {
  timestamp: string;
  total_calls: number;
  success_count: number;
  failed_count: number;
  blocked_count: number;
  total_cost: number;
}

/**
 * DecideApprovalRequest interface for approval decision submission
 */
export interface DecideApprovalRequest {
  approval_id: string;
  approved: boolean;
  reason?: string;
}

/**
 * DecideApprovalResponse interface for approval decision response
 */
export interface DecideApprovalResponse {
  id: string;
  approval_id: string;
  status: ApprovalStatus;
  decided_by: string;
  decided_at: string;
}

/**
 * API error response
 */
export interface ApiErrorResponse {
  error: string;
  message: string;
  status_code: number;
  timestamp: string;
}

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

/**
 * Trace filter options
 */
export interface TraceFilters {
  tool?: string;
  status?: TraceStatus;
  start_date?: string;
  end_date?: string;
  min_cost?: number;
  max_cost?: number;
  search?: string;
  page?: number;
  page_size?: number;
}

/**
 * Approval filter options
 */
export interface ApprovalFilters {
  tool?: string;
  status?: ApprovalStatus;
  start_date?: string;
  end_date?: string;
  search?: string;
  page?: number;
  page_size?: number;
}

/**
 * Audit log filter options
 */
export interface AuditLogFilters {
  event_type?: AuditEventType;
  actor?: string;
  tool?: string;
  result?: 'success' | 'failure';
  start_date?: string;
  end_date?: string;
  search?: string;
  page?: number;
  page_size?: number;
}

/**
 * Export format types
 */
export type ExportFormat = 'csv' | 'json' | 'xlsx';

/**
 * API response wrapper
 */

/**
 * Predicate outcome from a constructive trace
 */
export interface PredicateOutcome {
  predicate: string;
  value: boolean;
  witness: Record<string, unknown>;
}

/**
 * Runtime solver payload from Z3 evaluation
 */
export interface RuntimeSolverPayload {
  solver_mode: string;
  solver_backend: string;
  python_result: boolean;
  z3_result: boolean | null;
  z3_check_result: string | null;
  drift_detected: boolean;
  failure_reason: string | null;
}

/**
 * Full admissibility evaluation response
 */
export interface AdmissibilityResponse {
  success: boolean;
  certificate: {
    decision_id: string;
    theorem_hash: string;
    result: string;
    proof_type: string;
    proof_payload: {
      constructive_trace?: PredicateOutcome[];
      unsat_core?: string[];
      trace?: PredicateOutcome[];
      counterexample?: Record<string, unknown>;
      deny_absence_proof?: Record<string, unknown>;
      runtime_solver?: RuntimeSolverPayload;
    };
    alpha_hash: string;
    gamma_hash: string;
    solver_version: string;
    signature: string | null;
    created_at: string;
  };
  runtime_solver: RuntimeSolverPayload;
}

/**
 * Runtime solver status from /runtime-status endpoint
 */
export interface RuntimeSolverStatus {
  configured_mode: string;
  environment: string;
  off_mode_allowed: boolean;
  z3_available: boolean;
  z3_healthy: boolean;
  z3_check_result: string | null;
  z3_error?: string;
}

export type {
  PolicyCondition,
  PolicyRule,
  PolicyJsonDocument,
  PolicySetRequest,
  PolicySetResponse,
  PolicyListResponse,
  PolicyPatchRequest,
  EvaluatePolicyRequest,
  EvaluatePolicyResponse,
  PolicyDetailResponse,
} from './policy';
export interface ApiResponse<T> {
  data: T;
  timestamp: string;
}

/**
 * Test case status enumeration
 */
export enum TestCaseStatus {
  Active = 'active',
  Disabled = 'disabled',
  Draft = 'draft',
}

/**
 * Assertion type enumeration
 */
export enum AssertionType {
  Equals = 'equals',
  Contains = 'contains',
  NotContains = 'not_contains',
  MatchesRegex = 'matches_regex',
  JsonPath = 'json_path',
  TypeCheck = 'type_check',
  Custom = 'custom',
}

/**
 * Assertion interface for test case assertions
 */
export interface Assertion {
  type: AssertionType;
  expected?: unknown;
  expected_type?: string;
  path?: string;
  pattern?: string;
  description?: string;
  custom_fn?: string;
}

/**
 * Dataset interface for test datasets
 */
export interface Dataset {
  id: number;
  name: string;
  description?: string;
  created_by?: number;
  tags?: string[];
  test_count: number;
  last_run_at?: string;
  last_run_pass_rate?: number;
  created_at: string;
  updated_at: string;
}

/**
 * Test case interface
 */
export interface TestCase {
  id: number;
  dataset_id: number;
  name: string;
  tool: string;
  inputs: Record<string, unknown>;
  expected_output?: Record<string, unknown>;
  assertions?: Assertion[];
  source_trace_id?: string;
  status: TestCaseStatus;
  tags?: string[];
  description?: string;
  timeout_ms?: number;
  retry_count?: number;
  created_at: string;
  updated_at: string;
}

/**
 * Test run status enumeration
 */
export enum TestRunStatus {
  Pending = 'pending',
  Running = 'running',
  Completed = 'completed',
  Failed = 'failed',
  Cancelled = 'cancelled',
}

/**
 * Test result status enumeration
 */
export enum TestResultStatus {
  Passed = 'passed',
  Failed = 'failed',
  Error = 'error',
  Skipped = 'skipped',
  Timeout = 'timeout',
}

/**
 * Test run interface
 */
export interface TestRun {
  id: number;
  dataset_id: number;
  status: TestRunStatus;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  error_tests: number;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  triggered_by?: number;
  environment?: string;
  notes?: string;
}

/**
 * Test result interface
 */
export interface TestResult {
  id: number;
  test_run_id: number;
  test_case_id: number;
  status: TestResultStatus;
  actual_output?: Record<string, unknown>;
  assertion_results?: Array<{
    assertion_index: number;
    passed: boolean;
    message?: string;
  }>;
  error_message?: string;
  duration_ms?: number;
  started_at: string;
  ended_at?: string;
}

/**
 * Dataset filter options
 */
export interface DatasetFilters {
  search?: string;
  tags?: string[];
  page?: number;
  page_size?: number;
}

/**
 * Test case filter options
 */
export interface TestCaseFilters {
  tool?: string;
  status?: TestCaseStatus;
  tags?: string[];
  search?: string;
  page?: number;
  page_size?: number;
}
