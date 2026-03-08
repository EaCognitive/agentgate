/**
 * Zod Schemas for API Request/Response Validation
 *
 * Implements D-01 from the architectural audit - runtime schema validation
 * to prevent type-safety erosion in API routes.
 *
 * @author Erick | Founding Principal AI Architect
 */

import { z } from 'zod';

// ============================================================================
// Auth Schemas
// ============================================================================

export const RegisterRequestSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
});

export const LoginRequestSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
  mfa_code: z.string().optional(),
});

// ============================================================================
// Approval Schemas
// ============================================================================

export const DecideApprovalRequestSchema = z.object({
  approved: z.boolean(),
  reason: z.string().max(500, 'Reason too long').optional(),
});

// ============================================================================
// Dataset Schemas
// ============================================================================

export const CreateDatasetRequestSchema = z.object({
  name: z.string().min(1, 'Name is required').max(200, 'Name too long'),
  description: z.string().max(1000, 'Description too long').optional(),
  tags: z.array(z.string().max(50)).max(10, 'Too many tags').optional(),
});

export const UpdateDatasetRequestSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(1000).optional(),
  tags: z.array(z.string().max(50)).max(10).optional(),
});

// ============================================================================
// Test Case Schemas
// ============================================================================

export const AssertionSchema = z.object({
  type: z.enum(['equals', 'contains', 'not_contains', 'matches_regex', 'json_path', 'type_check', 'custom']),
  expected: z.unknown().optional(),
  expected_type: z.string().optional(),
  path: z.string().optional(),
  pattern: z.string().optional(),
  description: z.string().max(500).optional(),
  custom_fn: z.string().optional(),
});

export const CreateTestCaseRequestSchema = z.object({
  name: z.string().min(1, 'Name is required').max(200, 'Name too long'),
  tool: z.string().min(1, 'Tool is required').max(100),
  inputs: z.record(z.string(), z.unknown()),
  expected_output: z.record(z.string(), z.unknown()).optional(),
  assertions: z.array(AssertionSchema).max(20, 'Too many assertions').optional(),
  status: z.enum(['active', 'disabled', 'draft']).default('draft'),
  tags: z.array(z.string().max(50)).max(10).optional(),
  description: z.string().max(1000).optional(),
  timeout_ms: z.number().int().min(100).max(300000).optional(),
  retry_count: z.number().int().min(0).max(5).optional(),
});

export const UpdateTestCaseRequestSchema = CreateTestCaseRequestSchema.partial();

// ============================================================================
// Test Run Schemas
// ============================================================================

export const RunTestsRequestSchema = z.object({
  test_case_ids: z.array(z.number().int().positive()).optional(),
  environment: z.string().max(50).optional(),
  notes: z.string().max(500).optional(),
});

// ============================================================================
// PII Schemas
// ============================================================================

export const DetectPIIRequestSchema = z.object({
  text: z.string().min(1, 'Text is required').max(100000, 'Text too long'),
  entity_types: z.array(z.string()).optional(),
  language: z.string().max(10).default('en'),
});

export const RedactPIIRequestSchema = z.object({
  text: z.string().min(1, 'Text is required').max(100000, 'Text too long'),
  entity_types: z.array(z.string()).optional(),
  replacement_strategy: z.enum(['mask', 'hash', 'token', 'remove']).default('mask'),
});

// ============================================================================
// Security Schemas
// ============================================================================

export const Enable2FARequestSchema = z.object({
  method: z.enum(['totp', 'webauthn']),
});

export const Verify2FARequestSchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits').regex(/^\d+$/, 'Code must be numeric'),
});

export const ChangePasswordRequestSchema = z.object({
  current_password: z.string().min(1, 'Current password is required'),
  new_password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
});

export const RegisterPasskeyRequestSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  credential: z.object({
    id: z.string(),
    rawId: z.string(),
    response: z.object({
      clientDataJSON: z.string(),
      attestationObject: z.string(),
    }),
    type: z.literal('public-key'),
  }),
});

// ============================================================================
// Threat Schemas
// ============================================================================

export const ThreatActionRequestSchema = z.object({
  notes: z.string().max(500).optional(),
});

// ============================================================================
// Filter/Query Schemas
// ============================================================================

export const PaginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(20),
});

export const DateRangeQuerySchema = z.object({
  start_date: z.string().datetime().optional(),
  end_date: z.string().datetime().optional(),
});

export const TraceFilterQuerySchema = PaginationQuerySchema.extend({
  tool: z.string().optional(),
  status: z.enum(['pending', 'running', 'success', 'failed', 'blocked']).optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
  min_cost: z.coerce.number().optional(),
  max_cost: z.coerce.number().optional(),
  search: z.string().max(200).optional(),
});

export const ApprovalFilterQuerySchema = PaginationQuerySchema.extend({
  tool: z.string().optional(),
  status: z.enum(['pending', 'approved', 'denied', 'expired']).optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
  search: z.string().max(200).optional(),
});

export const AuditFilterQuerySchema = PaginationQuerySchema.extend({
  event_type: z.string().optional(),
  actor: z.string().optional(),
  tool: z.string().optional(),
  result: z.enum(['success', 'failure']).optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
  search: z.string().max(200).optional(),
});

export const ThreatFilterQuerySchema = PaginationQuerySchema.extend({
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  status: z.enum(['pending', 'acknowledged', 'resolved', 'dismissed']).optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
});

// ============================================================================
// Type Exports
// ============================================================================

export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;
export type LoginRequest = z.infer<typeof LoginRequestSchema>;
export type DecideApprovalRequest = z.infer<typeof DecideApprovalRequestSchema>;
export type CreateDatasetRequest = z.infer<typeof CreateDatasetRequestSchema>;
export type UpdateDatasetRequest = z.infer<typeof UpdateDatasetRequestSchema>;
export type CreateTestCaseRequest = z.infer<typeof CreateTestCaseRequestSchema>;
export type UpdateTestCaseRequest = z.infer<typeof UpdateTestCaseRequestSchema>;
export type RunTestsRequest = z.infer<typeof RunTestsRequestSchema>;
export type DetectPIIRequest = z.infer<typeof DetectPIIRequestSchema>;
export type RedactPIIRequest = z.infer<typeof RedactPIIRequestSchema>;
export type Enable2FARequest = z.infer<typeof Enable2FARequestSchema>;
export type Verify2FARequest = z.infer<typeof Verify2FARequestSchema>;
export type ChangePasswordRequest = z.infer<typeof ChangePasswordRequestSchema>;
export type RegisterPasskeyRequest = z.infer<typeof RegisterPasskeyRequestSchema>;
export type ThreatActionRequest = z.infer<typeof ThreatActionRequestSchema>;
