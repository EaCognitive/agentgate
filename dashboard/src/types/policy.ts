/**
 * Policy-related TypeScript interfaces for dashboard policy API wiring.
 */

export type PolicyEffect = 'allow' | 'deny';

export type PolicyOperator =
  | 'eq'
  | 'neq'
  | 'in'
  | 'not_in'
  | 'contains'
  | 'not_contains'
  | 'matches'
  | 'gt'
  | 'lt'
  | 'gte'
  | 'lte'
  | 'exists'
  | 'not_exists';

export interface PolicyCondition {
  field: string;
  operator: PolicyOperator;
  value: unknown;
}

export interface PolicyRule {
  rule_id: string;
  effect: PolicyEffect;
  description?: string;
  priority?: number;
  conditions: PolicyCondition[];
}

export interface PolicyJsonDocument {
  policy_set_id: string;
  version: string;
  description?: string;
  default_effect: PolicyEffect;
  rules: PolicyRule[];
}

export interface PolicySetRequest {
  policy_json: PolicyJsonDocument;
  origin?: string;
  locked?: boolean;
}

export interface PolicySetResponse {
  policy_set_id: string;
  version: string;
  description: string;
  default_effect: string;
  rule_count: number;
  loaded: boolean;
  db_id?: number | null;
  origin?: string | null;
  locked: boolean;
  is_active?: boolean;
}

export interface PolicyListResponse {
  loaded_policies: string[];
  db_policies: PolicySetResponse[];
}

export interface PolicyPatchRequest {
  locked: boolean;
}

export interface EvaluatePolicyRequest {
  policy_set_id?: string | null;
  request_context: Record<string, unknown>;
}

export interface EvaluatePolicyResponse {
  allowed: boolean;
  effect: string;
  matched_rules: string[];
  reason: string;
  policy_set_id: string;
  evaluation_time_ms: number;
}

export interface PolicyDetailResponse {
  policy_set_id: string;
  version: string;
  description: string;
  default_effect: string;
  rule_count: number;
  locked: boolean;
  is_active: boolean;
  db_id?: number | null;
  origin?: string | null;
  policy_json: PolicyJsonDocument;
}
