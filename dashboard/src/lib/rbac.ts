/**
 * RBAC (Role-Based Access Control) utilities for AgentGate Dashboard
 *
 * Defines permissions for each role and provides utilities for checking access
 *
 * @author Erick | Founding Principal AI Architect
 */

import { UserRole } from '@/types';

function normalizeRole(role: UserRole | undefined): UserRole | undefined {
  if (!role) return role;
  if (role === UserRole.Operator) return UserRole.Approver;
  return role;
}

/**
 * Permission actions that can be performed on resources
 */
export type PermissionAction = 'view' | 'create' | 'update' | 'delete' | 'approve' | 'export' | 'execute';

/**
 * Resource types in the dashboard
 */
export type Resource =
  | 'traces'
  | 'approvals'
  | 'audit'
  | 'costs'
  | 'datasets'
  | 'test_cases'
  | 'test_runs'
  | 'pii'
  | 'security_settings'
  | 'threats'
  | 'users'
  | 'settings';

/**
 * Permission matrix defining what each role can do
 */
const PERMISSION_MATRIX: Record<UserRole, Record<Resource, PermissionAction[]>> = {
  [UserRole.Admin]: {
    traces: ['view', 'create', 'update', 'delete', 'export'],
    approvals: ['view', 'create', 'update', 'delete', 'approve'],
    audit: ['view', 'export'],
    costs: ['view', 'update', 'export'],
    datasets: ['view', 'create', 'update', 'delete', 'export'],
    test_cases: ['view', 'create', 'update', 'delete', 'execute'],
    test_runs: ['view', 'create', 'delete'],
    pii: ['view', 'create', 'update', 'delete', 'export'],
    security_settings: ['view', 'update'],
    threats: ['view', 'update', 'delete'],
    users: ['view', 'create', 'update', 'delete'],
    settings: ['view', 'update'],
  },
  [UserRole.SecurityAdmin]: {
    traces: ['view', 'export'],
    approvals: ['view', 'approve'],
    audit: ['view', 'export'],
    costs: ['view', 'export'],
    datasets: ['view', 'create', 'update', 'delete', 'export'],
    test_cases: ['view', 'create', 'update', 'delete', 'execute'],
    test_runs: ['view', 'create', 'delete'],
    pii: ['view', 'create', 'update', 'delete', 'export'],
    security_settings: ['view', 'update'],
    threats: ['view', 'update', 'delete'],
    users: ['view', 'update'],
    settings: ['view', 'update'],
  },
  [UserRole.Approver]: {
    traces: ['view', 'export'],
    approvals: ['view', 'approve'],
    audit: ['view'],
    costs: ['view'],
    datasets: ['view', 'create', 'update', 'export'],
    test_cases: ['view', 'create', 'update', 'execute'],
    test_runs: ['view', 'create'],
    pii: ['view', 'create', 'update'],
    security_settings: ['view', 'update'],
    threats: ['view', 'update'],
    users: ['view'],
    settings: ['view'],
  },
  [UserRole.AgentOperator]: {
    traces: ['view', 'export'],
    approvals: ['view', 'approve'],
    audit: ['view'],
    costs: ['view'],
    datasets: ['view', 'create', 'update', 'export'],
    test_cases: ['view', 'create', 'update', 'execute'],
    test_runs: ['view', 'create'],
    pii: ['view', 'create', 'update'],
    security_settings: ['view', 'update'],
    threats: ['view', 'update'],
    users: ['view'],
    settings: ['view'],
  },
  [UserRole.ServiceAgent]: {
    traces: ['view'],
    approvals: ['view'],
    audit: [],
    costs: ['view'],
    datasets: ['view', 'create', 'update'],
    test_cases: ['view', 'create', 'update', 'execute'],
    test_runs: ['view', 'create'],
    pii: [],
    security_settings: ['view'],
    threats: ['view'],
    users: [],
    settings: [],
  },
  [UserRole.Auditor]: {
    traces: ['view', 'export'],
    approvals: ['view'],
    audit: ['view', 'export'],
    costs: ['view', 'export'],
    datasets: ['view', 'export'],
    test_cases: ['view'],
    test_runs: ['view'],
    pii: ['view', 'export'],
    security_settings: ['view'],
    threats: ['view'],
    users: ['view'],
    settings: ['view'],
  },
  [UserRole.Developer]: {
    traces: ['view', 'export'],
    approvals: ['view'],
    audit: ['view'],
    costs: ['view'],
    datasets: ['view', 'create', 'update', 'delete', 'export'],
    test_cases: ['view', 'create', 'update', 'delete', 'execute'],
    test_runs: ['view', 'create'],
    pii: ['view'],
    security_settings: ['view'],
    threats: ['view'],
    users: ['view'],
    settings: ['view'],
  },
  [UserRole.Viewer]: {
    traces: ['view'],
    approvals: ['view'],
    audit: [],
    costs: ['view'],
    datasets: ['view'],
    test_cases: ['view'],
    test_runs: ['view'],
    pii: [],
    security_settings: [],
    threats: ['view'],
    users: [],
    settings: [],
  },
  [UserRole.Operator]: {
    traces: ['view', 'export'],
    approvals: ['view', 'approve'],
    audit: ['view'],
    costs: ['view'],
    datasets: ['view', 'create', 'update', 'export'],
    test_cases: ['view', 'create', 'update', 'execute'],
    test_runs: ['view', 'create'],
    pii: ['view', 'create', 'update'],
    security_settings: ['view', 'update'],
    threats: ['view', 'update'],
    users: ['view'],
    settings: ['view'],
  },
};

/**
 * Navigation items that are visible to each role
 */
export const NAVIGATION_ACCESS: Record<string, UserRole[]> = {
  '/': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/traces': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/approvals': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/costs': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/audit': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.Auditor, UserRole.Developer],
  '/datasets': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/policies': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Developer],
  '/pii': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor],
  '/security/settings': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/security/threats': [UserRole.Admin, UserRole.SecurityAdmin, UserRole.Approver, UserRole.AgentOperator, UserRole.Auditor, UserRole.Developer, UserRole.Viewer],
  '/users': [UserRole.Admin],
  '/settings': [UserRole.Admin],
};

/**
 * Check if a role has permission to perform an action on a resource
 */
export function hasPermission(
  role: UserRole | undefined,
  resource: Resource,
  action: PermissionAction
): boolean {
  const normalizedRole = normalizeRole(role);
  if (!normalizedRole) return false;
  const permissions = PERMISSION_MATRIX[normalizedRole]?.[resource] || [];
  return permissions.includes(action);
}

/**
 * Check if a role can access a specific navigation path
 */
export function canAccessPath(role: UserRole | undefined, path: string): boolean {
  const normalizedRole = normalizeRole(role);
  if (!normalizedRole) return false;
  const allowedRoles = NAVIGATION_ACCESS[path];
  if (!allowedRoles) return true; // Allow access to unlisted paths by default
  return allowedRoles.includes(normalizedRole);
}

/**
 * Get all permissions for a role
 */
export function getRolePermissions(role: UserRole): Record<Resource, PermissionAction[]> {
  return PERMISSION_MATRIX[normalizeRole(role) ?? role] || {};
}

/**
 * Check if role has any permission on a resource
 */
export function hasAnyPermission(role: UserRole | undefined, resource: Resource): boolean {
  const normalizedRole = normalizeRole(role);
  if (!normalizedRole) return false;
  const permissions = PERMISSION_MATRIX[normalizedRole]?.[resource] || [];
  return permissions.length > 0;
}

/**
 * Get human-readable role name
 */
export function getRoleName(role: UserRole): string {
  const names: Record<UserRole, string> = {
    [UserRole.Admin]: 'Administrator',
    [UserRole.SecurityAdmin]: 'Security Administrator',
    [UserRole.Approver]: 'Approver',
    [UserRole.Auditor]: 'Auditor',
    [UserRole.Developer]: 'Developer',
    [UserRole.AgentOperator]: 'Agent Operator',
    [UserRole.ServiceAgent]: 'Service Agent',
    [UserRole.Viewer]: 'Viewer',
    [UserRole.Operator]: 'Approver',
  };
  const normalizedRole = normalizeRole(role) ?? role;
  return names[normalizedRole] || normalizedRole;
}

/**
 * Get role badge color for UI display
 */
export function getRoleBadgeColor(role: UserRole): string {
  const colors: Record<UserRole, string> = {
    [UserRole.Admin]: 'bg-red-500/20 text-red-400',
    [UserRole.SecurityAdmin]: 'bg-orange-500/20 text-orange-400',
    [UserRole.Approver]: 'bg-blue-500/20 text-blue-400',
    [UserRole.Auditor]: 'bg-purple-500/20 text-purple-400',
    [UserRole.Developer]: 'bg-emerald-500/20 text-emerald-400',
    [UserRole.AgentOperator]: 'bg-cyan-500/20 text-cyan-400',
    [UserRole.ServiceAgent]: 'bg-slate-500/20 text-slate-300',
    [UserRole.Viewer]: 'bg-gray-500/20 text-gray-400',
    [UserRole.Operator]: 'bg-blue-500/20 text-blue-400',
  };
  return colors[normalizeRole(role) ?? role] || 'bg-gray-500/20 text-gray-400';
}

/**
 * Resource descriptions for UI display
 */
export const RESOURCE_DESCRIPTIONS: Record<Resource, string> = {
  traces: 'Tool execution traces and logs',
  approvals: 'Tool execution approval requests',
  audit: 'Security audit logs',
  costs: 'Cost analytics and budgets',
  datasets: 'Test datasets',
  test_cases: 'Test case definitions',
  test_runs: 'Test execution runs',
  pii: 'PII vault and detection settings',
  security_settings: 'Security configuration (MFA, sessions)',
  threats: 'Threat detection and alerts',
  users: 'User management',
  settings: 'System settings',
};
