/**
 * RBAC React Hooks for AgentGate Dashboard
 *
 * Provides hooks for checking permissions in React components
 *
 * @author Erick | Founding Principal AI Architect
 */

'use client';

import { useSession } from 'next-auth/react';
import { useMemo, useCallback } from 'react';
import { UserRole } from '@/types';
import {
  hasPermission,
  canAccessPath,
  hasAnyPermission,
  getRolePermissions,
  getRoleName,
  getRoleBadgeColor,
  type Resource,
  type PermissionAction,
} from '@/lib/rbac';

/**
 * Hook to get the current user's role
 */
export function useUserRole(): UserRole | undefined {
  const { data: session } = useSession();
  return session?.user?.role as UserRole | undefined;
}

/**
 * Hook to check if user has a specific permission
 */
export function useHasPermission(resource: Resource, action: PermissionAction): boolean {
  const role = useUserRole();
  return useMemo(() => hasPermission(role, resource, action), [role, resource, action]);
}

/**
 * Hook to check multiple permissions at once
 */
export function usePermissions(
  checks: Array<{ resource: Resource; action: PermissionAction }>
): boolean[] {
  const role = useUserRole();
  return useMemo(
    () => checks.map(({ resource, action }) => hasPermission(role, resource, action)),
    [role, checks]
  );
}

/**
 * Hook to check if user can access any feature of a resource
 */
export function useCanAccessResource(resource: Resource): boolean {
  const role = useUserRole();
  return useMemo(() => hasAnyPermission(role, resource), [role, resource]);
}

/**
 * Hook to check if user can access a navigation path
 */
export function useCanAccessPath(path: string): boolean {
  const role = useUserRole();
  return useMemo(() => canAccessPath(role, path), [role, path]);
}

/**
 * Comprehensive RBAC hook with all permission utilities
 */
export function useRBAC() {
  const { data: session, status } = useSession();
  const role = session?.user?.role as UserRole | undefined;

  const checkPermission = useCallback(
    (resource: Resource, action: PermissionAction) => hasPermission(role, resource, action),
    [role]
  );

  const checkPath = useCallback((path: string) => canAccessPath(role, path), [role]);

  const checkResource = useCallback(
    (resource: Resource) => hasAnyPermission(role, resource),
    [role]
  );

  const permissions = useMemo(() => {
    if (!role) return {};
    return getRolePermissions(role);
  }, [role]);

  const roleName = useMemo(() => (role ? getRoleName(role) : 'Unknown'), [role]);
  const roleBadgeColor = useMemo(() => (role ? getRoleBadgeColor(role) : ''), [role]);

  return {
    role,
    roleName,
    roleBadgeColor,
    permissions,
    isLoading: status === 'loading',
    isAuthenticated: status === 'authenticated',
    isAdmin: role === UserRole.Admin,
    isSecurityAdmin: role === UserRole.SecurityAdmin,
    isApprover: role === UserRole.Approver || role === UserRole.Operator,
    isAuditor: role === UserRole.Auditor,
    isViewer: role === UserRole.Viewer,
    checkPermission,
    checkPath,
    checkResource,
    // Convenience methods for common checks
    can: {
      viewTraces: checkPermission('traces', 'view'),
      exportTraces: checkPermission('traces', 'export'),
      viewApprovals: checkPermission('approvals', 'view'),
      approveRequests: checkPermission('approvals', 'approve'),
      viewAudit: checkPermission('audit', 'view'),
      exportAudit: checkPermission('audit', 'export'),
      viewCosts: checkPermission('costs', 'view'),
      updateCosts: checkPermission('costs', 'update'),
      viewDatasets: checkPermission('datasets', 'view'),
      createDatasets: checkPermission('datasets', 'create'),
      runTests: checkPermission('test_cases', 'execute'),
      viewPII: checkPermission('pii', 'view'),
      managePII: checkPermission('pii', 'update'),
      viewSecurity: checkPermission('security_settings', 'view'),
      manageSecurity: checkPermission('security_settings', 'update'),
      viewThreats: checkPermission('threats', 'view'),
      manageThreats: checkPermission('threats', 'update'),
      viewUsers: checkPermission('users', 'view'),
      manageUsers: checkPermission('users', 'update'),
      viewSettings: checkPermission('settings', 'view'),
      manageSettings: checkPermission('settings', 'update'),
    },
  };
}

export type { Resource, PermissionAction };
