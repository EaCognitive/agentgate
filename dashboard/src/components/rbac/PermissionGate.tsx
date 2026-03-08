/**
 * RBAC Permission Gate Component
 *
 * Conditionally renders children based on user permissions
 *
 * @author Erick | Founding Principal AI Architect
 */

'use client';

import React, { ReactNode } from 'react';
import { useHasPermission, useCanAccessResource, useUserRole, type Resource, type PermissionAction } from '@/hooks/useRBAC';
import { Lock } from 'lucide-react';
import { UserRole } from '@/types';

interface PermissionGateProps {
  children: ReactNode;
  resource: Resource;
  action?: PermissionAction;
  fallback?: ReactNode;
  showAccessDenied?: boolean;
}

/**
 * Gate component that only renders children if user has the required permission
 */
export function PermissionGate({
  children,
  resource,
  action,
  fallback,
  showAccessDenied = false,
}: PermissionGateProps) {
  // Always call hooks at the top level
  const hasPermission = useHasPermission(resource, action || 'read' as PermissionAction);
  const canAccessResource = useCanAccessResource(resource);

  // Determine access based on whether action is specified
  const hasAccess = action ? hasPermission : canAccessResource;

  if (hasAccess) {
    return <>{children}</>;
  }

  if (fallback) {
    return <>{fallback}</>;
  }

  if (showAccessDenied) {
    return <AccessDeniedMessage resource={resource} action={action} />;
  }

  return null;
}

/**
 * Access denied message component
 */
function AccessDeniedMessage({
  resource,
  action,
}: {
  resource: Resource;
  action?: PermissionAction;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-muted/20 p-8 text-center">
      <Lock className="mb-4 h-12 w-12 text-muted-foreground/50" />
      <h3 className="mb-2 font-semibold">Access Restricted</h3>
      <p className="text-sm text-muted-foreground">
        You don&apos;t have permission to {action || 'access'} {resource.replace('_', ' ')}.
      </p>
      <p className="mt-2 text-xs text-muted-foreground">
        Contact your administrator if you need access.
      </p>
    </div>
  );
}

/**
 * Higher-order component for permission-based rendering
 */
export function withPermission<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  resource: Resource,
  action: PermissionAction
) {
  return function WithPermissionComponent(props: P) {
    return (
      <PermissionGate resource={resource} action={action} showAccessDenied>
        <WrappedComponent {...props} />
      </PermissionGate>
    );
  };
}

/**
 * Component that shows different content based on user role
 */
interface RoleBasedContentProps {
  admin?: ReactNode;
  securityAdmin?: ReactNode;
  approver?: ReactNode;
  auditor?: ReactNode;
  viewer?: ReactNode;
  default?: ReactNode;
}

export function RoleBasedContent({
  admin,
  securityAdmin,
  approver,
  auditor,
  viewer,
  default: defaultContent,
}: RoleBasedContentProps) {
  const role = useUserRole();

  switch (role) {
    case UserRole.Admin:
      return <>{admin ?? securityAdmin ?? approver ?? auditor ?? viewer ?? defaultContent}</>;
    case UserRole.SecurityAdmin:
      return <>{securityAdmin ?? approver ?? auditor ?? viewer ?? defaultContent}</>;
    case UserRole.Approver:
    case UserRole.Operator:
      return <>{approver ?? auditor ?? viewer ?? defaultContent}</>;
    case UserRole.Auditor:
      return <>{auditor ?? viewer ?? defaultContent}</>;
    case UserRole.Viewer:
      return <>{viewer ?? defaultContent}</>;
    default:
      return <>{defaultContent}</>;
  }
}
