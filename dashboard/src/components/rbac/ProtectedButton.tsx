/**
 * Protected Button Component
 *
 * A button that's automatically disabled or hidden based on user permissions
 *
 * @author Erick | Founding Principal AI Architect
 */

'use client';

import React, { forwardRef } from 'react';
import { Button, type ButtonProps } from '@/components/ui/button';
import { useHasPermission, type Resource, type PermissionAction } from '@/hooks/useRBAC';
import { Lock } from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

interface ProtectedButtonProps extends ButtonProps {
  resource: Resource;
  action: PermissionAction;
  hideWhenDisabled?: boolean;
  showLockIcon?: boolean;
  permissionTooltip?: string;
}

/**
 * Button that respects RBAC permissions
 *
 * - By default, shows as disabled with a tooltip when user lacks permission
 * - Can be hidden entirely with hideWhenDisabled
 * - Shows lock icon when disabled due to permissions
 */
export const ProtectedButton = forwardRef<HTMLButtonElement, ProtectedButtonProps>(
  function ProtectedButton(
    {
      resource,
      action,
      hideWhenDisabled = false,
      showLockIcon = true,
      permissionTooltip,
      disabled,
      children,
      className,
      ...props
    },
    ref
  ) {
    const hasPermission = useHasPermission(resource, action);

    // If user doesn't have permission and we should hide the button
    if (!hasPermission && hideWhenDisabled) {
      return null;
    }

    // Button is disabled either by permission or by explicit disabled prop
    const isDisabled = disabled || !hasPermission;

    // If disabled due to permissions, wrap in tooltip
    if (!hasPermission) {
      return (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex">
                <Button
                  ref={ref}
                  disabled={true}
                  className={`${className} cursor-not-allowed opacity-50`}
                  {...props}
                >
                  {showLockIcon && <Lock className="mr-2 h-3 w-3" />}
                  {children}
                </Button>
              </span>
            </TooltipTrigger>
            <TooltipContent>
              <p>
                {permissionTooltip ||
                  `You don't have permission to ${action} ${resource.replace('_', ' ')}`}
              </p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    }

    return (
      <Button ref={ref} disabled={isDisabled} className={className} {...props}>
        {children}
      </Button>
    );
  }
);
