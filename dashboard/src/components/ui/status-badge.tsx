"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { CheckCircle2, XCircle, AlertTriangle, Clock, Loader2 } from "lucide-react";

export type StatusType = "success" | "failed" | "blocked" | "pending" | "running";

interface StatusBadgeProps {
  status: string;
  showIcon?: boolean;
  size?: "sm" | "md";
  className?: string;
}

const statusConfig: Record<StatusType, {
  className: string;
  icon: React.ReactNode;
  label: string;
}> = {
  success: {
    className: "status-badge-success",
    icon: <CheckCircle2 className="h-3 w-3" />,
    label: "Success",
  },
  failed: {
    className: "status-badge-failed",
    icon: <XCircle className="h-3 w-3" />,
    label: "Failed",
  },
  blocked: {
    className: "status-badge-blocked",
    icon: <AlertTriangle className="h-3 w-3" />,
    label: "Blocked",
  },
  pending: {
    className: "status-badge-pending",
    icon: <Clock className="h-3 w-3" />,
    label: "Pending",
  },
  running: {
    className: "status-badge-pending",
    icon: <Loader2 className="h-3 w-3 animate-spin" />,
    label: "Running",
  },
};

export function StatusBadge({ status, showIcon = true, size = "md", className }: StatusBadgeProps) {
  const normalizedStatus = status.toLowerCase() as StatusType;
  const config = statusConfig[normalizedStatus] || statusConfig.pending;

  return (
    <span
      className={cn(
        "status-badge",
        config.className,
        size === "sm" && "px-2 py-0.5 text-[10px]",
        className
      )}
    >
      {showIcon && config.icon}
      {config.label}
    </span>
  );
}

// Convenience exports for direct usage
export function SuccessBadge({ className }: { className?: string }) {
  return <StatusBadge status="success" className={className} />;
}

export function FailedBadge({ className }: { className?: string }) {
  return <StatusBadge status="failed" className={className} />;
}

export function BlockedBadge({ className }: { className?: string }) {
  return <StatusBadge status="blocked" className={className} />;
}

export function PendingBadge({ className }: { className?: string }) {
  return <StatusBadge status="pending" className={className} />;
}
