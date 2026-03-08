"use client";

import React from "react";
import { cn } from "@/lib/utils";
import {
  Inbox,
  Search,
  FileText,
  Database,
  Shield,
  DollarSign,
  Activity
} from "lucide-react";
import { Button } from "./button";

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className
}: EmptyStateProps) {
  return (
    <div className={cn("empty-state animate-fade-in", className)}>
      {icon && (
        <div className="empty-state-icon">
          {icon}
        </div>
      )}
      <h3 className="empty-state-title">{title}</h3>
      {description && (
        <p className="empty-state-description max-w-sm">{description}</p>
      )}
      {action && (
        <Button
          variant="outline"
          size="sm"
          onClick={action.onClick}
          className="mt-4"
        >
          {action.label}
        </Button>
      )}
    </div>
  );
}

// Pre-configured empty states for common scenarios
export function NoTracesState({ onClear }: { onClear?: () => void }) {
  return (
    <EmptyState
      icon={<Activity className="h-12 w-12" />}
      title="No traces found"
      description="No traces match your current filters. Try adjusting your search criteria."
      action={onClear ? { label: "Clear Filters", onClick: onClear } : undefined}
    />
  );
}

export function NoDataState({ title = "No data available" }: { title?: string }) {
  return (
    <EmptyState
      icon={<Inbox className="h-12 w-12" />}
      title={title}
      description="Data will appear here once available."
    />
  );
}

export function NoSearchResultsState({ query }: { query?: string }) {
  return (
    <EmptyState
      icon={<Search className="h-12 w-12" />}
      title="No results found"
      description={query ? `No results found for "${query}". Try different keywords.` : "Try adjusting your search criteria."}
    />
  );
}

export function NoDatasetsState({ onCreate }: { onCreate?: () => void }) {
  return (
    <EmptyState
      icon={<Database className="h-12 w-12" />}
      title="No datasets yet"
      description="Create your first dataset to start organizing test cases."
      action={onCreate ? { label: "Create Dataset", onClick: onCreate } : undefined}
    />
  );
}

export function NoApprovalsState() {
  return (
    <EmptyState
      icon={<FileText className="h-12 w-12" />}
      title="No pending approvals"
      description="All caught up! There are no approvals waiting for your review."
    />
  );
}

export function NoPIIEntriesState() {
  return (
    <EmptyState
      icon={<Shield className="h-12 w-12" />}
      title="No PII entries"
      description="PII entries will appear here when detected in traces."
    />
  );
}

export function NoCostsState() {
  return (
    <EmptyState
      icon={<DollarSign className="h-12 w-12" />}
      title="No cost data"
      description="Cost tracking data will appear here as API calls are made."
    />
  );
}
