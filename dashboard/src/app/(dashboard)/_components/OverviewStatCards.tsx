"use client";

import React from "react";
import Link from "next/link";
import {
  Activity,
  CheckCircle2,
  ShieldAlert,
  Clock,
} from "lucide-react";
import { StatCard } from "@/components/ui/card";

interface OverviewStatCardsProps {
  stats?: {
    total_calls: number;
    success_count: number;
    failed_count: number;
    success_rate: number;
    blocked_count: number;
  };
  pendingCount?: { count: number };
  statsLoading: boolean;
  pendingLoading: boolean;
}

/**
 * Row 1: four stat cards showing key governance metrics.
 */
export default function OverviewStatCards({
  stats,
  pendingCount,
  statsLoading,
  pendingLoading,
}: OverviewStatCardsProps) {
  const dash = "--";

  const success = stats?.success_count ?? 0;
  const failed = stats?.failed_count ?? 0;
  const blocked = stats?.blocked_count ?? 0;
  const resolved = success + failed + blocked;

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <StatCard
        title="Total Requests"
        value={
          statsLoading
            ? dash
            : stats?.total_calls?.toLocaleString() ?? "0"
        }
        icon={<Activity className="h-5 w-5" />}
        description="Last 24 hours"
      />
      <StatCard
        title="Success Rate"
        value={
          statsLoading
            ? dash
            : `${(stats?.success_rate ?? 0).toFixed(1)}%`
        }
        icon={<CheckCircle2 className="h-5 w-5" />}
        description={
          statsLoading
            ? ""
            : `${success.toLocaleString()} of ${resolved.toLocaleString()} resolved`
        }
      />
      <StatCard
        title="Blocked"
        value={
          statsLoading
            ? dash
            : blocked.toLocaleString()
        }
        icon={<ShieldAlert className="h-5 w-5" />}
        description="Denied by policy"
      />
      <Link href="/approvals" className="contents">
        <StatCard
          title="Pending Approvals"
          value={
            pendingLoading
              ? dash
              : pendingCount?.count ?? 0
          }
          icon={<Clock className="h-5 w-5" />}
          description="Requires attention"
        />
      </Link>
    </div>
  );
}
