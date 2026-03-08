"use client";

import React from "react";
import {
  useOverview,
  useTimeline,
  useCertificateStats,
  usePendingCount,
  usePendingApprovals,
  usePolicies,
} from "@/lib/hooks";
import OverviewStatCards from "./_components/OverviewStatCards";
import ProtectionChart from "./_components/ProtectionChart";
import PendingApprovalsWidget from "./_components/PendingApprovalsWidget";
import RecentPoliciesWidget from "./_components/RecentPoliciesWidget";
import QuickActionsPanel from "./_components/QuickActionsPanel";
import StatusDistribution from "./_components/StatusDistribution";
import FormalVerification from "./_components/FormalVerification";

/**
 * Overview page -- security-focused governance dashboard.
 *
 * Row 1: Stat cards (requests, success rate, blocked, pending)
 * Row 2: Protection activity chart + pending approvals
 * Row 3: Recent policies + quick actions (trace search, new policy)
 * Row 4: Status distribution donut + formal verification stats
 */
export default function OverviewPage() {
  const {
    data: stats,
    isLoading: statsLoading,
  } = useOverview();
  const {
    data: timeline,
    isLoading: timelineLoading,
  } = useTimeline();
  const {
    data: certStats,
    isLoading: certLoading,
  } = useCertificateStats();
  const {
    data: pendingCount,
    isLoading: pendingLoading,
  } = usePendingCount();
  const {
    data: pendingApprovals,
    isLoading: approvalsLoading,
  } = usePendingApprovals();
  const {
    data: policies,
    isLoading: policiesLoading,
  } = usePolicies();

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Row 1: Stat Cards */}
      <OverviewStatCards
        stats={stats}
        pendingCount={pendingCount}
        statsLoading={statsLoading}
        pendingLoading={pendingLoading}
      />

      {/* Row 2: Protection Activity + Pending Approvals */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ProtectionChart
          timeline={timeline}
          isLoading={timelineLoading}
        />
        <PendingApprovalsWidget
          approvals={
            pendingApprovals
              ? (Array.isArray(pendingApprovals)
                ? pendingApprovals
                : [])
              : undefined
          }
          isLoading={approvalsLoading}
        />
      </div>

      {/* Row 3: Recent Policies + Quick Actions */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RecentPoliciesWidget
          policies={policies}
          isLoading={policiesLoading}
        />
        <QuickActionsPanel />
      </div>

      {/* Row 4: Status Distribution + Formal Verification */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <StatusDistribution stats={stats} />
        <FormalVerification
          certStats={certStats}
          isLoading={certLoading}
        />
      </div>
    </div>
  );
}
