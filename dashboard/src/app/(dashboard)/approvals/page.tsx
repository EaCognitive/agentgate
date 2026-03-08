"use client";

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  Loader2,
  ClipboardCheck,
  Filter,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  useApprovals,
  usePendingApprovals,
  useDecideApproval,
} from "@/lib/hooks";
import { formatDistanceToNow } from "date-fns";
import type { Approval, ApprovalStatus } from "@/types/index";

type FilterStatus = "all" | "pending" | "approved" | "denied";

function StatusBadge({ status }: { status: ApprovalStatus }) {
  switch (status) {
    case "pending":
      return (
        <Badge className="bg-warning-100 text-warning">
          <Clock className="mr-1 h-3 w-3" />
          Pending
        </Badge>
      );
    case "approved":
      return (
        <Badge className="bg-success-100 text-success">
          <CheckCircle2 className="mr-1 h-3 w-3" />
          Approved
        </Badge>
      );
    case "denied":
      return (
        <Badge className="bg-danger-100 text-danger">
          <XCircle className="mr-1 h-3 w-3" />
          Denied
        </Badge>
      );
    case "expired":
      return (
        <Badge className="bg-gray-500/20 text-gray-600 dark:text-gray-400">
          <Clock className="mr-1 h-3 w-3" />
          Expired
        </Badge>
      );
    default:
      return <Badge>{status}</Badge>;
  }
}

function DecisionModal({
  approval,
  onClose,
}: {
  approval: Approval;
  onClose: () => void;
}) {
  const [reason, setReason] = useState("");
  const decideApproval = useDecideApproval();

  const handleDecision = (approved: boolean) => {
    decideApproval.mutate(
      { id: approval.approval_id, approved, reason },
      { onSuccess: () => onClose() }
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="mx-4 w-full max-w-lg rounded-xl border border-border bg-card p-6 shadow-2xl">
        <h2 className="text-lg font-semibold text-foreground">
          Review Approval Request
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Tool: <span className="font-medium text-foreground">
            {approval.tool}
          </span>
        </p>

        <div className="mt-4 rounded-lg bg-muted/30 p-4">
          <p className="text-xs font-medium text-muted-foreground mb-2">
            Request Inputs
          </p>
          <pre className="overflow-x-auto text-xs text-foreground">
            {JSON.stringify(approval.inputs, null, 2)}
          </pre>
        </div>

        <div className="mt-4">
          <label className="block text-sm font-medium mb-1">
            Reason (optional)
          </label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Add a reason for your decision..."
            className="w-full rounded-lg border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary resize-none h-20"
          />
        </div>

        <div className="mt-6 flex gap-3">
          <Button
            variant="ghost"
            className="flex-1"
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button
            variant="danger"
            className="flex-1"
            onClick={() => handleDecision(false)}
            disabled={decideApproval.isPending}
          >
            {decideApproval.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <XCircle className="mr-2 h-4 w-4" />
            )}
            Deny
          </Button>
          <Button
            className="flex-1"
            onClick={() => handleDecision(true)}
            disabled={decideApproval.isPending}
          >
            {decideApproval.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <CheckCircle2 className="mr-2 h-4 w-4" />
            )}
            Approve
          </Button>
        </div>
      </div>
    </div>
  );
}

export default function ApprovalsPage() {
  const [filter, setFilter] = useState<FilterStatus>("all");
  const [reviewingApproval, setReviewingApproval] =
    useState<Approval | null>(null);
  const queryClient = useQueryClient();

  const statusFilter =
    filter === "all"
      ? undefined
      : (filter as ApprovalStatus);

  const { data: approvalsData, isLoading } = useApprovals({
    status: statusFilter,
    page_size: 50,
  });

  const { data: pendingApprovals } = usePendingApprovals();
  const pendingCount = pendingApprovals?.length ?? 0;

  const approvals: Approval[] = Array.isArray(approvalsData)
    ? approvalsData
    : approvalsData?.items ?? [];

  const filters: { label: string; value: FilterStatus }[] = [
    { label: "All", value: "all" },
    { label: `Pending (${pendingCount})`, value: "pending" },
    { label: "Approved", value: "approved" },
    { label: "Denied", value: "denied" },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Approvals</h1>
          <p className="text-muted-foreground">
            Review and manage tool execution approval requests
          </p>
        </div>
        {pendingCount > 0 && (
          <div className="flex items-center gap-2 rounded-lg bg-warning-50 px-3 py-2 text-sm text-warning">
            <AlertTriangle className="h-4 w-4" />
            {pendingCount} pending
          </div>
        )}
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-border pb-2">
        {filters.map((f) => (
          <Button
            key={f.value}
            variant={
              filter === f.value ? "primary" : "ghost"
            }
            size="sm"
            onClick={() => setFilter(f.value)}
          >
            {f.value === "all" && (
              <Filter className="mr-2 h-4 w-4" />
            )}
            {f.label}
          </Button>
        ))}
      </div>

      {/* Approvals Table */}
      <Card>
        <CardHeader>
          <CardTitle>Approval Requests</CardTitle>
          <CardDescription>
            {filter === "all"
              ? "All approval requests"
              : `Showing ${filter} requests`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex h-64 items-center justify-center text-muted-foreground">
              <Loader2 className="mr-2 h-5 w-5 animate-spin" />
              Loading approvals...
            </div>
          ) : approvals.length > 0 ? (
            <div className="overflow-x-auto">
              <Table className="min-w-[600px]">
                <TableHeader>
                  <TableRow>
                    <TableHead>Tool</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Decided By</TableHead>
                    <TableHead>Decided At</TableHead>
                    <TableHead className="text-right">
                      Actions
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {approvals.map((approval) => (
                    <TableRow
                      key={
                        approval.id || approval.approval_id
                      }
                    >
                      <TableCell className="font-medium">
                        {approval.tool}
                      </TableCell>
                      <TableCell>
                        <StatusBadge
                          status={approval.status}
                        />
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {formatDistanceToNow(
                          new Date(approval.created_at),
                          { addSuffix: true }
                        )}
                      </TableCell>
                      <TableCell className="text-sm">
                        {approval.decided_by || "\u2014"}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {approval.decided_at
                          ? formatDistanceToNow(
                              new Date(approval.decided_at),
                              { addSuffix: true }
                            )
                          : "\u2014"}
                      </TableCell>
                      <TableCell className="text-right">
                        {approval.status === "pending" ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              setReviewingApproval(approval)
                            }
                          >
                            Review
                          </Button>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            Resolved
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="flex h-64 flex-col items-center justify-center text-center text-muted-foreground">
              <ClipboardCheck className="mb-2 h-12 w-12 opacity-30" />
              <p>No approval requests</p>
              <p className="text-xs">
                {filter === "pending"
                  ? "No pending approvals to review"
                  : filter === "approved"
                  ? "No approved requests yet"
                  : filter === "denied"
                  ? "No denied requests yet"
                  : "Approval requests will appear here"}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Decision Modal */}
      {reviewingApproval && (
        <DecisionModal
          approval={reviewingApproval}
          onClose={() => {
            setReviewingApproval(null);
            queryClient.invalidateQueries({
              queryKey: ["approvals"],
            });
          }}
        />
      )}
    </div>
  );
}
