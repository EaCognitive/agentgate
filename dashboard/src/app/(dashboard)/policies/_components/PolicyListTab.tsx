import React from "react";
import {
  Plus,
  Lock,
  Unlock,
  Upload,
  Loader2,
  CheckCircle,
  X,
  Trash2,
  FileText,
  Power,
  PowerOff,
  Eye,
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
import type { PolicyListResponse } from "@/types/policy";

export interface PolicyListTabProps {
  dbPolicies: PolicyListResponse["db_policies"];
  loadedIds: Set<string>;
  isLoading: boolean;
  deleteConfirm: string | null;
  setDeleteConfirm: (v: string | null) => void;
  onView: (policySetId: string) => void;
  onLoad: (id: string) => void;
  onLock: (id: string, locked: boolean) => void;
  onDelete: (id: string) => void;
  onActivate: (dbId: number) => void;
  onDeactivate: (dbId: number) => void;
  actionPending: boolean;
  activateError: string | null;
  deactivateError: string | null;
  onCreateClick: () => void;
}

export default function PolicyListTab({
  dbPolicies,
  loadedIds,
  isLoading,
  deleteConfirm,
  setDeleteConfirm,
  onView,
  onLoad,
  onLock,
  onDelete,
  onActivate,
  onDeactivate,
  actionPending,
  activateError,
  deactivateError,
  onCreateClick,
}: PolicyListTabProps) {
  const mutationError = activateError || deactivateError;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Policy Sets</CardTitle>
        <CardDescription>
          Manage your declarative policy rule sets
        </CardDescription>
      </CardHeader>
      <CardContent>
        {mutationError && (
          <div className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {mutationError}
          </div>
        )}
        {isLoading ? (
          <div className="flex h-64 items-center justify-center text-muted-foreground">
            <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            Loading policies...
          </div>
        ) : dbPolicies.length > 0 ? (
          <div className="overflow-x-auto">
            <Table className="min-w-[600px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Policy ID</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Rules</TableHead>
                  <TableHead>Default</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dbPolicies.map((policy) => {
                  const loaded = loadedIds.has(
                    policy.policy_set_id,
                  );
                  return (
                    <TableRow key={policy.policy_set_id}>
                      <TableCell className="font-mono text-sm font-medium">
                        {policy.policy_set_id}
                      </TableCell>
                      <TableCell className="text-sm">
                        {policy.version}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {policy.rule_count} rules
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={
                            policy.default_effect === "allow"
                              ? "bg-success-100 text-success"
                              : "bg-danger-100 text-danger"
                          }
                        >
                          {policy.default_effect}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1.5">
                          {policy.is_active && (
                            <Badge className="bg-info-100 text-info">
                              <Power className="mr-1 h-3 w-3" />
                              Active
                            </Badge>
                          )}
                          {loaded && (
                            <Badge className="bg-success-100 text-success">
                              <CheckCircle className="mr-1 h-3 w-3" />
                              Loaded
                            </Badge>
                          )}
                          {policy.locked && (
                            <Badge className="bg-warning-100 text-warning">
                              <Lock className="mr-1 h-3 w-3" />
                              Locked
                            </Badge>
                          )}
                          {!loaded && !policy.locked && !policy.is_active && (
                            <Badge className="bg-gray-500/20 text-gray-600 dark:text-gray-400">
                              Inactive
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              onView(policy.policy_set_id)
                            }
                            title="View policy details"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {policy.db_id != null && !policy.is_active && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                onActivate(policy.db_id!)
                              }
                              disabled={actionPending}
                              title="Activate policy"
                              className="text-success hover:text-success"
                            >
                              <Power className="h-4 w-4" />
                            </Button>
                          )}
                          {policy.db_id != null && policy.is_active && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                onDeactivate(policy.db_id!)
                              }
                              disabled={actionPending}
                              title="Deactivate policy"
                              className="text-danger hover:text-danger"
                            >
                              <PowerOff className="h-4 w-4" />
                            </Button>
                          )}
                          {!loaded && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                onLoad(policy.policy_set_id)
                              }
                              disabled={actionPending}
                              title="Load into runtime"
                            >
                              <Upload className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              onLock(
                                policy.policy_set_id,
                                !policy.locked,
                              )
                            }
                            disabled={actionPending}
                            title={
                              policy.locked ? "Unlock" : "Lock"
                            }
                          >
                            {policy.locked ? (
                              <Unlock className="h-4 w-4" />
                            ) : (
                              <Lock className="h-4 w-4" />
                            )}
                          </Button>
                          {deleteConfirm ===
                          policy.policy_set_id ? (
                            <div className="flex items-center gap-1">
                              <Button
                                variant="danger"
                                size="sm"
                                onClick={() =>
                                  onDelete(
                                    policy.policy_set_id,
                                  )
                                }
                                disabled={actionPending}
                              >
                                {actionPending ? (
                                  <Loader2 className="h-4 w-4 animate-spin" />
                                ) : (
                                  "Confirm"
                                )}
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() =>
                                  setDeleteConfirm(null)
                                }
                              >
                                <X className="h-4 w-4" />
                              </Button>
                            </div>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                setDeleteConfirm(
                                  policy.policy_set_id,
                                )
                              }
                              title="Delete"
                              className="text-destructive hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="flex h-64 flex-col items-center justify-center text-center text-muted-foreground">
            <FileText className="mb-2 h-12 w-12 opacity-30" />
            <p>No policies configured</p>
            <p className="text-xs">
              Create your first policy to get started
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-4"
              onClick={onCreateClick}
            >
              <Plus className="mr-2 h-4 w-4" />
              Create Policy
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
