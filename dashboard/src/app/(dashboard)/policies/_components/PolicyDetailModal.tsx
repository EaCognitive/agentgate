"use client";

import React from "react";
import { X, Shield, ShieldOff, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { PolicyDetailResponse } from "@/types/policy";

interface PolicyDetailModalProps {
  policy: PolicyDetailResponse | null;
  isLoading?: boolean;
  error?: string | null;
  onClose: () => void;
}

/**
 * Slide-over modal displaying full policy detail
 * including rules and their conditions.
 */
export default function PolicyDetailModal({
  policy,
  isLoading,
  error,
  onClose,
}: PolicyDetailModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="relative z-10 flex h-full w-full max-w-2xl flex-col bg-background shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-foreground">
              {policy?.policy_set_id || "Policy Details"}
            </h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {policy?.description || (isLoading ? "Loading..." : "No description")}
            </p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>

        {isLoading && (
          <div className="flex flex-1 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}

        {error && (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 px-6">
            <p className="text-sm text-destructive">
              {error}
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={onClose}
            >
              Close
            </Button>
          </div>
        )}

        {policy && !isLoading && !error && (
          <PolicyDetailContent policy={policy} />
        )}
      </div>
    </div>
  );
}

function PolicyDetailContent({
  policy,
}: {
  policy: PolicyDetailResponse;
}) {
  const rules = policy.policy_json.rules || [];

  return (
    <>
      {/* Metadata */}
      <div className="flex flex-wrap gap-2 border-b border-border px-6 py-3">
        <Badge variant="outline">
          v{policy.version}
        </Badge>
        <Badge
          className={
            policy.default_effect === "allow"
              ? "bg-success-100 text-success"
              : "bg-danger-100 text-danger"
          }
        >
          Default: {policy.default_effect}
        </Badge>
        {policy.is_active && (
          <Badge className="bg-info-100 text-info">
            Active
          </Badge>
        )}
        {policy.locked && (
          <Badge className="bg-warning-100 text-warning">
            Locked
          </Badge>
        )}
        {policy.origin && (
          <Badge variant="outline">
            Origin: {policy.origin}
          </Badge>
        )}
      </div>

        {/* Rules */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          <h3 className="mb-3 text-sm font-semibold text-foreground">
            Rules ({rules.length})
          </h3>

          {rules.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No rules defined.
            </p>
          ) : (
            <div className="space-y-3">
              {rules.map((rule) => (
                <div
                  key={rule.rule_id}
                  className="rounded-lg border border-border bg-card/80 p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {rule.effect === "allow" ? (
                        <Shield className="h-4 w-4 text-success" />
                      ) : (
                        <ShieldOff className="h-4 w-4 text-danger" />
                      )}
                      <span className="font-mono text-sm font-medium text-foreground">
                        {rule.rule_id}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        className={
                          rule.effect === "allow"
                            ? "bg-success-100 text-success"
                            : "bg-danger-100 text-danger"
                        }
                      >
                        {rule.effect}
                      </Badge>
                      {rule.priority != null && (
                        <Badge variant="outline">
                          Priority: {rule.priority}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {rule.description && (
                    <p className="mt-2 text-xs text-muted-foreground">
                      {rule.description}
                    </p>
                  )}

                  {/* Conditions */}
                  {rule.conditions &&
                    rule.conditions.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/60">
                        Conditions
                      </p>
                      {rule.conditions.map((cond, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-2 rounded bg-muted/50 px-3 py-1.5 font-mono text-xs"
                        >
                          <span className="text-foreground">
                            {cond.field}
                          </span>
                          <span className="text-primary">
                            {cond.operator}
                          </span>
                          <span className="text-muted-foreground">
                            {typeof cond.value === "object"
                              ? JSON.stringify(cond.value)
                              : String(cond.value)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </>
  );
}
