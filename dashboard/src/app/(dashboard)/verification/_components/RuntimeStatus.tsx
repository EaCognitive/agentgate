"use client";

import { useRuntimeStatus } from "@/lib/hooks";
import { cn } from "@/lib/utils";
import { Activity, AlertTriangle, Loader2 } from "lucide-react";

/**
 * Compact banner showing Z3 solver runtime status.
 */
export default function RuntimeStatus() {
  const { data, isLoading, isError } = useRuntimeStatus();

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-border bg-card/70 px-4 py-2.5 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading solver status...
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-warning-200 bg-warning-50 px-4 py-2.5 text-sm text-warning">
        <AlertTriangle className="h-4 w-4" />
        Unable to reach runtime status endpoint
      </div>
    );
  }

  const z3Ok = data.z3_available && data.z3_healthy;
  const modeLabel = data.configured_mode.toUpperCase();

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-6 gap-y-1 rounded-xl border px-4 py-2.5 text-sm",
        z3Ok
          ? "border-success-200 bg-success-50"
          : "border-warning-200 bg-warning-50",
      )}
    >
      <div className="flex items-center gap-2">
        <Activity className="h-4 w-4 text-muted-foreground" />
        <span className="font-medium text-foreground">
          Z3 Solver
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        <span
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            z3Ok ? "bg-success" : "bg-warning",
          )}
        />
        <span className="text-muted-foreground">
          {z3Ok ? "Available" : "Unavailable"}
        </span>
      </div>

      <div className="text-muted-foreground">
        Mode:{" "}
        <span className="font-mono font-medium text-foreground">
          {modeLabel}
        </span>
      </div>

      {data.z3_check_result && (
        <div className="text-muted-foreground">
          Check:{" "}
          <span className="font-mono text-foreground">
            {data.z3_check_result}
          </span>
        </div>
      )}

      {data.z3_error && (
        <div className="text-warning">
          {data.z3_error}
        </div>
      )}
    </div>
  );
}
