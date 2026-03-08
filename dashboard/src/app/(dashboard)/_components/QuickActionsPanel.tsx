"use client";

import React, { useState } from "react";
import {
  Search,
  Loader2,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useTraceLookup } from "@/lib/hooks";
import type { TraceStatus } from "@/types/index";

/**
 * Format milliseconds to a human-readable duration.
 */
function formatDuration(ms: number): string {
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const STATUS_VARIANT: Record<
  string,
  "success" | "failed" | "blocked" | "pending"
> = {
  success: "success",
  failed: "failed",
  blocked: "blocked",
  pending: "pending",
  running: "pending",
};

/**
 * Trace ID lookup panel with inline result display.
 */
export default function QuickActionsPanel() {
  const [inputId, setInputId] = useState("");
  const [submittedId, setSubmittedId] = useState("");
  const {
    data: trace,
    isLoading,
    isError,
  } = useTraceLookup(submittedId);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = inputId.trim();
    if (trimmed) {
      setSubmittedId(trimmed);
    }
  }

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="flex items-start gap-2">
          <Search
            className="mt-0.5 h-4 w-4 text-muted-foreground"
          />
          <div>
            <CardTitle>Trace Lookup</CardTitle>
            <CardDescription>
              Search execution traces by ID
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1 space-y-4">
        <form
          onSubmit={handleSubmit}
          className="flex gap-2"
        >
          <input
            type="text"
            value={inputId}
            onChange={(e) => setInputId(e.target.value)}
            placeholder="Enter trace ID..."
            className={
              "flex-1 rounded-md border border-border"
              + " bg-card px-3 py-2 text-sm"
              + " placeholder:text-muted-foreground"
              + " focus:outline-none focus:ring-2"
              + " focus:ring-primary/40"
            }
          />
          <Button
            type="submit"
            size="sm"
            disabled={!inputId.trim()}
          >
            <Search className="mr-1.5 h-3.5 w-3.5" />
            Lookup
          </Button>
        </form>

        {/* Trace result */}
        {submittedId && isLoading && (
          <div className="flex items-center justify-center py-4 text-muted-foreground">
            <Loader2
              className="mr-2 h-4 w-4 animate-spin"
            />
            <span className="text-sm">
              Searching...
            </span>
          </div>
        )}
        {submittedId && isError && (
          <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            Trace not found
          </div>
        )}
        {submittedId && trace && (
          <div className="space-y-1.5 rounded-md border border-border p-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs truncate">
                {trace.trace_id}
              </span>
              <Badge
                variant={
                  STATUS_VARIANT[
                    trace.status as TraceStatus
                  ] ?? "default"
                }
              >
                {trace.status}
              </Badge>
            </div>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>Tool: {trace.tool}</span>
              <span>
                {formatDuration(trace.duration_ms)}
              </span>
            </div>
          </div>
        )}

        {/* Hint when no search performed */}
        {!submittedId && (
          <p className="text-xs text-muted-foreground">
            Paste a trace ID above to inspect execution
            details, status, and duration.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
