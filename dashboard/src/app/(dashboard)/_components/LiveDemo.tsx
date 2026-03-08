"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import {
  Play,
  Loader2,
  CheckCircle,
  XCircle,
  AlertCircle,
  ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import Link from "next/link";

interface PredicateOutcome {
  predicate: string;
  value: boolean;
  witness?: Record<string, unknown>;
}

interface DemoResult {
  success: boolean;
  certificate: {
    decision_id: string;
    result: string;
    proof_type: string;
    proof_payload: {
      constructive_trace?: PredicateOutcome[];
      trace?: PredicateOutcome[];
    };
    signature: string | null;
  };
}

const DEMO_PAYLOAD = {
  principal: "demo-agent",
  action: "read",
  resource: "database/users",
};

/**
 * Interactive live demo card that runs a real
 * admissibility evaluation against the backend.
 */
export default function LiveDemo() {
  const [result, setResult] = useState<DemoResult | null>(
    null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runDemo() {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(
        "/api/security/admissibility/evaluate",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(DEMO_PAYLOAD),
        },
      );

      if (!res.ok) {
        const data = await res
          .json()
          .catch(() => ({}));
        throw new Error(
          data.error
            || `Request failed (${res.status})`,
        );
      }

      const data: DemoResult = await res.json();
      setResult(data);
    } catch (err) {
      const msg =
        err instanceof Error
          ? err.message
          : String(err);
      if (msg.includes("fetch")) {
        setError(
          "Connect the backend to run the live demo.",
        );
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }

  const predicates =
    result?.certificate?.proof_payload
      ?.constructive_trace
    ?? result?.certificate?.proof_payload?.trace
    ?? [];

  const isAdmissible =
    result?.certificate?.result === "ADMISSIBLE";

  return (
    <div
      className={cn(
        "rounded-xl border border-border",
        "bg-card/80 p-6 shadow-sm",
      )}
    >
      {/* Pre-configured inputs */}
      <div className="mb-4 flex flex-wrap gap-3">
        {Object.entries(DEMO_PAYLOAD).map(
          ([label, val]) => (
            <div
              key={label}
              className={
                "rounded-md bg-muted/50 px-3 py-1.5"
              }
            >
              <span
                className={cn(
                  "text-[11px] font-medium uppercase",
                  "tracking-wider",
                  "text-muted-foreground/60",
                )}
              >
                {label}
              </span>
              <p className="font-mono text-sm text-foreground">
                {val}
              </p>
            </div>
          ),
        )}
      </div>

      {/* Run button */}
      <Button
        onClick={runDemo}
        disabled={loading}
        className="gap-2"
      >
        {loading ? (
          <>
            <Loader2
              className="h-4 w-4 animate-spin"
            />
            Evaluating...
          </>
        ) : (
          <>
            <Play className="h-4 w-4" />
            Run Live Demo
          </>
        )}
      </Button>

      {/* Error state */}
      {error && (
        <div
          className={cn(
            "mt-4 flex items-center gap-2",
            "rounded-md border",
            "border-destructive/30",
            "bg-destructive/10 px-4 py-3",
            "text-sm text-destructive",
          )}
        >
          <AlertCircle
            className="h-4 w-4 shrink-0"
          />
          {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="mt-4 space-y-4">
          {/* Decision banner */}
          <div
            className={cn(
              "flex items-center gap-2",
              "rounded-lg px-4 py-3",
              "text-sm font-semibold",
              isAdmissible
                ? "bg-success-50 text-success"
                : "bg-danger-50 text-danger",
            )}
          >
            {isAdmissible ? (
              <CheckCircle className="h-5 w-5" />
            ) : (
              <XCircle className="h-5 w-5" />
            )}
            {result.certificate.result}
          </div>

          {/* Predicate indicators */}
          {predicates.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {predicates.map((p) => (
                <div
                  key={p.predicate}
                  className={cn(
                    "flex items-center gap-1.5",
                    "rounded-md px-2.5 py-1",
                    "text-xs font-medium",
                    p.value
                      ? "bg-success-50 text-success"
                      : "bg-danger-50 text-danger",
                  )}
                >
                  {p.value ? (
                    <CheckCircle
                      className="h-3 w-3"
                    />
                  ) : (
                    <XCircle
                      className="h-3 w-3"
                    />
                  )}
                  {p.predicate}
                </div>
              ))}
            </div>
          )}

          {/* Certificate signature preview */}
          {result.certificate.signature && (
            <div
              className={
                "rounded-md bg-muted/50 px-3 py-2"
              }
            >
              <span
                className={cn(
                  "text-[11px] font-medium uppercase",
                  "tracking-wider",
                  "text-muted-foreground/60",
                )}
              >
                Certificate Signature
              </span>
              <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
                {result.certificate.signature}
              </p>
            </div>
          )}

          {/* Link to full verification */}
          <Link
            href="/verification"
            className={cn(
              "inline-flex items-center gap-1.5",
              "text-xs font-medium",
              "text-primary hover:underline",
            )}
          >
            View full details
            <ExternalLink className="h-3 w-3" />
          </Link>
        </div>
      )}
    </div>
  );
}
