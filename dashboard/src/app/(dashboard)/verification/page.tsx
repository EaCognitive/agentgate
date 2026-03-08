"use client";

import React, { useState } from "react";
import type { AdmissibilityResponse } from "@/types/index";
import {
  BadgeCheck,
  ArrowRight,
  ShieldCheck,
} from "lucide-react";
import RuntimeStatus from "./_components/RuntimeStatus";
import EvaluationForm from "./_components/EvaluationForm";
import PipelineSteps from "./_components/PipelineSteps";
import VerificationResults from "./_components/VerificationResults";

/**
 * Interactive formal verification page.
 * Allows users to submit actions for Z3-backed admissibility evaluation
 * and view the resulting proof certificate.
 */
export default function VerificationPage() {
  const [result, setResult] = useState<AdmissibilityResponse | null>(
    null,
  );
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-2xl font-bold text-foreground">
            Formal Verification
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Evaluate an agent action against the admissibility
            theorem using Z3 formal verification and view the
            signed proof certificate.
          </p>
        </div>
        <RuntimeStatus />
      </div>

      {/* Differentiator callout */}
      <div
        className={
          "rounded-xl border border-primary/20 "
          + "bg-primary/5 p-5"
        }
      >
        <p
          className={
            "text-sm leading-relaxed text-foreground"
          }
        >
          What you are about to see is computed live against
          a running verification engine. Every decision
          produces a cryptographically signed certificate
          -- not a log entry.
        </p>
        <div className="mt-3 flex flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            <span
              className={
                "text-xs font-medium "
                + "text-muted-foreground"
              }
            >
              6 Formal Predicates
            </span>
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            <span
              className={
                "text-xs font-medium "
                + "text-muted-foreground"
              }
            >
              Independent Cross-Verification
            </span>
          </div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            <span
              className={
                "text-xs font-medium "
                + "text-muted-foreground"
              }
            >
              Signed Certificate
            </span>
          </div>
        </div>
      </div>

      {/* Pipeline visualization */}
      <PipelineSteps result={result} running={running} />

      {/* Two-column layout */}
      <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-12">
        {/* Left column: Evaluation form -- sticky on desktop */}
        <div className="lg:col-span-4 lg:sticky lg:top-6 lg:self-start">
          <div className="rounded-xl border border-border bg-card/80 shadow-sm backdrop-blur-sm">
            <div className="border-b border-border px-5 py-4">
              <p className="text-sm font-semibold text-foreground">
                Evaluation Input
              </p>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Define the action an agent wants to perform.
              </p>
            </div>
            <div className="p-5">
              <EvaluationForm
                onResult={(data) => {
                  setRunning(false);
                  setError("");
                  setResult(data);
                }}
                onError={(msg) => {
                  setRunning(false);
                  setError(msg);
                }}
                onSubmit={() => {
                  setRunning(true);
                  setResult(null);
                }}
              />
              {error && (
                <div className="mt-3 rounded-md border border-danger-200 bg-danger-50 px-3 py-2 text-sm text-danger">
                  {error}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right column: Results */}
        <div className="lg:col-span-8">
          {result ? (
            <VerificationResults data={result} />
          ) : (
            <EmptyState />
          )}
        </div>
      </div>

    </div>
  );
}

/**
 * Placeholder shown before any verification has been submitted.
 * Provides a visual walkthrough of what will appear.
 */
function EmptyState() {
  const steps = [
    {
      step: "1",
      title: "Configure action",
      description:
        "Enter the principal, action, resource, and optional "
        + "runtime context in the form.",
    },
    {
      step: "2",
      title: "Run verification",
      description:
        "The system evaluates six formal predicates and runs "
        + "the Z3 theorem prover.",
    },
    {
      step: "3",
      title: "Review certificate",
      description:
        "See the predicate results, theorem evaluation, solver "
        + "output, and signed proof certificate.",
    },
  ];

  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card/30 px-6 py-16">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
        <BadgeCheck className="h-6 w-6 text-primary" />
      </div>
      <p className="mb-1 text-sm font-semibold text-foreground">
        No verification results yet
      </p>
      <p className="mb-8 max-w-sm text-center text-xs text-muted-foreground">
        Submit an action using the form to walk through the formal
        verification process step by step.
      </p>
      <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start sm:gap-3">
        {steps.map((s, idx) => (
          <React.Fragment key={s.step}>
            {idx > 0 && (
              <ArrowRight className="hidden h-4 w-4 shrink-0 text-muted-foreground/40 sm:block sm:mt-3" />
            )}
            <div className="max-w-[10rem] text-center">
              <div className="mx-auto mb-2 flex h-7 w-7 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
                {s.step}
              </div>
              <p className="text-xs font-medium text-foreground">
                {s.title}
              </p>
              <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                {s.description}
              </p>
            </div>
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
