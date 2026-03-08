"use client";

import type {
  AdmissibilityResponse,
  PredicateOutcome,
  RuntimeSolverPayload,
} from "@/types/index";
import { cn } from "@/lib/utils";
import {
  BadgeCheck,
  ShieldAlert,
  Check,
  X,
} from "lucide-react";
import PredicateGrid from "./PredicateGrid";
import TheoremDisplay from "./TheoremDisplay";
import CertificateCard from "./CertificateCard";

interface VerificationResultsProps {
  data: AdmissibilityResponse;
}

/**
 * Human-readable descriptions for proof types.
 */
const PROOF_TYPE_HINTS: Record<string, string> = {
  CONSTRUCTIVE_TRACE:
    "A complete step-by-step proof showing every predicate evaluation.",
  COUNTEREXAMPLE:
    "A concrete scenario proving the action cannot be admitted.",
  UNSAT_CORE:
    "The minimal set of unsatisfied predicates that caused rejection.",
};

/**
 * Extracts the predicate list from the proof payload.
 * Tries constructive_trace first, then trace (counterexample).
 */
function extractPredicates(
  data: AdmissibilityResponse,
): PredicateOutcome[] {
  const payload = data.certificate.proof_payload;
  return (
    payload.constructive_trace
    || payload.trace
    || []
  );
}

/**
 * Banner showing ADMISSIBLE / INADMISSIBLE with proof type.
 */
function DecisionBanner({
  result,
  proofType,
}: {
  result: string;
  proofType: string;
}) {
  const isAdmissible = result.toUpperCase() === "ADMISSIBLE";
  const proofLabel = proofType.replace(/_/g, " ").toUpperCase();
  const proofHint = PROOF_TYPE_HINTS[proofType.toUpperCase()]
    || PROOF_TYPE_HINTS[proofType]
    || "";

  return (
    <div
      className={cn(
        "rounded-xl border p-5 shadow-sm",
        isAdmissible
          ? "border-success-200 bg-success-50"
          : "border-danger-200 bg-danger-50",
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {isAdmissible ? (
            <BadgeCheck
              className="h-6 w-6 text-success"
            />
          ) : (
            <ShieldAlert
              className="h-6 w-6 text-danger"
            />
          )}
          <div>
            <span
              className={cn(
                "text-lg font-bold tracking-wide",
                isAdmissible
                  ? "text-success"
                  : "text-danger",
              )}
            >
              {isAdmissible
                ? "ADMISSIBLE"
                : "INADMISSIBLE"}
            </span>
            <p
              className={cn(
                "mt-0.5 text-xs",
                "text-muted-foreground",
              )}
            >
              {isAdmissible
                ? "The action satisfies all formal "
                  + "requirements and is permitted."
                : "The action failed one or more formal "
                  + "requirements and is blocked."}
            </p>
          </div>
        </div>
        <div className="text-right">
          <span
            className={cn(
              "rounded-full px-3 py-1",
              "text-xs font-semibold",
              isAdmissible
                ? "bg-success-100 text-success"
                : "bg-danger-100 text-danger",
            )}
            title={proofHint}
          >
            {proofLabel}
          </span>
          {proofHint && (
            <p className="mt-1.5 max-w-xs text-xs text-muted-foreground">
              {proofHint}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Simplified verification method card.
 * Shows verification outcomes without exposing backend architecture.
 */
function SolverCard({
  solver,
}: {
  solver: RuntimeSolverPayload;
}) {
  const independentPassed =
    solver.python_result === true
    && solver.z3_result === true;
  const crossConsistent = !solver.drift_detected;

  return (
    <div
      className={cn(
        "rounded-xl border border-border",
        "bg-card/80 p-5 shadow-sm",
      )}
    >
      <p
        className={cn(
          "mb-1 text-xs font-semibold uppercase",
          "tracking-wider text-muted-foreground",
        )}
      >
        Verification Method
      </p>
      <p className="mb-3 text-xs text-muted-foreground/70">
        Two independent evaluation engines verified
        this decision.
      </p>
      <div className="divide-y divide-border">
        <div
          className={cn(
            "flex items-center justify-between py-2",
          )}
        >
          <div>
            <span className="text-xs text-muted-foreground">
              Independent Verification
            </span>
            <p
              className={cn(
                "text-[11px]",
                "text-muted-foreground/70",
              )}
            >
              Both engines evaluated this decision
              independently.
            </p>
          </div>
          <span
            className={cn(
              "flex items-center gap-1",
              "text-xs font-medium",
              independentPassed
                ? "text-success"
                : "text-danger",
            )}
          >
            {independentPassed ? (
              <Check className="h-3 w-3" />
            ) : (
              <X className="h-3 w-3" />
            )}
            {independentPassed ? "Passed" : "Failed"}
          </span>
        </div>
        <div
          className={cn(
            "flex items-center justify-between py-2",
          )}
        >
          <div>
            <span className="text-xs text-muted-foreground">
              Cross-Verification
            </span>
            <p
              className={cn(
                "text-[11px]",
                "text-muted-foreground/70",
              )}
            >
              Cross-verification confirms both engines
              reached the same conclusion.
            </p>
          </div>
          <span
            className={cn(
              "flex items-center gap-1",
              "text-xs font-medium",
              crossConsistent
                ? "text-success"
                : "text-danger",
            )}
          >
            {crossConsistent ? (
              <Check className="h-3 w-3" />
            ) : (
              <X className="h-3 w-3" />
            )}
            {crossConsistent
              ? "Consistent"
              : "Drift Detected"}
          </span>
        </div>
        <div
          className={cn(
            "flex items-center justify-between py-2",
          )}
        >
          <span className="text-xs text-muted-foreground">
            Verification Mode
          </span>
          <span
            className="font-mono text-xs text-foreground"
          >
            {solver.solver_mode || "N/A"}
          </span>
        </div>
        {solver.failure_reason && (
          <div className="py-2">
            <span
              className={cn(
                "text-xs",
                "text-danger",
              )}
            >
              {solver.failure_reason}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Orchestrates the full verification results display.
 */
export default function VerificationResults({
  data,
}: VerificationResultsProps) {
  const predicates = extractPredicates(data);
  const solver =
    data.runtime_solver
    || data.certificate.proof_payload.runtime_solver;

  return (
    <div className="space-y-6">
      <DecisionBanner
        result={data.certificate.result}
        proofType={data.certificate.proof_type}
      />

      {predicates.length > 0 && (
        <>
          <div>
            <p
              className={cn(
                "mb-1 text-xs font-semibold uppercase",
                "tracking-wider text-muted-foreground",
              )}
            >
              Predicate Evaluation
            </p>
            <p className="mb-3 text-xs text-muted-foreground/70">
              Each predicate is a formal requirement that must be
              satisfied. All six must pass for an action to be
              admissible.
            </p>
            <PredicateGrid predicates={predicates} />
          </div>

          <TheoremDisplay predicates={predicates} />
        </>
      )}

      {solver && <SolverCard solver={solver} />}

      <CertificateCard certificate={data.certificate} />
    </div>
  );
}
