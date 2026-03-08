"use client";

import type { PredicateOutcome } from "@/types/index";
import { cn } from "@/lib/utils";

interface TheoremDisplayProps {
  predicates: PredicateOutcome[];
}

/**
 * Proof summary card showing predicate satisfaction
 * without exposing the formal conjunction structure.
 */
export default function TheoremDisplay({
  predicates,
}: TheoremDisplayProps) {
  const total = predicates.length || 6;
  const passed = predicates.filter((p) => {
    if (p.predicate === "DenyExists") {
      return !p.value;
    }
    return p.value;
  }).length;
  const allPassed = passed === total;
  const pct = Math.round((passed / total) * 100);

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
        Formal Proof
      </p>
      <p className="mb-3 text-xs text-muted-foreground/70">
        All predicates must be satisfied for the
        admissibility theorem to hold.
      </p>
      <div className="flex items-center justify-between">
        <span
          className={cn(
            "text-sm font-bold",
            allPassed ? "text-success" : "text-danger",
          )}
        >
          {passed} of {total} predicates satisfied
        </span>
      </div>
      <div
        className={cn(
          "mt-2 h-2 w-full overflow-hidden",
          "rounded-full bg-muted",
        )}
      >
        <div
          className={cn(
            "h-full rounded-full transition-all duration-500",
            allPassed
              ? "bg-success"
              : "bg-danger",
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
