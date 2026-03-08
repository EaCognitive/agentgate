"use client";

import React, { useState } from "react";
import type { PredicateOutcome } from "@/types/index";
import { cn } from "@/lib/utils";
import { Check, ChevronDown, ChevronRight, X } from "lucide-react";

interface PredicateGridProps {
  predicates: PredicateOutcome[];
}

interface PredicateMeta {
  label: string;
  invertColor: boolean;
  description: string;
}

/**
 * Display labels and human-readable descriptions for each predicate.
 * DenyExists is inverted: green when false (good), red when true (bad).
 */
const PREDICATE_META: Record<string, PredicateMeta> = {
  AuthValid: {
    label: "AuthValid",
    invertColor: false,
    description:
      "The agent's identity is authenticated and verified.",
  },
  LineageValid: {
    label: "LineageValid",
    invertColor: false,
    description:
      "The request has a valid chain of delegation from its origin.",
  },
  PermitExists: {
    label: "PermitExists",
    invertColor: false,
    description:
      "At least one policy rule explicitly allows this action.",
  },
  DenyExists: {
    label: "DenyExists",
    invertColor: true,
    description:
      "Checks for explicit deny rules. Passes when no deny rule matches.",
  },
  ObligationsMet: {
    label: "ObligationsMet",
    invertColor: false,
    description:
      "All required preconditions and obligations are satisfied.",
  },
  ContextBound: {
    label: "ContextBound",
    invertColor: false,
    description:
      "The runtime context (environment, time) is within allowed bounds.",
  },
};

const PREDICATE_ORDER = [
  "AuthValid",
  "LineageValid",
  "PermitExists",
  "DenyExists",
  "ObligationsMet",
  "ContextBound",
];

function PredicateCard({ outcome }: { outcome: PredicateOutcome }) {
  const [expanded, setExpanded] = useState(false);
  const meta = PREDICATE_META[outcome.predicate] || {
    label: outcome.predicate,
    invertColor: false,
    description: "",
  };

  const isGood = meta.invertColor
    ? !outcome.value
    : outcome.value;

  return (
    <div
      className={cn(
        "rounded-xl border p-4 shadow-sm",
        "transition-colors",
        isGood
          ? "border-success-200 bg-success-50"
          : "border-danger-200 bg-danger-50",
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "flex h-6 w-6 items-center",
              "justify-center rounded-full text-white",
              isGood
                ? "bg-success"
                : "bg-danger",
            )}
          >
            {isGood ? (
              <Check className="h-3.5 w-3.5" />
            ) : (
              <X className="h-3.5 w-3.5" />
            )}
          </div>
          <span
            className={cn(
              "text-sm font-semibold text-foreground",
            )}
          >
            {meta.label}
          </span>
        </div>
        <span
          className={cn(
            "font-mono text-xs font-semibold",
            isGood
              ? "text-success"
              : "text-danger",
          )}
        >
          {String(outcome.value)}
        </span>
      </div>

      {meta.description && (
        <p className="mt-1.5 text-xs leading-snug text-muted-foreground">
          {meta.description}
        </p>
      )}

      {outcome.witness && Object.keys(outcome.witness).length > 0 && (
        <div className="mt-2">
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className={cn(
              "flex items-center gap-1 text-xs",
              "text-muted-foreground hover:text-foreground",
            )}
          >
            {expanded ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronRight className="h-3 w-3" />
            )}
            Witness data
          </button>
          {expanded && (
            <pre className={cn(
              "mt-1.5 max-h-40 overflow-auto rounded border",
              "border-border bg-background p-2",
              "font-mono text-xs text-muted-foreground",
            )}>
              {JSON.stringify(outcome.witness, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * 2x3 grid of predicate evaluation cards.
 */
export default function PredicateGrid({
  predicates,
}: PredicateGridProps) {
  const predicateMap = new Map(
    predicates.map((p) => [p.predicate, p]),
  );

  const ordered = PREDICATE_ORDER.map(
    (name) =>
      predicateMap.get(name) || {
        predicate: name,
        value: false,
        witness: {},
      },
  );

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {ordered.map((p) => (
        <PredicateCard key={p.predicate} outcome={p} />
      ))}
    </div>
  );
}
