"use client";

import React from "react";
import { cn } from "@/lib/utils";
import {
  Radio,
  Shield,
  KeyRound,
  SearchCheck,
  Scale,
  Cpu,
  FileCheck2,
  ArrowDown,
} from "lucide-react";

interface Stage {
  icon: React.ReactNode;
  label: string;
  title: string;
  description: string;
  detail: string;
}

const ICON_CLS = "h-5 w-5";

const STAGES: Stage[] = [
  {
    icon: <Radio className={ICON_CLS} />,
    label: "Stage 1",
    title: "MCP Tool Interception",
    description:
      "Every tool call from an AI agent is intercepted before execution.",
    detail:
      "The MCP server classifies the operation (read, mutating, "
      + "high-impact mutating) and routes it through the governance "
      + "kernel. No tool call bypasses this entry point.",
  },
  {
    icon: <Shield className={ICON_CLS} />,
    label: "Stage 2",
    title: "Guardrails & Rate Limits",
    description:
      "Hardcoded safety rules that cannot be overridden by AI or API.",
    detail:
      "File-based configuration defines blocked operations, approval "
      + "requirements, and per-hour rate limits. These guardrails are "
      + "immutable to API calls -- only a human with server access can "
      + "change them.",
  },
  {
    icon: <KeyRound className={ICON_CLS} />,
    label: "Stage 3",
    title: "Authentication & Authorization",
    description:
      "Verifies the principal's identity, role, and session validity.",
    detail:
      "Session tokens are validated against a 30-second cache. "
      + "Role-based permissions are checked, and MCP-specific policy "
      + "gates are applied. Failure here means immediate rejection.",
  },
  {
    icon: <SearchCheck className={ICON_CLS} />,
    label: "Stage 4",
    title: "Honey-Token Deception Check",
    description:
      "Detects compromised agents by checking for canary resource access.",
    detail:
      "Admin-planted canary resources (fake credentials, honeypot "
      + "endpoints) are checked before any evaluation. If triggered, "
      + "the principal's trust is progressively degraded: flag, "
      + "downgrade scope, or fully suspend grants.",
  },
  {
    icon: <Scale className={ICON_CLS} />,
    label: "Stage 5",
    title: "Six-Predicate Formal Evaluation",
    description:
      "The core admissibility theorem: six conditions that must "
      + "ALL hold for an action to be permitted.",
    detail:
      "AuthValid (identity verified), LineageValid (delegation chain "
      + "intact), PermitExists (policy allows it), NOT DenyExists (no "
      + "deny rule matches), ObligationsMet (preconditions satisfied), "
      + "ContextBound (runtime context within bounds). Every predicate "
      + "produces a witness -- evidence of why it passed or failed.",
  },
  {
    icon: <Cpu className={ICON_CLS} />,
    label: "Stage 6",
    title: "Z3 Dual-Solver Cross-Verification",
    description:
      "An independent SMT theorem prover re-evaluates the decision.",
    detail:
      "The Z3 solver binds predicate outcomes to symbolic boolean "
      + "variables and checks satisfiability of the theorem formula. "
      + "If Z3 disagrees with the Python evaluator (drift), the "
      + "system fails closed. This is a mathematical proof, not a "
      + "heuristic.",
  },
  {
    icon: <FileCheck2 className={ICON_CLS} />,
    label: "Stage 7",
    title: "Certificate Signing & Evidence Chain",
    description:
      "The decision is cryptographically signed and appended to "
      + "an immutable evidence chain.",
    detail:
      "An Ed25519 signature binds the decision to three hashes: "
      + "alpha (action context), gamma (policy knowledge base), and "
      + "theorem (the formal rules). This certificate is tamper-evident "
      + "and independently verifiable. The decision is then appended to "
      + "a transparency log for audit.",
  },
];

/**
 * Vertical architecture pipeline diagram showing all 7 governance stages.
 */
export default function ArchitecturePipeline() {
  return (
    <div className="space-y-1">
      {STAGES.map((stage, idx) => (
        <React.Fragment key={stage.label}>
          <div
            className={cn(
              "rounded-xl border border-border bg-card/80 p-5 shadow-sm",
              "transition-colors hover:border-primary/30 hover:bg-card",
            )}
          >
            <div className="flex gap-4">
              {/* Icon + stage number */}
              <div className="flex flex-col items-center">
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-primary">
                  {stage.icon}
                </div>
                <span className="mt-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {stage.label}
                </span>
              </div>

              {/* Content */}
              <div className="flex-1">
                <h3 className="text-sm font-semibold text-foreground">
                  {stage.title}
                </h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {stage.description}
                </p>
                <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground/80">
                  {stage.detail}
                </p>
              </div>
            </div>
          </div>

          {/* Arrow between stages */}
          {idx < STAGES.length - 1 && (
            <div className="flex justify-center py-0.5">
              <ArrowDown className="h-4 w-4 text-muted-foreground/40" />
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}
