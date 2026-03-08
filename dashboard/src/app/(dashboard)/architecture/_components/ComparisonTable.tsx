"use client";

import React from "react";
import { cn } from "@/lib/utils";
import { Check, X, Minus } from "lucide-react";

type Support = "full" | "partial" | "none";

interface Feature {
  name: string;
  why: string;
  agentgate: Support;
  cedar: Support;
  opa: Support;
  zanzibar: Support;
  guardrailsAi: Support;
}

const FEATURES: Feature[] = [
  {
    name: "Provable decision correctness",
    why:
      "A boolean allow/deny can be wrong silently. A formal proof "
      + "demonstrates WHY the decision was made and can be independently "
      + "verified after the fact.",
    agentgate: "full",
    cedar: "none",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "none",
  },
  {
    name: "Cryptographically signed decisions",
    why:
      "CloudTrail logs can be deleted or modified. A signed certificate "
      + "with hash-bound inputs is tamper-evident without trusting the "
      + "logging infrastructure.",
    agentgate: "full",
    cedar: "none",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "none",
  },
  {
    name: "Dual-solver cross-verification",
    why:
      "A single evaluator has no way to detect its own bugs. Two "
      + "independent solvers (Python + Z3) catch internal "
      + "inconsistencies before they become security incidents.",
    agentgate: "full",
    cedar: "none",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "none",
  },
  {
    name: "AI agent delegation lineage",
    why:
      "Human users don't delegate to sub-users at runtime. AI agents "
      + "do. Delegation chains need attenuation guarantees and "
      + "transitive revocation -- concepts these systems lack.",
    agentgate: "full",
    cedar: "none",
    opa: "none",
    zanzibar: "partial",
    guardrailsAi: "none",
  },
  {
    name: "Deception detection (honey-tokens)",
    why:
      "Rule engines react to known bad actions. Honey-tokens "
      + "proactively detect compromised agents by observing behavior "
      + "against canary resources.",
    agentgate: "full",
    cedar: "none",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "none",
  },
  {
    name: "MCP-native tool governance",
    why:
      "Governing AI agent tool calls at the MCP protocol level, "
      + "including operation classification and agent-to-tool "
      + "lifecycle management.",
    agentgate: "full",
    cedar: "full",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "partial",
  },
  {
    name: "Policy-as-code evaluation",
    why:
      "Declarative policy languages for access control rules.",
    agentgate: "full",
    cedar: "full",
    opa: "full",
    zanzibar: "partial",
    guardrailsAi: "partial",
  },
  {
    name: "Role-based access control",
    why:
      "Assigning permissions based on user/agent roles.",
    agentgate: "full",
    cedar: "full",
    opa: "full",
    zanzibar: "full",
    guardrailsAi: "none",
  },
  {
    name: "Human approval workflows",
    why:
      "High-impact operations require explicit human review before "
      + "execution. Critical for AI agents making autonomous decisions.",
    agentgate: "full",
    cedar: "none",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "none",
  },
  {
    name: "Static policy verification (SMT)",
    why:
      "Proving policies themselves are consistent and free of "
      + "contradictions before deployment.",
    agentgate: "partial",
    cedar: "full",
    opa: "none",
    zanzibar: "none",
    guardrailsAi: "none",
  },
  {
    name: "Immutable evidence chain",
    why:
      "Append-only log of every decision with full proof payloads, "
      + "not just event records.",
    agentgate: "full",
    cedar: "partial",
    opa: "partial",
    zanzibar: "partial",
    guardrailsAi: "none",
  },
];

interface ColumnDef {
  key: string;
  label: string;
  sublabel: string;
}

const COLUMNS: ColumnDef[] = [
  {
    key: "agentgate",
    label: "AgentGate",
    sublabel: "",
  },
  {
    key: "cedar",
    label: "Cedar",
    sublabel: "AWS AgentCore",
  },
  {
    key: "opa",
    label: "OPA / Rego",
    sublabel: "CNCF",
  },
  {
    key: "zanzibar",
    label: "Zanzibar",
    sublabel: "Google / SpiceDB",
  },
  {
    key: "guardrailsAi",
    label: "Guardrails AI",
    sublabel: "/ NeMo",
  },
];

function SupportIcon({ level }: { level: Support }) {
  if (level === "full") {
    return (
      <div className="flex h-5 w-5 items-center justify-center rounded-full bg-success-100">
        <Check className="h-3 w-3 text-success" />
      </div>
    );
  }
  if (level === "partial") {
    return (
      <div className="flex h-5 w-5 items-center justify-center rounded-full bg-warning-100">
        <Minus className="h-3 w-3 text-warning" />
      </div>
    );
  }
  return (
    <div className="flex h-5 w-5 items-center justify-center rounded-full bg-muted">
      <X className="h-3 w-3 text-muted-foreground/40" />
    </div>
  );
}

/**
 * Feature comparison table: AgentGate vs. real market competitors.
 * Each row includes a "why it matters" tooltip.
 */
export default function ComparisonTable() {
  return (
    <div className="overflow-x-auto rounded-xl border border-border shadow-sm">
      <table className="min-w-[700px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 font-semibold text-foreground">
              Capability
            </th>
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className={cn(
                  "px-3 py-3 text-center",
                  col.key === "agentgate"
                    ? "text-primary"
                    : "text-muted-foreground",
                )}
              >
                <span className="block font-semibold">
                  {col.label}
                </span>
                {col.sublabel && (
                  <span className="block text-[10px] font-normal text-muted-foreground">
                    {col.sublabel}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {FEATURES.map((feat, idx) => (
            <tr
              key={feat.name}
              className={cn(
                "group border-b border-border last:border-0",
                idx % 2 === 0 ? "bg-card/80" : "bg-card/40",
              )}
            >
              <td className="px-4 py-2.5">
                <span className="font-medium text-foreground">
                  {feat.name}
                </span>
                <p className="mt-0.5 max-w-xs text-[11px] leading-snug text-muted-foreground/70">
                  {feat.why}
                </p>
              </td>
              {COLUMNS.map((col) => (
                <td
                  key={col.key}
                  className="px-3 py-2.5 text-center"
                >
                  <div className="flex justify-center">
                    <SupportIcon
                      level={
                        feat[col.key as keyof Feature] as Support
                      }
                    />
                  </div>
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
