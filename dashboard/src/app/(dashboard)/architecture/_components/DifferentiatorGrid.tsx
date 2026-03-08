"use client";

import React from "react";
import { cn } from "@/lib/utils";
import {
  ShieldCheck,
  Binary,
  GitFork,
  Fingerprint,
  Eye,
  Layers,
} from "lucide-react";

interface Differentiator {
  icon: React.ReactNode;
  title: string;
  description: string;
  comparison: string;
}

const ICON_CLS = "h-5 w-5";

const ITEMS: Differentiator[] = [
  {
    icon: <Binary className={ICON_CLS} />,
    title: "Formal Verification, Not Rule Matching",
    description:
      "Decisions are derived from a six-predicate admissibility "
      + "theorem evaluated by an SMT solver (Z3). Each decision is "
      + "a mathematical proof, not a boolean from a rule engine.",
    comparison:
      "Cedar evaluates policies and returns allow/deny. OPA evaluates "
      + "Rego and returns a JSON result. Neither can prove the decision "
      + "was correct -- they can only assert it. A Z3 proof is "
      + "independently verifiable.",
  },
  {
    icon: <Fingerprint className={ICON_CLS} />,
    title: "Signed Certificates, Not Audit Logs",
    description:
      "Every decision is Ed25519-signed with three hashes binding "
      + "the action context, policy state, and theorem formula. "
      + "Tamper-evident and verifiable without trusting the issuer.",
    comparison:
      "AWS CloudTrail records events to S3 -- logs that can be "
      + "modified or deleted. Cedar/OPA produce no cryptographic "
      + "artifact. You trust the log store, not the math.",
  },
  {
    icon: <ShieldCheck className={ICON_CLS} />,
    title: "Dual-Solver Drift Detection",
    description:
      "Two independent evaluation engines (Python + Z3) must agree. "
      + "Disagreement automatically fails closed and alerts -- no "
      + "silent wrong answers.",
    comparison:
      "Cedar, OPA, and Zanzibar each run a single evaluator. "
      + "If the evaluator has a bug, the wrong decision is emitted "
      + "silently. There is no cross-check mechanism.",
  },
  {
    icon: <Eye className={ICON_CLS} />,
    title: "Proactive Deception Detection",
    description:
      "Admin-planted honey-token resources detect compromised or "
      + "misbehaving agents before any damage occurs. Trust is "
      + "progressively degraded on detection.",
    comparison:
      "Cedar, OPA, and Guardrails AI are reactive -- they evaluate "
      + "requests against rules. None proactively detect bad actors "
      + "through behavioral traps. Deception detection is an "
      + "entirely absent category.",
  },
  {
    icon: <GitFork className={ICON_CLS} />,
    title: "Agent Delegation Lineage",
    description:
      "Agents delegate to sub-agents with attenuated permissions. "
      + "Revocation cascades transitively. No agent can escalate "
      + "beyond its delegator's scope.",
    comparison:
      "Cedar and OPA model human users with static roles. "
      + "Zanzibar/SpiceDB has relationship-based ACLs but no "
      + "delegation attenuation or transitive revocation. None "
      + "were designed for agent-to-agent delegation chains.",
  },
  {
    icon: <Layers className={ICON_CLS} />,
    title: "Built for AI Agents, Not Human Users",
    description:
      "MCP-native tool governance with operation classification, "
      + "human approval workflows for high-impact actions, "
      + "rate limiting on destructive operations, and hardcoded "
      + "guardrails that AI cannot override.",
    comparison:
      "Cedar, OPA, and Zanzibar were built for human authorization "
      + "in web apps. Guardrails AI filters LLM I/O but does not "
      + "govern tool execution. None address the MCP tool call "
      + "lifecycle or autonomous agent threat model.",
  },
];

/**
 * Grid of competitive differentiators vs. real market alternatives.
 */
export default function DifferentiatorGrid() {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      {ITEMS.map((item) => (
        <div
          key={item.title}
          className={cn(
            "group rounded-xl border border-border bg-card/80 p-5",
            "shadow-sm transition-colors",
            "hover:border-primary/30 hover:bg-card",
          )}
        >
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            {item.icon}
          </div>
          <h3 className="text-sm font-semibold text-foreground">
            {item.title}
          </h3>
          <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">
            {item.description}
          </p>
          <div className="mt-3 border-t border-border pt-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/60">
              Industry Comparison
            </p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {item.comparison}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
