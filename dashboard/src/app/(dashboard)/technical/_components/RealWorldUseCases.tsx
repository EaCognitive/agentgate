"use client";

import React from "react";
import { cn } from "@/lib/utils";
import {
  Landmark,
  HeartPulse,
  Bot,
  Scale,
  Shield,
  FileCheck2,
} from "lucide-react";

interface UseCase {
  icon: React.ReactNode;
  industry: string;
  scenario: string;
  withoutAgentgate: string;
  withAgentgate: string;
  capabilities: string[];
}

const ICON_CLS = "h-5 w-5";

const USE_CASES: UseCase[] = [
  {
    icon: <Landmark className={ICON_CLS} />,
    industry: "Financial Services",
    scenario:
      "An AI trading agent generates a 15-trade rebalancing plan "
      + "for a client portfolio. Trade 11 would exceed the agent's "
      + "delegated authority by accessing a restricted asset class.",
    withoutAgentgate:
      "Trades 1 through 10 execute successfully. Trade 11 fails "
      + "at the broker API. Trades 12-15 are orphaned. The portfolio "
      + "is in an inconsistent state. Rollback requires manual "
      + "intervention and the client sees partial execution.",
    withAgentgate:
      "Counterfactual plan verification evaluates all 15 trades "
      + "before any execution. Step 11 is flagged as inadmissible "
      + "with a proof certificate explaining the delegation scope "
      + "violation. The human advisor reviews and adjusts the plan. "
      + "Zero trades execute until the full plan is approved.",
    capabilities: [
      "Counterfactual plan verification",
      "Delegation lineage",
      "Signed certificates",
    ],
  },
  {
    icon: <HeartPulse className={ICON_CLS} />,
    industry: "Healthcare / HIPAA",
    scenario:
      "A clinical AI agent accesses patient records to generate "
      + "a treatment summary. A regulator audits the access six "
      + "months later and asks: 'Prove this agent was authorized "
      + "to access these specific records at this specific time.'",
    withoutAgentgate:
      "You produce CloudTrail logs showing an API call was made. "
      + "The regulator asks: 'How do I know these logs were not "
      + "modified?' You point to S3 versioning. They point to the "
      + "30+ ways S3 objects can be altered with the right IAM "
      + "permissions. The conversation stalls.",
    withAgentgate:
      "You hand the regulator the decision certificate. It contains "
      + "the Ed25519 signature, the hash of the exact policy state, "
      + "the hash of the exact request context, and the constructive "
      + "proof showing all six predicates were satisfied. The "
      + "regulator can verify the signature independently without "
      + "trusting your infrastructure.",
    capabilities: [
      "Signed proof certificates",
      "Hash-linked evidence chain",
      "Formal verification",
    ],
  },
  {
    icon: <Bot className={ICON_CLS} />,
    industry: "Multi-Agent Orchestration",
    scenario:
      "A primary agent delegates to a research sub-agent, which "
      + "delegates to a data-fetching sub-sub-agent. The data "
      + "fetcher attempts to access a resource outside the original "
      + "delegation scope.",
    withoutAgentgate:
      "The data fetcher successfully accesses the resource because "
      + "delegation permissions are not tracked across hops. The "
      + "privilege escalation goes undetected. Data is exfiltrated "
      + "through the delegation chain.",
    withAgentgate:
      "Delegation lineage enforces attenuation at every hop: child "
      + "permissions must be a strict subset of parent permissions, "
      + "and resource scopes must narrow (never widen). The data "
      + "fetcher's request is inadmissible because its scope exceeds "
      + "the research agent's scope, which in turn is bounded by "
      + "the primary agent's original grant.",
    capabilities: [
      "Delegation lineage with attenuation",
      "Transitive revocation",
      "Formal verification",
    ],
  },
  {
    icon: <Scale className={ICON_CLS} />,
    industry: "Legal / Liability Protection",
    scenario:
      "An AI agent makes a decision that causes financial harm to "
      + "a customer. The customer sues. The company's legal team "
      + "needs to demonstrate that adequate governance controls "
      + "were in place and functioning correctly.",
    withoutAgentgate:
      "The legal team presents server logs and policy documentation. "
      + "Opposing counsel argues that logs are mutable, policies "
      + "could have been changed after the fact, and there is no "
      + "proof the system was functioning as described at the time "
      + "of the incident.",
    withAgentgate:
      "The legal team presents the signed decision certificate "
      + "from the exact moment of the decision. It cryptographically "
      + "proves: which policies were active (gamma_hash), what the "
      + "agent requested (alpha_hash), that all six predicates were "
      + "satisfied (constructive_trace), and that two independent "
      + "solvers agreed (drift_detected: false). The evidence is "
      + "tamper-proof by construction.",
    capabilities: [
      "Signed proof certificates",
      "Dual-solver verification",
      "Context binding",
      "Evidence chain",
    ],
  },
  {
    icon: <Shield className={ICON_CLS} />,
    industry: "Security / Incident Response",
    scenario:
      "An AI agent is compromised through a prompt injection "
      + "attack and begins probing for sensitive resources it "
      + "should not access.",
    withoutAgentgate:
      "The compromised agent probes APIs and databases. Each "
      + "individual request might pass authorization checks because "
      + "it uses valid credentials. The anomalous behavior pattern "
      + "is only detected after significant data access has occurred, "
      + "if it is detected at all.",
    withAgentgate:
      "The agent's first probe hits a honey-token resource. The "
      + "deception framework triggers immediately: severity 1 flags "
      + "the behavior, severity 2 downgrades the agent's trust "
      + "level, severity 3 suspends all delegation grants in the "
      + "chain. The attack surface collapses within milliseconds, "
      + "before any real data is accessed.",
    capabilities: [
      "Honey-token deception detection",
      "Progressive trust degradation",
      "Transitive grant revocation",
    ],
  },
  {
    icon: <FileCheck2 className={ICON_CLS} />,
    industry: "Policy Management / DevOps",
    scenario:
      "A team deploys a new set of authorization policies for "
      + "their AI agent fleet. The new policies contain a subtle "
      + "contradiction: two rules conflict for a specific "
      + "action/resource combination.",
    withoutAgentgate:
      "The contradiction goes live. For three weeks, some requests "
      + "are randomly allowed or denied depending on rule evaluation "
      + "order. The bug is discovered during a production incident "
      + "when a critical operation is unexpectedly blocked.",
    withAgentgate:
      "Before deployment, property-based synthesis runs 10,000+ "
      + "randomized scenarios against the new policy set. It "
      + "discovers 12 INSTABILITY invariants where the same "
      + "action/resource pair yields different results under minimal "
      + "perturbation. The team fixes three contradicting rules "
      + "before any production impact.",
    capabilities: [
      "Property-based policy synthesis",
      "DTSL rule proposals",
      "Invariant classification",
    ],
  },
];

export default function RealWorldUseCases() {
  return (
    <div className="space-y-4">
      {USE_CASES.map((uc) => (
        <div
          key={uc.industry}
          className="rounded-xl border border-border bg-card/80 p-5 shadow-sm"
        >
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              {uc.icon}
            </div>
            <div className="min-w-0 flex-1">
              <h4 className="text-sm font-semibold text-foreground">
                {uc.industry}
              </h4>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {uc.scenario}
              </p>

              <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
                {/* Without */}
                <div
                  className={cn(
                    "rounded-lg border px-3 py-2.5",
                    "border-danger-200 bg-danger-50",
                  )}
                >
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-danger">
                    Without AgentGate
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                    {uc.withoutAgentgate}
                  </p>
                </div>

                {/* With */}
                <div
                  className={cn(
                    "rounded-lg border px-3 py-2.5",
                    "border-success-200 bg-success-50",
                  )}
                >
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-success">
                    With AgentGate
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                    {uc.withAgentgate}
                  </p>
                </div>
              </div>

              {/* Capability tags */}
              <div className="mt-3 flex flex-wrap gap-1.5">
                {uc.capabilities.map((cap) => (
                  <span
                    key={cap}
                    className={cn(
                      "inline-block rounded-full px-2 py-0.5",
                      "bg-primary/10 text-[10px] font-medium text-primary",
                    )}
                  >
                    {cap}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
