"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface EvidenceRow {
  capability: string;
  module: string;
  status: string;
  keyCapabilities: string;
  verifiable: string;
}

const EVIDENCE: EvidenceRow[] = [
  {
    capability: "Signed proof certificates",
    module: "Formal models module",
    status: "Implemented",
    keyCapabilities:
      "Certificate issuance, Ed25519 signing, "
      + "canonical serialization, hash computation",
    verifiable:
      "Certificate contains decision ID, theorem hash, "
      + "context hash, policy hash, and signature. "
      + "Independent verification recomputes and checks.",
  },
  {
    capability: "Formal verification (Z3)",
    module: "Solver engine",
    status: "Implemented",
    keyCapabilities:
      "Theorem definition, solver mode configuration, "
      + "admissibility evaluation",
    verifiable:
      "Six-predicate conjunction. Three modes: "
      + "off/shadow/enforce. Shadow logs without blocking. "
      + "Enforce fails closed on error.",
  },
  {
    capability: "Dual-solver drift detection",
    module: "Solver engine",
    status: "Implemented",
    keyCapabilities:
      "Z3 evaluation, drift detection, "
      + "metrics recording",
    verifiable:
      "Python and Z3 results compared. Disagreement "
      + "triggers fail-closed. Decision forced to "
      + "INADMISSIBLE.",
  },
  {
    capability: "Counterfactual plan verification",
    module: "Plan verification module",
    status: "Implemented",
    keyCapabilities:
      "Risk-tiered bounds, plan evaluation, "
      + "step-level failure reporting",
    verifiable:
      "Risk tiers: low=5, medium=10, high=20, "
      + "critical=30 steps. Returns blocked step index "
      + "with counterexample on failure.",
  },
  {
    capability: "Distributed consensus",
    module: "Consensus module",
    status: "Implemented",
    keyCapabilities:
      "Node management, quorum configuration, "
      + "co-signing, transparency logging",
    verifiable:
      "N-of-M quorum. Co-signature protocol. "
      + "Global revocation broadcast on disagreement.",
  },
  {
    capability: "Policy synthesis (fuzzing)",
    module: "Policy synthesis module",
    status: "Implemented",
    keyCapabilities:
      "Anomaly classification, synthesis configuration, "
      + "automated discovery, policy perturbation",
    verifiable:
      "10K-100K iterations. Four invariant types. "
      + "DTSL expression generation. Proposal workflow "
      + "with approve/reject.",
  },
  {
    capability: "Honey-token deception",
    module: "Deception detection module",
    status: "Implemented",
    keyCapabilities:
      "Token type management, trust degradation, "
      + "trigger detection",
    verifiable:
      "Four token types (TOOL, RESOURCE, CREDENTIAL, "
      + "DATA_STORE). Three severity levels with "
      + "graduated response.",
  },
  {
    capability: "Delegation lineage",
    module: "Delegation module",
    status: "Implemented",
    keyCapabilities:
      "Grant issuance, subset enforcement, "
      + "scope enforcement, transitive revocation",
    verifiable:
      "Attenuation: child must be subset of parent. "
      + "Max depth 8. Transitive revocation cascades "
      + "to all descendants.",
  },
  {
    capability: "Hash-linked evidence chain",
    module: "Evidence chain module",
    status: "Implemented",
    keyCapabilities:
      "Chain append, chain verification, "
      + "integrity status reporting",
    verifiable:
      "Each hash includes the previous entry hash. "
      + "Verification recomputes every link. "
      + "Retry logic for concurrent operations.",
  },
  {
    capability: "Master security key",
    module: "Master key module",
    status: "Implemented",
    keyCapabilities:
      "Key file management, protected operation "
      + "registry, high-iteration key derivation",
    verifiable:
      "AES-256-GCM encryption. PBKDF2-SHA256 with "
      + "600K iterations. OS-level file permissions. "
      + "10 backup recovery codes.",
  },
  {
    capability: "Obligation enforcement",
    module: "Solver engine",
    status: "Implemented",
    keyCapabilities:
      "Obligation evaluation, MFA checks, "
      + "approval checks, preview confirmation",
    verifiable:
      "Three obligation types checked as theorem "
      + "predicate. Failure makes theorem unprovable. "
      + "Not bypassable.",
  },
  {
    capability: "Context binding",
    module: "Formal models module + Solver engine",
    status: "Implemented",
    keyCapabilities:
      "Context hashing, context-bound predicate "
      + "evaluation",
    verifiable:
      "Hash computed at capture time using SHA-256. "
      + "Predicate recomputes and compares at "
      + "evaluation time.",
  },
];

export default function EvidenceTable() {
  return (
    <div className="overflow-x-auto rounded-xl border border-border shadow-sm">
      <table className="min-w-[700px] w-full text-left text-xs">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            <th className="px-4 py-3 font-semibold text-foreground">
              Capability
            </th>
            <th className="px-3 py-3 font-semibold text-foreground">
              Module
            </th>
            <th className="px-3 py-3 font-semibold text-foreground">
              Status
            </th>
            <th className="px-3 py-3 font-semibold text-foreground">
              Key Capabilities
            </th>
            <th className="px-3 py-3 font-semibold text-foreground">
              What to Verify
            </th>
          </tr>
        </thead>
        <tbody>
          {EVIDENCE.map((row, idx) => (
            <tr
              key={row.capability}
              className={cn(
                "border-b border-border last:border-0",
                idx % 2 === 0 ? "bg-card/80" : "bg-card/40",
              )}
            >
              <td className="px-4 py-2.5 font-medium text-foreground">
                {row.capability}
              </td>
              <td className="px-3 py-2.5">
                <span className="text-[11px] text-primary/80">
                  {row.module}
                </span>
              </td>
              <td className="px-3 py-2.5 text-[11px] text-muted-foreground">
                {row.status}
              </td>
              <td className="max-w-[14rem] px-3 py-2.5 text-[11px] leading-snug text-muted-foreground">
                {row.keyCapabilities}
              </td>
              <td className="max-w-[16rem] px-3 py-2.5 text-[11px] leading-snug text-muted-foreground">
                {row.verifiable}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
