"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import {
  Fingerprint,
  ShieldCheck,
  GitFork,
  Eye,
  Binary,
  KeyRound,
  FileSearch,
  FlaskConical,
  Network,
  Scroll,
  UserCheck,
  Lock,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

type CapabilityCategory =
  | "verification"
  | "security"
  | "governance";

interface Capability {
  icon: React.ReactNode;
  title: string;
  what: string;
  problem: string;
  evidence: string;
  comparison: string;
  demoLink?: string;
  category: CapabilityCategory;
}

const ICON_CLS = "h-5 w-5";

const CAPABILITIES: Capability[] = [
  {
    icon: <Fingerprint className={ICON_CLS} />,
    title: "Signed Proof Certificates",
    what:
      "Every authorization decision produces an Ed25519-signed "
      + "certificate binding three SHA-256 hashes: the action "
      + "context (alpha), the policy state (gamma), and the "
      + "theorem formula. The certificate is independently "
      + "verifiable without trusting the issuing system.",
    problem:
      "When a regulator or auditor asks \"prove this AI agent was "
      + "authorized to perform this action,\" every existing system "
      + "answers with a log file. Logs can be modified after the fact. "
      + "A signed certificate with hash-bound inputs breaks if "
      + "anything is altered. This is the difference between "
      + "'we logged it' and 'here is tamper-proof mathematical evidence.'",
    evidence:
      "Ed25519 signing module with SHA-256 hash binding. "
      + "Certificate generation integrated into the core "
      + "evaluation pipeline. Each certificate binds three "
      + "independent hashes to a single signature.",
    comparison:
      "Cedar, OPA, and Zanzibar return a boolean allow/deny. "
      + "No cryptographic artifact is produced. CloudTrail records "
      + "events to S3 -- mutable storage, not tamper-evident proof.",
    demoLink: "/verification",
    category: "verification",
  },
  {
    icon: <Binary className={ICON_CLS} />,
    title: "Formal Verification (Z3 Theorem Prover)",
    what:
      "Decisions are derived from a six-predicate admissibility "
      + "theorem evaluated by an SMT solver. Each decision is a "
      + "mathematical proof, not a boolean from a rule engine. "
      + "The solver mode is configurable: off, shadow (log-only), "
      + "or enforce (blocking).",
    problem:
      "A rule engine can have bugs that silently return wrong "
      + "answers. A formal proof is independently verifiable -- "
      + "if the proof checks out, the decision was correct by "
      + "construction. Shadow mode enables gradual rollout without "
      + "all-or-nothing risk.",
    evidence:
      "Six-predicate admissibility theorem with configurable "
      + "solver modes (off, shadow, enforce). Runtime constraint "
      + "binding with dedicated healthcheck subsystem.",
    comparison:
      "Cedar Analysis uses SMT to verify policies are sound "
      + "(static, done once at deploy time). AgentGate uses Z3 to "
      + "verify each individual decision is correct (per-request, "
      + "runtime, with a proof artifact). Different problems.",
    demoLink: "/verification",
    category: "verification",
  },
  {
    icon: <ShieldCheck className={ICON_CLS} />,
    title: "Dual-Solver Drift Detection",
    what:
      "Two independent evaluation engines (Python and Z3) must "
      + "agree on every decision. If the results diverge, the "
      + "system fails closed immediately and raises an alert. "
      + "This is N-version programming applied to authorization.",
    problem:
      "A single evaluator has no way to detect its own bugs. "
      + "If Cedar's evaluator has a logic error, the wrong decision "
      + "is emitted silently. With two independent solvers, "
      + "disagreement is detected before it becomes a security "
      + "incident.",
    evidence:
      "Independent Python and Z3 evaluation paths with "
      + "automatic drift detection. Fail-closed on disagreement "
      + "with metrics recording for post-incident analysis.",
    comparison:
      "No policy engine runs two independent evaluators. Cedar, "
      + "OPA, and Zanzibar each use a single evaluation path.",
    demoLink: "/verification",
    category: "verification",
  },
  {
    icon: <FileSearch className={ICON_CLS} />,
    title: "Counterfactual Plan Verification",
    what:
      "Before an AI agent executes any step, the system can "
      + "evaluate an entire multi-step plan (5-30 steps based on "
      + "risk tier) against the admissibility theorem. Returns "
      + "which step would fail and why -- before any execution.",
    problem:
      "An AI financial advisor generates a 15-trade rebalancing "
      + "plan. Without counterfactual verification, it executes "
      + "trades 1 through 14 before discovering trade 15 is "
      + "blocked. With it, the entire plan is verified upfront. "
      + "No wasted computation, no partial execution to roll back.",
    evidence:
      "Risk-tiered plan verification supporting 5-30 step "
      + "plans. Returns the specific step that would fail and "
      + "a counterexample explaining why.",
    comparison:
      "No policy engine offers pre-execution plan verification. "
      + "Each request is evaluated in isolation.",
    category: "security",
  },
  {
    icon: <Network className={ICON_CLS} />,
    title: "Distributed Consensus (N-of-M Co-Signing)",
    what:
      "Multiple independent SafetyNodes must co-sign admissibility "
      + "decisions via quorum-based verification. If the primary "
      + "server says ADMISSIBLE but the quorum disagrees, a global "
      + "revocation broadcast goes out to all nodes.",
    problem:
      "If a single authorization server is compromised, all "
      + "decisions it issues are suspect. With N-of-M co-signing, "
      + "even a fully compromised primary cannot unilaterally "
      + "authorize actions. This is multi-sig for authorization.",
    evidence:
      "Quorum-based co-signing with configurable node "
      + "topology. Includes global revocation broadcast and "
      + "append-only transparency log.",
    comparison:
      "Cedar, OPA, and Zanzibar are single-evaluator architectures. "
      + "No distributed consensus mechanism exists.",
    category: "governance",
  },
  {
    icon: <FlaskConical className={ICON_CLS} />,
    title: "Property-Based Policy Synthesis",
    what:
      "Automated fuzzing engine that runs up to 100,000 randomized "
      + "test cases against the policy set, discovering four types "
      + "of anomalies: instabilities (same input yields different "
      + "results), surprising admits, surprising denies, and "
      + "boundary cases. Generates DTSL rule proposals.",
    problem:
      "Policy authors introduce contradictions they cannot see. "
      + "'We added a new rule and three weeks later discovered it "
      + "conflicted with an existing rule -- after a production "
      + "incident.' Synthesis finds these before deployment.",
    evidence:
      "Automated fuzzing engine with configurable iteration "
      + "counts (10K-100K). Discovers four anomaly classes: "
      + "instabilities, surprising admits, surprising denies, "
      + "and boundary cases.",
    comparison:
      "Cedar has static analysis via SMT. OPA has unit test "
      + "support. Neither does automated randomized discovery "
      + "of policy contradictions.",
    category: "governance",
  },
  {
    icon: <Eye className={ICON_CLS} />,
    title: "Honey-Token Deception Detection",
    what:
      "Admin-planted canary resources (tools, credentials, data "
      + "stores) detect compromised agents through behavioral traps. "
      + "Four token types: TOOL, RESOURCE, CREDENTIAL, DATA_STORE. "
      + "Three graduated responses: flag-only, downgrade trust, "
      + "suspend all grants.",
    problem:
      "Rule engines are reactive -- they wait for a known bad "
      + "action. Honey-tokens detect compromised agents proactively "
      + "by observing behavior against resources no legitimate "
      + "agent should access. Trust is progressively degraded, "
      + "not binary on/off.",
    evidence:
      "Four token types with three graduated response levels. "
      + "Trust degradation cascades transitively through "
      + "delegation chains.",
    comparison:
      "This category does not exist in Cedar, OPA, Zanzibar, "
      + "or Guardrails AI. Deception detection is an entirely "
      + "absent concept in policy engines.",
    category: "security",
  },
  {
    icon: <GitFork className={ICON_CLS} />,
    title: "Delegation Lineage with Attenuation",
    what:
      "Agents delegate to sub-agents with strictly attenuated "
      + "permissions. Attenuation is enforced: child actions must "
      + "be a subset of parent actions, child scope must be within "
      + "parent scope. Maximum depth of 8 hops. Revocation cascades "
      + "transitively to all descendants.",
    problem:
      "Agent A delegates to Agent B who delegates to Agent C. "
      + "Without attenuation enforcement, Agent C could escalate "
      + "beyond Agent A's original permissions. Without transitive "
      + "revocation, revoking Agent B's access leaves Agent C "
      + "still active.",
    evidence:
      "Subset and scope attenuation enforcement on every "
      + "delegation. Transitive revocation cascades to all "
      + "descendants. Maximum configurable delegation depth.",
    comparison:
      "Cedar and OPA model static roles. Zanzibar/SpiceDB has "
      + "relationship-based ACLs but no delegation attenuation "
      + "or transitive revocation for agent-to-agent chains.",
    category: "governance",
  },
  {
    icon: <Scroll className={ICON_CLS} />,
    title: "Hash-Linked Evidence Chain",
    what:
      "Every decision is appended to an immutable evidence chain "
      + "where each entry's hash includes the previous entry's hash "
      + "(blockchain-style linking). Offline verification recomputes "
      + "every hash to detect tampering. Counterexample traces are "
      + "separately persisted.",
    problem:
      "Audit logs in a database can be modified by anyone with "
      + "write access. A hash-linked chain breaks if any entry is "
      + "altered, inserted, or deleted. This provides cryptographic "
      + "proof that the audit trail has not been tampered with.",
    evidence:
      "SHA-256 chain linking with offline verification "
      + "support. Retry logic for concurrent append "
      + "operations. Each entry includes the previous "
      + "entry hash.",
    comparison:
      "CloudTrail and similar services store events in mutable "
      + "object stores. No policy engine produces a hash-linked "
      + "evidence chain with offline verification.",
    category: "governance",
  },
  {
    icon: <Lock className={ICON_CLS} />,
    title: "Master Security Key (Physical Gate)",
    what:
      "Destructive operations (delete all users, drop tables, "
      + "disable security, export all PII) require a physical "
      + "key file encrypted with AES-256-GCM, derived via PBKDF2 "
      + "with 600,000 iterations. File permissions enforced at "
      + "OS level (chmod 600). Backup codes for recovery.",
    problem:
      "A compromised server with root access could drop every "
      + "database table. The master key creates a physical security "
      + "gate: even with full server access, catastrophic operations "
      + "require a file that does not exist on the server by default. "
      + "No AI agent can override this.",
    evidence:
      "AES-256-GCM encrypted key file with high-iteration "
      + "key derivation. OS-level file permission enforcement. "
      + "Backup code recovery system.",
    comparison:
      "Standard RBAC systems protect operations with permissions. "
      + "Permissions can be escalated. A filesystem key file cannot "
      + "be escalated through the application layer.",
    category: "security",
  },
  {
    icon: <UserCheck className={ICON_CLS} />,
    title: "Obligations as Theorem Predicates",
    what:
      "Human approval, MFA verification, and preview-confirmation "
      + "are predicates in the formal admissibility theorem "
      + "(ObligationsMet). They are not optional middleware checks "
      + "-- they are part of the mathematical proof. If obligations "
      + "are not met, the theorem is unprovable.",
    problem:
      "In most systems, 'require approval' is an if-statement "
      + "in middleware that can be accidentally bypassed during "
      + "refactoring. When obligations are part of a formal theorem, "
      + "there is no code path that can skip them -- the proof "
      + "literally cannot be constructed.",
    evidence:
      "MFA, approval, and preview-confirmation are formal "
      + "predicates in the admissibility theorem. The proof "
      + "cannot be constructed if obligations are unmet.",
    comparison:
      "Cedar and OPA evaluate conditions in policy rules. "
      + "Conditions can be misconfigured. Neither integrates "
      + "obligations into a formal proof structure.",
    category: "verification",
  },
  {
    icon: <KeyRound className={ICON_CLS} />,
    title: "Context Binding (Anti-Manipulation)",
    what:
      "The runtime context (authentication status, MFA state, "
      + "execution phase) is hashed at capture time. The "
      + "ContextBound predicate verifies the hash has not changed "
      + "between capture and evaluation. If context is modified "
      + "after hashing, the predicate fails.",
    problem:
      "An attacker could modify the context between when it was "
      + "captured and when the decision is made -- claiming "
      + "'authenticated=true' in the proof while actually executing "
      + "with 'authenticated=false'. Hash commitment prevents this "
      + "class of attack entirely.",
    evidence:
      "Context hashed at capture time using SHA-256. The "
      + "ContextBound predicate recomputes and compares the "
      + "hash at evaluation time. Any modification invalidates "
      + "the proof.",
    comparison:
      "No policy engine binds the decision context with a "
      + "cryptographic commitment. Context is trusted implicitly.",
    demoLink: "/verification",
    category: "verification",
  },
];

const TAB_OPTIONS: {
  value: "all" | CapabilityCategory;
  label: string;
  count: number;
}[] = [
  {
    value: "all",
    label: "All",
    count: CAPABILITIES.length,
  },
  {
    value: "verification",
    label: "Verification",
    count: CAPABILITIES.filter(
      (c) => c.category === "verification",
    ).length,
  },
  {
    value: "security",
    label: "Security",
    count: CAPABILITIES.filter(
      (c) => c.category === "security",
    ).length,
  },
  {
    value: "governance",
    label: "Governance",
    count: CAPABILITIES.filter(
      (c) => c.category === "governance",
    ).length,
  },
];

function CapabilityCard({ item }: { item: Capability }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
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
        {item.what}
      </p>

      {/* Expandable detail */}
      <button
        onClick={() => setExpanded(!expanded)}
        className={cn(
          "mt-3 flex w-full items-center gap-1 text-[11px]",
          "font-medium text-primary/80 hover:text-primary",
        )}
      >
        {expanded ? (
          <>
            Less detail
            <ChevronUp className="h-3 w-3" />
          </>
        ) : (
          <>
            Details and evidence
            <ChevronDown className="h-3 w-3" />
          </>
        )}
      </button>

      {expanded && (
        <div className="mt-3 space-y-3 border-t border-border pt-3">
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/60">
              Real-world problem
            </p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {item.problem}
            </p>
          </div>
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/60">
              vs. existing solutions
            </p>
            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
              {item.comparison}
            </p>
          </div>
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/60">
              Technical evidence
            </p>
            <p className="mt-1 font-mono text-[11px] leading-relaxed text-muted-foreground/80">
              {item.evidence}
            </p>
          </div>
          {item.demoLink && (
            <div className="mt-2">
              <a
                href={item.demoLink}
                className={
                  "text-[11px] font-medium "
                  + "text-primary hover:underline"
                }
              >
                Try it live &rarr;
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function CapabilityGrid() {
  const [activeTab, setActiveTab] = useState<
    "all" | CapabilityCategory
  >("all");

  const filtered =
    activeTab === "all"
      ? CAPABILITIES
      : CAPABILITIES.filter(
          (c) => c.category === activeTab,
        );

  return (
    <div>
      <div className="mb-4 flex gap-2">
        {TAB_OPTIONS.map((tab) => (
          <button
            key={tab.value}
            type="button"
            onClick={() => setActiveTab(tab.value)}
            className={cn(
              "rounded-lg px-3 py-1.5",
              "text-xs font-medium",
              "transition-colors",
              activeTab === tab.value
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground "
                  + "hover:bg-muted",
            )}
          >
            {tab.label} ({tab.count})
          </button>
        ))}
      </div>
      <div
        className={
          "grid grid-cols-1 gap-4 "
          + "md:grid-cols-2 lg:grid-cols-3"
        }
      >
        {filtered.map((item) => (
          <CapabilityCard
            key={item.title}
            item={item}
          />
        ))}
      </div>
    </div>
  );
}
