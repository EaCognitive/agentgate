"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import {
  MessageCircleQuestion,
  ChevronDown,
} from "lucide-react";

interface QA {
  question: string;
  answer: string;
}

const QUESTIONS: QA[] = [
  {
    question:
      "AWS announced AgentCore Policy with Cedar at re:Invent 2025. "
      + "It intercepts tool calls, uses Cedar policies, and is "
      + "MCP-native. Why not just use that?",
    answer:
      "AgentCore Policy is a real competitor and the overlap is "
      + "genuine -- it does real-time tool call interception, "
      + "Cedar policy evaluation, default deny, and MCP integration. "
      + "The gap is in what happens after the evaluation. Cedar "
      + "returns allow/deny and the reasoning is discarded. AgentGate "
      + "produces a signed cryptographic certificate per decision with "
      + "hash-bound inputs (action context, policy state, theorem). "
      + "Cedar Analysis uses SMT to verify that policies are sound "
      + "(static, done once when policies change). AgentGate uses Z3 "
      + "to verify that each individual decision is correct at runtime "
      + "(per-request, with a proof artifact). These are different "
      + "problems. Cedar answers 'are my policies consistent?' "
      + "AgentGate answers 'was this specific decision provably "
      + "correct, and here is the tamper-evident proof.'",
  },
  {
    question:
      "Is there anything genuinely novel here, or is this "
      + "a reimplementation of existing tools?",
    answer:
      "Three things no shipping product does. First: per-decision "
      + "signed proof certificates. Every authorization product "
      + "returns a boolean. AgentGate returns a boolean plus a "
      + "cryptographic artifact that binds the decision to the exact "
      + "inputs and policies evaluated -- verifiable independently "
      + "without trusting the system that issued it. Second: "
      + "dual-solver drift detection. Two independent evaluation "
      + "engines must agree on every decision. This is N-version "
      + "programming applied to authorization, and no policy engine "
      + "does it. Third: honey-token deception integrated into the "
      + "authorization path. Canary resources detect compromised "
      + "agents before damage occurs. This category does not exist "
      + "in Cedar, OPA, or Zanzibar.",
  },
  {
    question:
      "What real-world problem does a signed certificate solve "
      + "that logging does not?",
    answer:
      "A log entry says 'decision X happened at time T.' "
      + "A certificate says 'decision X was mathematically derived "
      + "from policies P using theorem T, given action context A, "
      + "and here is the signature you can verify.' Logs can be "
      + "modified after the fact -- even CloudTrail entries live in "
      + "S3. A certificate with hash-bound inputs breaks if anything "
      + "is altered. This matters concretely in three scenarios: "
      + "a regulator asks you to prove a decision was correct (you "
      + "hand them the certificate, not a log query); a breach "
      + "investigation needs to confirm the authz system was "
      + "functioning correctly (tamper-evident certificates vs. "
      + "mutable logs); and a multi-agent delegation chain needs "
      + "post-hoc verification that no agent escalated beyond its "
      + "delegated scope.",
  },
  {
    question:
      "OPA/Rego is battle-tested at massive scale. Cedar has "
      + "Amazon behind it. Why would anyone choose this?",
    answer:
      "OPA is excellent for Kubernetes admission control and API "
      + "authorization. Cedar is excellent for fine-grained "
      + "permissions in web applications. Both are strong at what "
      + "they were built for. Neither was built for the threat model "
      + "of autonomous AI agents making thousands of tool calls "
      + "per minute, delegating to sub-agents, and requiring "
      + "formally verifiable decision trails for compliance. "
      + "The question is not OPA vs. AgentGate -- it is whether "
      + "the AI agent governance problem requires capabilities "
      + "(per-decision proofs, delegation lineage, deception "
      + "detection) that policy engines were never designed to "
      + "provide. If your use case is API authorization, use Cedar "
      + "or OPA. If your use case is governing autonomous AI agents "
      + "with auditable proof trails, that is a different product "
      + "category.",
  },
  {
    question:
      "Guardrails AI and NeMo Guardrails already handle AI safety. "
      + "How is this different?",
    answer:
      "Guardrails AI and NeMo filter what an LLM says -- they "
      + "validate inputs and outputs of the language model. AgentGate "
      + "governs what an AI agent does -- it evaluates tool calls "
      + "against a formal theorem before execution. When an agent "
      + "calls a tool to write to a database or invoke an API, "
      + "Guardrails AI has no opinion because that is not its scope. "
      + "These are complementary systems. Guardrails AI governs "
      + "language. AgentGate governs actions.",
  },
];

/**
 * FAQ-style accordion addressing real competitive questions.
 */
export default function HardQuestions() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  return (
    <div className="space-y-4">
      {QUESTIONS.map((qa, idx) => {
        const isOpen = openIndex === idx;
        return (
          <div
            key={qa.question}
            className={cn(
              "rounded-xl border bg-card/80",
              "shadow-sm transition-colors",
              isOpen
                ? "border-primary/20"
                : "border-border",
            )}
          >
            <button
              type="button"
              onClick={() =>
                setOpenIndex(isOpen ? null : idx)
              }
              className={
                "flex w-full items-start gap-3 "
                + "p-5 text-left"
              }
            >
              <MessageCircleQuestion
                className={
                  "mt-0.5 h-5 w-5 shrink-0 text-primary"
                }
              />
              <p
                className={
                  "flex-1 text-sm font-semibold "
                  + "leading-snug text-foreground"
                }
              >
                &ldquo;{qa.question}&rdquo;
              </p>
              <ChevronDown
                className={cn(
                  "mt-0.5 h-4 w-4 shrink-0",
                  "text-muted-foreground",
                  "transition-transform duration-200",
                  isOpen && "rotate-180",
                )}
              />
            </button>
            {isOpen && (
              <div
                className={
                  "border-t border-border "
                  + "px-5 pb-5 pt-3"
                }
              >
                <p
                  className={
                    "pl-8 text-xs leading-relaxed "
                    + "text-muted-foreground"
                  }
                >
                  {qa.answer}
                </p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
