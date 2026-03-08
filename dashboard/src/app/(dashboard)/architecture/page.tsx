"use client";

import React from "react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import ArchitecturePipeline from "./_components/ArchitecturePipeline";
import DifferentiatorGrid from "./_components/DifferentiatorGrid";
import ComparisonTable from "./_components/ComparisonTable";
import HardQuestions from "./_components/HardQuestions";
import LiveDemo from "../_components/LiveDemo";
import ShowcaseNav from "../_components/ShowcaseNav";

/**
 * Architecture showcase page for investor/stakeholder demos.
 * Presents the full governance pipeline, market differentiation,
 * and a link to the interactive verification page.
 */
export default function ArchitecturePage() {
  return (
    <div className="space-y-12">
      {/* Hero */}
      <div className="max-w-2xl">
        <h2 className="text-2xl font-bold text-foreground">
          How AgentGate Governs AI Agents
        </h2>
        <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
          Every tool call from an AI agent passes through a
          seven-stage governance pipeline before execution.
          Unlike policy engines (Cedar, OPA) or LLM guardrails,
          AgentGate uses formal mathematical verification backed by
          an SMT theorem prover and produces cryptographically signed
          decision certificates for every action.
        </p>
        <div className="mt-4">
          <Link href="/verification">
            <Button variant="outline" size="sm" className="gap-2">
              Try interactive verification
              <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
        </div>
      </div>

      {/* Section: Live Demo */}
      <section>
        <SectionHeader
          title="Live Demo"
          subtitle={
            "Run a real verification against the "
            + "governance pipeline."
          }
        />
        <LiveDemo />
      </section>

      {/* Section: Why MCP Governance */}
      <section>
        <SectionHeader
          title="Why MCP Governance Matters"
          subtitle={
            "The Model Context Protocol is becoming the "
            + "standard interface between AI agents and "
            + "the tools they use."
          }
        />
        <div className="grid gap-4 md:grid-cols-2">
          <div
            className={
              "rounded-xl border border-border "
              + "bg-card/80 p-5"
            }
          >
            <h4
              className={
                "text-sm font-semibold text-foreground"
              }
            >
              What MCP Is
            </h4>
            <p
              className={
                "mt-2 text-xs leading-relaxed "
                + "text-muted-foreground"
              }
            >
              The Model Context Protocol (MCP) is an open
              standard that lets AI agents call external
              tools -- databases, APIs, file systems, SaaS
              products. When an AI agent needs to read
              customer data, execute a trade, or modify a
              record, it does so through MCP tool calls.
              Major providers including Anthropic, OpenAI,
              and Google are converging on this protocol.
            </p>
          </div>
          <div
            className={
              "rounded-xl border border-border "
              + "bg-card/80 p-5"
            }
          >
            <h4
              className={
                "text-sm font-semibold text-foreground"
              }
            >
              The Governance Gap
            </h4>
            <p
              className={
                "mt-2 text-xs leading-relaxed "
                + "text-muted-foreground"
              }
            >
              Today, most AI governance operates at the
              input/output layer -- filtering what an LLM
              says. But the real risk is what an AI agent
              does: the tool calls it executes. Guardrails
              AI and NeMo filter text. Cedar and OPA
              evaluate policies. Neither governs the
              actual tool execution lifecycle with formal
              proof that the decision was correct.
            </p>
          </div>
          <div
            className={
              "rounded-xl border border-border "
              + "bg-card/80 p-5"
            }
          >
            <h4
              className={
                "text-sm font-semibold text-foreground"
              }
            >
              Why Runtime Verification
            </h4>
            <p
              className={
                "mt-2 text-xs leading-relaxed "
                + "text-muted-foreground"
              }
            >
              Static policy checks happen once at deploy
              time. Runtime verification happens on every
              tool call, producing a mathematical proof
              that the decision was correct at that exact
              moment with that exact context. If the
              context changes between check and execution,
              the proof breaks. This is the difference
              between a locked door and a guard who checks
              credentials on every entry.
            </p>
          </div>
          <div
            className={
              "rounded-xl border border-border "
              + "bg-card/80 p-5"
            }
          >
            <h4
              className={
                "text-sm font-semibold text-foreground"
              }
            >
              The Timing Advantage
            </h4>
            <p
              className={
                "mt-2 text-xs leading-relaxed "
                + "text-muted-foreground"
              }
            >
              MCP adoption is early-stage. Gartner
              predicts 40% of enterprise apps will have
              AI agents by 2026. The governance layer for
              these agents does not exist yet. Building
              the verified governance standard while the
              protocol is still forming creates a
              structural moat -- the same way Datadog
              became the standard for cloud observability
              during the early cloud migration wave.
            </p>
          </div>
        </div>
      </section>

      {/* Section: Pipeline */}
      <section>
        <SectionHeader
          title="The Governance Pipeline"
          subtitle={
            "Every MCP tool call traverses these seven stages. "
            + "Failure at any stage results in an immediate "
            + "rejection with a signed proof of why."
          }
        />
        <ArchitecturePipeline />
      </section>

      {/* Section: FAQ */}
      <section>
        <SectionHeader
          title="Frequently Asked Questions"
          subtitle={
            "Common questions about how AgentGate compares "
            + "to existing solutions."
          }
        />
        <HardQuestions />
      </section>

      {/* Section: Differentiators */}
      <section>
        <SectionHeader
          title="Key Differentiators"
          subtitle={
            "Six architectural properties that distinguish "
            + "AgentGate from existing policy engines."
          }
        />
        <DifferentiatorGrid />
      </section>

      {/* Section: Comparison Table */}
      <section>
        <SectionHeader
          title="Feature Comparison"
          subtitle={
            "AgentGate vs. Cedar (AWS), OPA/Rego (CNCF), "
            + "Zanzibar/SpiceDB (Google), and Guardrails AI / NeMo."
          }
        />
        <ComparisonTable />
      </section>

      <ShowcaseNav
        nextHref="/technical"
        nextLabel="Next: Technical Deep Dive"
      />
    </div>
  );
}

/**
 * Reusable section heading with title and subtitle.
 */
function SectionHeader({
  title,
  subtitle,
}: {
  title: string;
  subtitle: string;
}) {
  return (
    <div className="mb-6">
      <h3 className="text-lg font-semibold text-foreground">
        {title}
      </h3>
      <p className="mt-1 max-w-xl text-xs text-muted-foreground">
        {subtitle}
      </p>
    </div>
  );
}
