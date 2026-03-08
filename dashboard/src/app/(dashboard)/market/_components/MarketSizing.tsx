"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface MarketTier {
  label: string;
  name: string;
  size2024: string;
  size2030: string;
  cagr: string;
  source: string;
  description: string;
  widthPct: string;
  color: string;
}

const TIERS: MarketTier[] = [
  {
    label: "TAM",
    name: "AI Trust, Risk and Security Management",
    size2024: "$2.34B (2024)",
    size2030: "$7.44B",
    cagr: "21.6%",
    source: "Grand View Research, 2024",
    description:
      "The full AI TRiSM market as defined by "
      + "Gartner, covering model monitoring, AI "
      + "firewalls, governance platforms, and risk "
      + "management tooling.",
    widthPct: "w-full",
    color: "bg-primary/20 border-primary/40",
  },
  {
    label: "SAM",
    name: "AI Governance Software",
    size2024: "$228M (2024)",
    size2030: "$1.42B",
    cagr: "35.7%",
    source: "Grand View Research, 2024",
    description:
      "Policy engines, compliance automation, and "
      + "governance platforms for AI systems. This "
      + "is the narrow market AgentGate directly "
      + "competes in. Broader agentic AI governance "
      + "estimates ($7B+, Mordor Intelligence) "
      + "include consulting and GRC tooling outside "
      + "our scope.",
    widthPct: "w-3/4",
    color: "bg-info-100 border-info-200",
  },
  {
    label: "SOM",
    name: "Bottom-Up: Year 3 Target",
    size2024: "$3.6M-$7.2M ARR",
    size2030: "Scaling with SAM",
    cagr: "Bottom-up model",
    source:
      "40-80 customers at $90K avg ACV "
      + "(see Revenue Roadmap below)",
    description:
      "Derived bottom-up: enterprise customers "
      + "requiring formally verified authorization "
      + "for AI agents. At $90K average annual "
      + "contract value with 40-80 accounts by "
      + "Year 3, this represents ~0.5-1% of the "
      + "SAM -- consistent with early-stage SaaS "
      + "capture rates.",
    widthPct: "w-1/2",
    color: "bg-success-100 border-success-200",
  },
];

const KEY_STATS = [
  {
    value: "62%",
    label:
      "of organizations experimenting with AI agents",
    source: "McKinsey, Nov 2025",
  },
  {
    value: "40%+",
    label:
      "of agentic AI projects may be canceled by 2027",
    source: "Gartner, June 2025",
  },
  {
    value: "80%",
    label:
      "AI project failure rate (2x traditional IT)",
    source: "RAND Corporation, 2024",
  },
  {
    value: "11%",
    label:
      "have fully implemented responsible AI",
    source: "Stanford HAI, 2025",
  },
  {
    value: "$4.44M",
    label:
      "average cost of a data breach in 2025",
    source: "IBM / Ponemon, 2025",
  },
  {
    value: "59",
    label:
      "new AI regulations issued by U.S. agencies "
      + "in 2024",
    source: "Stanford HAI AI Index, 2025",
  },
];

/**
 * TAM/SAM/SOM market sizing visualization
 * with supporting industry statistics.
 */
export default function MarketSizing() {
  return (
    <div className="space-y-8">
      {/* Funnel */}
      <div className="space-y-4">
        {TIERS.map((tier) => (
          <div
            key={tier.label}
            className={cn(
              tier.widthPct,
              "mx-auto rounded-xl border p-5",
              tier.color,
              "transition-all",
            )}
          >
            <div
              className={
                "flex items-baseline justify-between"
              }
            >
              <div
                className="flex items-center gap-2"
              >
                <span
                  className={cn(
                    "rounded-md bg-background/50",
                    "px-2 py-0.5 text-xs",
                    "font-bold text-foreground",
                  )}
                >
                  {tier.label}
                </span>
                <h4
                  className={
                    "text-sm font-semibold "
                    + "text-foreground"
                  }
                >
                  {tier.name}
                </h4>
              </div>
            </div>
            <div className="mt-2 flex gap-6">
              <div>
                <p
                  className={
                    "text-xs "
                    + "text-muted-foreground/60"
                  }
                >
                  Current
                </p>
                <p
                  className={
                    "text-lg font-bold "
                    + "text-foreground"
                  }
                >
                  {tier.size2024}
                </p>
              </div>
              <div>
                <p
                  className={
                    "text-xs "
                    + "text-muted-foreground/60"
                  }
                >
                  2030 Projected
                </p>
                <p
                  className={
                    "text-lg font-bold "
                    + "text-foreground"
                  }
                >
                  {tier.size2030}
                </p>
              </div>
              <div>
                <p
                  className={
                    "text-xs "
                    + "text-muted-foreground/60"
                  }
                >
                  CAGR
                </p>
                <p
                  className={
                    "text-lg font-bold text-primary"
                  }
                >
                  {tier.cagr}
                </p>
              </div>
            </div>
            <p
              className={cn(
                "mt-2 text-xs leading-relaxed",
                "text-muted-foreground",
              )}
            >
              {tier.description}
            </p>
            <p
              className={cn(
                "mt-1 text-[10px]",
                "text-muted-foreground/50",
              )}
            >
              Source: {tier.source}
            </p>
          </div>
        ))}
      </div>

      {/* Key stats grid */}
      <div>
        <h4
          className={cn(
            "mb-3 text-sm font-semibold",
            "text-foreground",
          )}
        >
          Why Now: Industry Inflection Points
        </h4>
        <div
          className={
            "grid grid-cols-2 gap-3 md:grid-cols-3"
          }
        >
          {KEY_STATS.map((stat) => (
            <div
              key={stat.value}
              className={cn(
                "rounded-lg border border-border",
                "bg-card/80 p-4",
              )}
            >
              <p
                className={
                  "text-2xl font-bold text-primary"
                }
              >
                {stat.value}
              </p>
              <p
                className={cn(
                  "mt-1 text-xs leading-snug",
                  "text-muted-foreground",
                )}
              >
                {stat.label}
              </p>
              <p
                className={cn(
                  "mt-1 text-[10px]",
                  "text-muted-foreground/50",
                )}
              >
                {stat.source}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* M&A signal */}
      <div
        className={cn(
          "rounded-xl border border-border",
          "bg-card/80 p-5",
        )}
      >
        <h4
          className={cn(
            "text-sm font-semibold",
            "text-foreground",
          )}
        >
          Recent M&A Activity
        </h4>
        <p
          className={cn(
            "mt-1 text-xs",
            "text-muted-foreground",
          )}
        >
          Validating market demand for AI security
          infrastructure.
        </p>
        <div className="mt-3 space-y-2">
          <AcquisitionRow
            acquirer="Palo Alto Networks"
            target="Protect AI"
            amount="~$650-700M"
            date="July 2025"
            detail="Now powers Prisma AIRS"
          />
          <AcquisitionRow
            acquirer="Cisco"
            target="Robust Intelligence"
            amount="~$400M"
            date="August 2024"
            detail="Now powers Cisco AI Defense"
          />
        </div>
      </div>
    </div>
  );
}

function AcquisitionRow({
  acquirer,
  target,
  amount,
  date,
  detail,
}: {
  acquirer: string;
  target: string;
  amount: string;
  date: string;
  detail: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-between",
        "rounded-lg bg-muted/30 px-4 py-2.5",
      )}
    >
      <div>
        <p
          className={
            "text-xs font-medium text-foreground"
          }
        >
          {acquirer} acquired {target}
        </p>
        <p
          className={
            "text-[10px] text-muted-foreground/60"
          }
        >
          {date} -- {detail}
        </p>
      </div>
      <span
        className={
          "text-sm font-bold text-primary"
        }
      >
        {amount}
      </span>
    </div>
  );
}
