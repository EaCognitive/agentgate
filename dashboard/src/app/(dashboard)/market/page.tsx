"use client";

import React from "react";
import UseCaseGrid from "./_components/UseCaseGrid";
import MarketSizing from "./_components/MarketSizing";
import RevenueRoadmap from "./_components/RevenueRoadmap";
import ShowcaseNav from "../_components/ShowcaseNav";

/**
 * Market opportunity and business case page.
 * All figures sourced from published research reports.
 */
export default function MarketPage() {
  return (
    <div className="space-y-12">
      {/* Hero */}
      <div className="max-w-2xl">
        <h2 className="text-2xl font-bold text-foreground">
          Market Opportunity
        </h2>
        <p
          className={
            "mt-2 text-sm leading-relaxed "
            + "text-muted-foreground"
          }
        >
          AI agent governance is emerging as a critical
          infrastructure layer. All market data below is
          sourced from published research by Gartner,
          McKinsey, Grand View Research, Stanford HAI,
          and IBM. Revenue projections are derived
          bottom-up from pricing and customer targets.
        </p>
      </div>

      {/* Current Stage */}
      <div
        className={
          "rounded-xl border border-border "
          + "bg-card/80 p-5 shadow-sm"
        }
      >
        <h3
          className={
            "text-sm font-semibold text-foreground"
          }
        >
          Current Stage: Pre-Revenue / Product Built
        </h3>
        <p
          className={
            "mt-1 text-xs leading-relaxed "
            + "text-muted-foreground"
          }
        >
          AgentGate has a working product with formal
          verification (Z3), signed proof certificates,
          dual-solver drift detection, and a full
          dashboard. The codebase is tested and
          demonstrable. Next milestones: design partner
          recruitment, developer SDK release, and seed
          funding.
        </p>
      </div>

      {/* Use Cases by Vertical */}
      <section>
        <SectionHeader
          title="Use Cases by Vertical"
          subtitle={
            "Where AI agent governance creates measurable "
            + "value across regulated industries."
          }
        />
        <UseCaseGrid />
      </section>

      {/* TAM / SAM / SOM */}
      <section>
        <SectionHeader
          title="Market Sizing"
          subtitle={
            "Total addressable, serviceable, and obtainable "
            + "market based on published research."
          }
        />
        <MarketSizing />
      </section>

      {/* Revenue Roadmap */}
      <section>
        <SectionHeader
          title="Revenue Roadmap"
          subtitle={
            "Phased go-to-market with pricing tiers "
            + "and customer acquisition targets."
          }
        />
        <RevenueRoadmap />
      </section>

      <ShowcaseNav
        previousHref="/technical"
        previousLabel="Technical Deep Dive"
        nextHref="/verification"
        nextLabel="Next: Try Live Verification"
      />
    </div>
  );
}

function SectionHeader({
  title,
  subtitle,
}: {
  title: string;
  subtitle: string;
}) {
  return (
    <div className="mb-6">
      <h3
        className={
          "text-lg font-semibold text-foreground"
        }
      >
        {title}
      </h3>
      <p
        className={
          "mt-1 max-w-xl text-xs text-muted-foreground"
        }
      >
        {subtitle}
      </p>
    </div>
  );
}
