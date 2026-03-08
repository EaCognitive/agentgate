"use client";

import React from "react";
import CapabilityGrid from "./_components/CapabilityGrid";
import EvidenceTable from "./_components/EvidenceTable";
import RealWorldUseCases from "./_components/RealWorldUseCases";
import LiveDemo from "../_components/LiveDemo";
import ShowcaseNav from "../_components/ShowcaseNav";

/**
 * Technical deep dive page.
 * Presents every core capability with
 * technical evidence and real-world use cases.
 */
export default function TechnicalPage() {
  return (
    <div className="space-y-12">
      {/* Hero */}
      <div className="max-w-2xl">
        <h2 className="text-2xl font-bold text-foreground">
          Technical Deep Dive
        </h2>
        <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
          Every capability listed below is implemented and tested.
          Select any capability to see details and technical
          evidence.
        </p>
      </div>

      {/* Section: Live Demo */}
      <section>
        <SectionHeader
          title="Live Demo"
          subtitle={
            "Run a real-time formal verification "
            + "to see the system in action."
          }
        />
        <LiveDemo />
      </section>

      {/* Capabilities */}
      <section>
        <SectionHeader
          title="Core Capabilities"
          subtitle={
            "Each capability includes a description, the real-world "
            + "problem it solves, and technical evidence."
          }
        />
        <CapabilityGrid />
      </section>

      {/* Real-world use cases */}
      <section>
        <SectionHeader
          title="Real-World Use Cases"
          subtitle={
            "Concrete scenarios where these capabilities "
            + "translate to measurable business value."
          }
        />
        <RealWorldUseCases />
      </section>

      {/* Source evidence */}
      <section>
        <SectionHeader
          title="Implementation Evidence"
          subtitle={
            "Module-level implementation details "
            + "for independent verification."
          }
        />
        <EvidenceTable />
      </section>

      <ShowcaseNav
        previousHref="/architecture"
        previousLabel="Architecture Overview"
        nextHref="/market"
        nextLabel="Next: Market Opportunity"
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
      <h3 className="text-lg font-semibold text-foreground">
        {title}
      </h3>
      <p className="mt-1 max-w-xl text-xs text-muted-foreground">
        {subtitle}
      </p>
    </div>
  );
}
