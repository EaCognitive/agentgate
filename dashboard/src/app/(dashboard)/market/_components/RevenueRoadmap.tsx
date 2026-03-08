"use client";

import React from "react";
import { cn } from "@/lib/utils";
import {
  Rocket,
  TrendingUp,
  Building,
} from "lucide-react";

interface Phase {
  icon: React.ReactNode;
  year: string;
  name: string;
  arrTarget: string;
  pricing: string;
  customers: string;
  milestones: string[];
  accentColor: string;
}

const ICON_CLS = "h-5 w-5";

const PHASES: Phase[] = [
  {
    icon: <Rocket className={ICON_CLS} />,
    year: "Year 1 (2026-2027)",
    name: "Foundation and Design Partners",
    arrTarget: "$200K-$600K ARR",
    pricing:
      "Free community tier (metered) + managed "
      + "service at $2K-$5K/mo. Early adopter "
      + "discounts for design partners committing "
      + "to case studies.",
    customers:
      "5-10 design partners (paid), "
      + "50+ free-tier users",
    milestones: [
      "Developer SDK with MCP integration",
      "SOC 2 Type I certification",
      "3 published design partner case studies",
      "Seed round ($2-4M) to fund initial team",
    ],
    accentColor: "border-l-blue-500",
  },
  {
    icon: <TrendingUp className={ICON_CLS} />,
    year: "Year 2 (2027-2028)",
    name: "Product-Market Fit",
    arrTarget: "$1M-$3M ARR",
    pricing:
      "$5K-$15K/mo enterprise tier with SLA and "
      + "dedicated support. Volume pricing for "
      + "customers governing 100+ agents.",
    customers: "15-40 paying customers",
    milestones: [
      "SOC 2 Type II certification",
      "HIPAA BAA offering (Healthcare vertical)",
      "Series A ($8-12M) to fund GTM team",
      "Channel partnership with 1 cloud provider",
    ],
    accentColor: "border-l-green-500",
  },
  {
    icon: <Building className={ICON_CLS} />,
    year: "Year 3 (2028-2029)",
    name: "Growth",
    arrTarget: "$3.6M-$7.2M ARR",
    pricing:
      "$5K-$25K/mo standard tiers. Platform tier "
      + "at $25K-$50K/mo for customers requiring "
      + "distributed consensus and compliance "
      + "packages.",
    customers: "40-80 enterprise accounts",
    milestones: [
      "FedRAMP authorization process initiated",
      "Self-hosted enterprise deployment option",
      "ISO 42001 certification support",
      "Series B ($15-25M) for scale and expansion",
    ],
    accentColor: "border-l-primary",
  },
];

const PRICING_TIERS = [
  {
    name: "Community",
    price: "Free",
    features: [
      "Hosted free tier (metered)",
      "Single-solver evaluation",
      "Basic audit logging",
      "Community support",
    ],
  },
  {
    name: "Team",
    price: "$2,000-$5,000/mo",
    features: [
      "Managed cloud deployment",
      "Dual-solver drift detection",
      "Signed proof certificates",
      "Up to 50 governed agents",
    ],
  },
  {
    name: "Enterprise",
    price: "$5,000-$15,000/mo",
    features: [
      "Dedicated infrastructure",
      "Formal verification SLA",
      "SSO / SCIM / RBAC",
      "99.9% uptime SLA",
    ],
  },
  {
    name: "Platform",
    price: "$25,000-$50,000/mo",
    features: [
      "Distributed consensus nodes",
      "HIPAA / compliance packages",
      "Custom policy consulting",
      "24/7 dedicated support",
    ],
  },
];

/**
 * Phased revenue roadmap with pricing tiers.
 */
export default function RevenueRoadmap() {
  return (
    <div className="space-y-8">
      {/* Timeline */}
      <div className="space-y-4">
        {PHASES.map((phase) => (
          <div
            key={phase.year}
            className={cn(
              "rounded-xl border border-border",
              "border-l-4 bg-card/80 p-5",
              phase.accentColor,
            )}
          >
            <div
              className={
                "flex items-center justify-between"
              }
            >
              <div
                className="flex items-center gap-3"
              >
                <div
                  className={cn(
                    "flex h-10 w-10 items-center",
                    "justify-center rounded-lg",
                    "bg-primary/10 text-primary",
                  )}
                >
                  {phase.icon}
                </div>
                <div>
                  <h4
                    className={cn(
                      "text-sm font-semibold",
                      "text-foreground",
                    )}
                  >
                    {phase.year}
                  </h4>
                  <p
                    className={
                      "text-xs "
                      + "text-muted-foreground"
                    }
                  >
                    {phase.name}
                  </p>
                </div>
              </div>
              <span
                className={
                  "text-lg font-bold text-primary"
                }
              >
                {phase.arrTarget}
              </span>
            </div>

            <div
              className={
                "mt-4 grid gap-4 md:grid-cols-2"
              }
            >
              <div>
                <p
                  className={cn(
                    "text-[11px] font-medium",
                    "uppercase tracking-wider",
                    "text-muted-foreground/60",
                  )}
                >
                  Pricing
                </p>
                <p
                  className={cn(
                    "mt-1 text-xs",
                    "text-muted-foreground",
                  )}
                >
                  {phase.pricing}
                </p>
              </div>
              <div>
                <p
                  className={cn(
                    "text-[11px] font-medium",
                    "uppercase tracking-wider",
                    "text-muted-foreground/60",
                  )}
                >
                  Target Customers
                </p>
                <p
                  className={cn(
                    "mt-1 text-xs",
                    "text-muted-foreground",
                  )}
                >
                  {phase.customers}
                </p>
              </div>
            </div>

            <div className="mt-3">
              <p
                className={cn(
                  "text-[11px] font-medium",
                  "uppercase tracking-wider",
                  "text-muted-foreground/60",
                )}
              >
                Key Milestones
              </p>
              <ul className="mt-1.5 space-y-1">
                {phase.milestones.map((m) => (
                  <li
                    key={m}
                    className={cn(
                      "flex items-start gap-2",
                      "text-xs",
                      "text-muted-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "mt-1.5 h-1 w-1 shrink-0",
                        "rounded-full bg-primary/60",
                      )}
                    />
                    {m}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      {/* Pricing tiers */}
      <div>
        <h4
          className={cn(
            "mb-3 text-sm font-semibold",
            "text-foreground",
          )}
        >
          Pricing Tiers
        </h4>
        <div
          className={cn(
            "grid grid-cols-1 gap-3",
            "sm:grid-cols-2 lg:grid-cols-4",
          )}
        >
          {PRICING_TIERS.map((tier) => (
            <div
              key={tier.name}
              className={cn(
                "rounded-xl border border-border",
                "bg-card/80 p-4",
              )}
            >
              <h5
                className={cn(
                  "text-sm font-semibold",
                  "text-foreground",
                )}
              >
                {tier.name}
              </h5>
              <p
                className={cn(
                  "mt-1 text-lg font-bold",
                  "text-primary",
                )}
              >
                {tier.price}
              </p>
              <ul className="mt-3 space-y-1.5">
                {tier.features.map((f) => (
                  <li
                    key={f}
                    className={cn(
                      "flex items-start gap-2",
                      "text-xs",
                      "text-muted-foreground",
                    )}
                  >
                    <span
                      className={cn(
                        "mt-1.5 h-1 w-1 shrink-0",
                        "rounded-full bg-primary/60",
                      )}
                    />
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Competitive funding context */}
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
          Competitive Funding Context
        </h4>
        <p
          className={cn(
            "mt-1 text-xs text-muted-foreground",
          )}
        >
          Recent funding rounds in adjacent
          AI governance companies.
        </p>
        <div className="mt-3 space-y-2">
          <FundingRow
            company="Styra (OPA)"
            amount="$54-67M total"
            round="Series B, May 2021"
            note={
              "CNCF Graduated project, "
              + "75M+ downloads"
            }
          />
          <FundingRow
            company="Credo AI"
            amount="$41.3M total"
            round="2024 round, $101M valuation"
            note={
              "AI governance platform, "
              + "founded by Andrew Ng"
            }
          />
          <FundingRow
            company="AuthZed (SpiceDB)"
            amount="$15.9M total"
            round="$12M in April 2024"
            note={
              "Serves OpenAI ChatGPT Enterprise"
            }
          />
          <FundingRow
            company="Guardrails AI"
            amount="$7.5M seed"
            round="February 2024"
            note={
              "LLM reliability, backed by "
              + "Ian Goodfellow"
            }
          />
        </div>
      </div>
    </div>
  );
}

function FundingRow({
  company,
  amount,
  round,
  note,
}: {
  company: string;
  amount: string;
  round: string;
  note: string;
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
          {company}
        </p>
        <p
          className={
            "text-[10px] "
            + "text-muted-foreground/60"
          }
        >
          {round} -- {note}
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
