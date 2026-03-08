"use client";

import React from "react";
import { cn } from "@/lib/utils";
import {
  Landmark,
  HeartPulse,
  Building2,
  ShieldAlert,
} from "lucide-react";

interface Vertical {
  icon: React.ReactNode;
  name: string;
  marketSize: string;
  marketSource: string;
  regulations: string[];
  useCase: string;
  painPoint: string;
}

const ICON_CLS = "h-5 w-5";

const VERTICALS: Vertical[] = [
  {
    icon: <Landmark className={ICON_CLS} />,
    name: "Financial Services",
    marketSize: "$38.4B AI in Finance (2024)",
    marketSource: "MarketsandMarkets",
    regulations: [
      "SOX",
      "Basel III",
      "MiFID II",
      "SEC AI Guidance",
    ],
    useCase:
      "Automated trading agents require provably correct "
      + "authorization for every transaction. Signed "
      + "decision certificates satisfy SOX audit "
      + "requirements without manual documentation.",
    painPoint:
      "Securities class actions targeting AI "
      + "misrepresentations increased 100% between "
      + "2023 and 2024. (NYSBA)",
  },
  {
    icon: <HeartPulse className={ICON_CLS} />,
    name: "Healthcare",
    marketSize:
      "$6.9B AI Agents in Healthcare by 2030",
    marketSource: "MarketsandMarkets",
    regulations: [
      "HIPAA",
      "FDA AI/ML Guidance",
      "PCCP",
      "21st Century Cures Act",
    ],
    useCase:
      "Clinical AI agents accessing PHI must have "
      + "cryptographic audit trails. Formal verification "
      + "ensures every data access decision is provably "
      + "compliant before execution.",
    painPoint:
      "FDA has authorized over 1,250 AI-enabled medical "
      + "devices as of 2025. Each requires governance "
      + "controls. (FDA/IntuitionLabs)",
  },
  {
    icon: <Building2 className={ICON_CLS} />,
    name: "Enterprise SaaS",
    marketSize:
      "$41.8B Enterprise Agentic AI by 2030",
    marketSource: "Grand View Research",
    regulations: [
      "SOC 2 Type II",
      "ISO 27001",
      "ISO 42001",
      "GDPR",
    ],
    useCase:
      "AI agents in customer support, code generation, "
      + "and data pipelines need auditable governance. "
      + "Dual-solver drift detection catches silent "
      + "policy evaluation errors in production.",
    painPoint:
      "40% of enterprise apps will feature AI agents "
      + "by 2026, up from less than 5% in 2025. "
      + "(Gartner, August 2025)",
  },
  {
    icon: <ShieldAlert className={ICON_CLS} />,
    name: "Government and Defense",
    marketSize:
      "$13.4B Defense AI spending by 2026",
    marketSource: "CCS Global Tech / NDAA",
    regulations: [
      "FedRAMP",
      "NIST AI RMF",
      "CMMC 2.0",
      "OMB AI Guidance",
    ],
    useCase:
      "Federal AI deployments require FedRAMP-authorized "
      + "infrastructure with formal risk documentation. "
      + "Signed proof certificates provide the "
      + "cryptographic audit trail NIST AI RMF demands.",
    painPoint:
      "Federal AI budget reached $3.3B in FY2025. "
      + "DoD launched a $100M AI Rapid Capabilities "
      + "Cell. (Federal Budget IQ)",
  },
];

/**
 * Grid of vertical use cases with market data.
 */
export default function UseCaseGrid() {
  return (
    <div
      className={
        "grid grid-cols-1 gap-4 md:grid-cols-2"
      }
    >
      {VERTICALS.map((v) => (
        <div
          key={v.name}
          className={cn(
            "rounded-xl border border-border",
            "bg-card/80 p-5 shadow-sm",
            "transition-colors",
            "hover:border-primary/30 hover:bg-card",
          )}
        >
          <div
            className={cn(
              "mb-3 flex h-10 w-10 items-center",
              "justify-center rounded-lg",
              "bg-primary/10 text-primary",
            )}
          >
            {v.icon}
          </div>
          <h3
            className={
              "text-sm font-semibold text-foreground"
            }
          >
            {v.name}
          </h3>
          <p
            className={cn(
              "mt-1 text-xs font-medium",
              "text-primary/80",
            )}
          >
            {v.marketSize}
          </p>
          <p
            className={
              "text-[10px] text-muted-foreground/50"
            }
          >
            Source: {v.marketSource}
          </p>

          {/* Regulations */}
          <div className="mt-3 flex flex-wrap gap-1">
            {v.regulations.map((reg) => (
              <span
                key={reg}
                className={cn(
                  "rounded-md bg-muted/50 px-2 py-0.5",
                  "text-[10px] font-medium",
                  "text-muted-foreground",
                )}
              >
                {reg}
              </span>
            ))}
          </div>

          {/* Use case */}
          <p
            className={cn(
              "mt-3 text-xs leading-relaxed",
              "text-muted-foreground",
            )}
          >
            {v.useCase}
          </p>

          {/* Pain point */}
          <div
            className={cn(
              "mt-3 border-t border-border pt-3",
            )}
          >
            <p
              className={cn(
                "text-[11px] italic leading-relaxed",
                "text-muted-foreground/70",
              )}
            >
              {v.painPoint}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
