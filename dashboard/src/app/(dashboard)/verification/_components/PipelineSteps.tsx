"use client";

import React, { useEffect, useState } from "react";
import type { AdmissibilityResponse } from "@/types/index";
import { cn } from "@/lib/utils";
import {
  Radio,
  Shield,
  KeyRound,
  SearchCheck,
  Scale,
  Cpu,
  FileCheck2,
} from "lucide-react";

interface PipelineStepsProps {
  /** null = idle, "running" = in-flight, response = completed. */
  result: AdmissibilityResponse | null;
  running: boolean;
}

interface StageDefinition {
  key: string;
  label: string;
  description: string;
  icon: React.ReactNode;
}

const ICON_SIZE = "h-3.5 w-3.5";

const STAGES: StageDefinition[] = [
  {
    key: "intercept",
    label: "Intercept",
    description: "MCP tool call received by governance layer.",
    icon: <Radio className={ICON_SIZE} />,
  },
  {
    key: "guardrails",
    label: "Guardrails",
    description: "Execution policy, rate limits, and blocked-ops check.",
    icon: <Shield className={ICON_SIZE} />,
  },
  {
    key: "auth",
    label: "Auth",
    description: "Principal identity and session verified.",
    icon: <KeyRound className={ICON_SIZE} />,
  },
  {
    key: "deception",
    label: "Deception",
    description: "Honey-token canary check before evaluation.",
    icon: <SearchCheck className={ICON_SIZE} />,
  },
  {
    key: "formal",
    label: "Formal",
    description: "Six-predicate admissibility theorem evaluated.",
    icon: <Scale className={ICON_SIZE} />,
  },
  {
    key: "z3",
    label: "Z3",
    description: "Independent theorem prover cross-verification.",
    icon: <Cpu className={ICON_SIZE} />,
  },
  {
    key: "certificate",
    label: "Cert",
    description: "Decision cryptographically signed and persisted.",
    icon: <FileCheck2 className={ICON_SIZE} />,
  },
];

/**
 * Derives a short status label from the API response for each stage.
 */
function stageStatus(
  key: string,
  data: AdmissibilityResponse,
): string {
  const cert = data.certificate;
  const solver = data.runtime_solver
    || cert.proof_payload.runtime_solver;
  const predicates =
    cert.proof_payload.constructive_trace
    || cert.proof_payload.trace
    || [];

  switch (key) {
    case "intercept":
      return "OK";
    case "guardrails":
      return "OK";
    case "auth":
      return predicates.find((p) => p.predicate === "AuthValid")?.value
        ? "OK"
        : "Fail";
    case "deception":
      return "Clear";
    case "formal": {
      const passed = predicates.filter((p) => {
        if (p.predicate === "DenyExists") {
          return !p.value;
        }
        return p.value;
      }).length;
      return `${passed}/${predicates.length}`;
    }
    case "z3":
      if (!solver) {
        return "Skip";
      }
      if (solver.drift_detected) {
        return "Drift";
      }
      return solver.z3_result === null
        ? "Off"
        : solver.z3_result
          ? "OK"
          : "Fail";
    case "certificate":
      return cert.signature ? "Signed" : "N/A";
    default:
      return "";
  }
}

/**
 * Horizontal pipeline showing each governance stage.
 * Stages reveal with staggered animation after results arrive.
 * Fully responsive -- no horizontal scrollbar.
 */
export default function PipelineSteps({
  result,
  running,
}: PipelineStepsProps) {
  const [visibleCount, setVisibleCount] = useState(0);

  useEffect(() => {
    if (!result) {
      return;
    }
    let step = 0;
    const tick = () => {
      setVisibleCount(step);
      step += 1;
      if (step <= STAGES.length) {
        timerId = window.setTimeout(tick, 150);
      }
    };
    let timerId = window.setTimeout(tick, 0);
    return () => window.clearTimeout(timerId);
  }, [result]);

  const isAdmissible = result
    ? result.certificate.result.toUpperCase() === "ADMISSIBLE"
    : false;

  return (
    <div className="rounded-xl border border-border bg-card/80 px-3 py-4 shadow-sm sm:px-4">
      <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Governance Pipeline
      </p>
      <p className="mb-4 text-xs text-muted-foreground">
        Every action traverses seven stages before a decision is
        issued. Hover a stage for details.
      </p>

      {/* Stage row -- horizontal scroll on mobile, grid on desktop */}
      <div className="flex gap-3 overflow-x-auto pb-2 snap-x sm:grid sm:grid-cols-7 sm:gap-1 sm:overflow-visible sm:pb-0">
        {STAGES.map((stage, idx) => {
          const lit = idx < visibleCount;
          const status = result
            ? stageStatus(stage.key, result)
            : "";

          return (
            <div
              key={stage.key}
              className="group relative flex min-w-[4.5rem] snap-center flex-col items-center sm:min-w-0"
              title={stage.description}
            >
              {/* Connector line (before icon, except first) */}
              {idx > 0 && (
                <div
                  className={cn(
                    "hidden sm:block",
                    "absolute left-0 top-3",
                    "h-px w-full -translate-x-1/2",
                    "transition-colors duration-300",
                    lit
                      ? isAdmissible
                        ? "bg-success"
                        : "bg-danger"
                      : "bg-border",
                  )}
                />
              )}

              {/* Icon circle -- uses inline style for
                  the opaque fill so twMerge cannot strip
                  it when dark: overrides are present. */}
              <div
                className={cn(
                  "relative z-10 flex h-7 w-7",
                  "items-center justify-center",
                  "rounded-full border-2",
                  "transition-all duration-300",
                  !lit && running
                    && "animate-pulse",
                  !lit && !running
                    && "text-muted-foreground/60",
                  lit
                    ? isAdmissible
                      ? "border-success bg-success text-white"
                      : "border-danger bg-danger text-white"
                    : "border-border bg-background",
                )}
              >
                {stage.icon}
              </div>

              {/* Label */}
              <span
                className={cn(
                  "mt-1.5 text-center text-[10px] font-semibold leading-tight",
                  "transition-colors duration-300",
                  lit ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {stage.label}
              </span>

              {/* Status */}
              {lit && status && (
                <span
                  className={cn(
                    "mt-0.5 text-center text-[9px] font-bold",
                    isAdmissible
                      ? "text-success"
                      : "text-danger",
                  )}
                >
                  {status}
                </span>
              )}

              {/* Tooltip on hover */}
              <div
                className={cn(
                  "pointer-events-none absolute top-full z-20 mt-1",
                  "left-1/2 -translate-x-1/2",
                  "w-max max-w-[12rem] rounded-md border border-border",
                  "bg-popover px-2.5 py-1.5 text-center shadow-md",
                  "text-[11px] leading-snug text-popover-foreground",
                  "opacity-0 transition-opacity group-hover:opacity-100",
                )}
              >
                <span className="font-semibold">{stage.label}</span>
                <br />
                {stage.description}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
