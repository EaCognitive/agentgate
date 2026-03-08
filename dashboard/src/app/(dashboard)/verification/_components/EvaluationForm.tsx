"use client";

import React, { useState } from "react";
import type { AdmissibilityResponse } from "@/types/index";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  ChevronDown,
  ChevronRight,
  Loader2,
  Play,
} from "lucide-react";

interface EvaluationFormProps {
  onResult: (data: AdmissibilityResponse) => void;
  onError: (msg: string) => void;
  onSubmit?: () => void;
}

interface PresetScenario {
  label: string;
  description: string;
  principal: string;
  action: string;
  resource: string;
  context: Record<string, unknown>;
}

const PRESET_SCENARIOS: PresetScenario[] = [
  {
    label: "Authorized Read",
    description:
      "Agent reads database -- should be admitted",
    principal: "demo-agent",
    action: "read",
    resource: "database/users",
    context: { authenticated: true },
  },
  {
    label: "Destructive Action",
    description:
      "Agent deletes records -- should be denied",
    principal: "demo-agent",
    action: "delete",
    resource: "database/users",
    context: { authenticated: true },
  },
  {
    label: "External API Write",
    description:
      "Agent writes to API -- may require approval",
    principal: "demo-agent",
    action: "write",
    resource: "api/external-service",
    context: { authenticated: true },
  },
  {
    label: "Unauthenticated Agent",
    description:
      "Missing authentication -- should fail",
    principal: "unknown-agent",
    action: "read",
    resource: "database/users",
    context: { authenticated: false },
  },
];

const ACTION_OPTIONS = ["read", "write", "execute", "delete"];

const DEFAULT_CONTEXT = JSON.stringify(
  { authenticated: true },
  null,
  2,
);

/**
 * Input form for submitting an action to formal verification.
 */
export default function EvaluationForm({
  onResult,
  onError,
  onSubmit,
}: EvaluationFormProps) {
  const [principal, setPrincipal] = useState("demo-agent");
  const [action, setAction] = useState("read");
  const [resource, setResource] = useState("database/users");
  const [contextJson, setContextJson] = useState(DEFAULT_CONTEXT);
  const [contextOpen, setContextOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  const applyPreset = (preset: PresetScenario) => {
    setPrincipal(preset.principal);
    setAction(preset.action);
    setResource(preset.resource);
    setContextJson(
      JSON.stringify(preset.context, null, 2),
    );
    setContextOpen(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    onError("");
    onSubmit?.();

    let parsedContext: Record<string, unknown> = {};
    try {
      parsedContext = JSON.parse(contextJson);
    } catch {
      onError("Invalid JSON in runtime context");
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(
        "/api/security/admissibility/evaluate",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            principal,
            action,
            resource,
            runtime_context: parsedContext,
          }),
        },
      );

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        onError(
          errData.error
          || errData.detail
          || `Server error: ${res.status}`,
        );
        setLoading(false);
        return;
      }

      const data: AdmissibilityResponse = await res.json();
      onResult(data);
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Network error",
      );
    } finally {
      setLoading(false);
    }
  };

  const inputClass = cn(
    "w-full rounded-lg border border-border bg-background px-3 py-2",
    "text-sm text-foreground placeholder:text-muted-foreground",
    "transition-colors",
    "focus:outline-none focus:ring-2 focus:ring-primary/40",
    "focus:border-primary/40",
  );

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Preset scenarios */}
      <div className="grid grid-cols-2 gap-2">
        {PRESET_SCENARIOS.map((preset) => (
          <button
            key={preset.label}
            type="button"
            onClick={() => applyPreset(preset)}
            className={cn(
              "rounded-lg border border-border",
              "p-2.5 text-left",
              "transition-colors",
              "hover:border-primary/30",
              "hover:bg-primary/5",
            )}
          >
            <p
              className={cn(
                "text-xs font-medium",
                "text-foreground",
              )}
            >
              {preset.label}
            </p>
            <p
              className={cn(
                "mt-0.5 text-[11px] leading-snug",
                "text-muted-foreground",
              )}
            >
              {preset.description}
            </p>
          </button>
        ))}
      </div>

      {/* Divider */}
      <div className="flex items-center gap-3">
        <div className="h-px flex-1 bg-border" />
        <span
          className={cn(
            "text-[11px] text-muted-foreground",
          )}
        >
          or configure manually
        </span>
        <div className="h-px flex-1 bg-border" />
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-foreground">
          Principal
        </label>
        <input
          type="text"
          value={principal}
          onChange={(e) => setPrincipal(e.target.value)}
          className={inputClass}
          placeholder="demo-agent"
          required
        />
        <p className="mt-1 text-[11px] text-muted-foreground/70">
          The agent or user requesting the action.
        </p>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-foreground">
          Action
        </label>
        <select
          value={action}
          onChange={(e) => setAction(e.target.value)}
          className={inputClass}
        >
          {ACTION_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
        <p className="mt-1 text-[11px] text-muted-foreground/70">
          The operation to perform on the resource.
        </p>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-foreground">
          Resource
        </label>
        <input
          type="text"
          value={resource}
          onChange={(e) => setResource(e.target.value)}
          className={inputClass}
          placeholder="database/users"
          required
        />
        <p className="mt-1 text-[11px] text-muted-foreground/70">
          The target resource path (e.g. database/users).
        </p>
      </div>

      <div>
        <button
          type="button"
          onClick={() => setContextOpen(!contextOpen)}
          className={cn(
            "flex items-center gap-1 text-sm",
            "font-medium text-muted-foreground",
            "hover:text-foreground",
          )}
        >
          {contextOpen ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
          Runtime Context (JSON)
        </button>
        {contextOpen && (
          <textarea
            value={contextJson}
            onChange={(e) => setContextJson(e.target.value)}
            rows={4}
            className={cn(inputClass, "mt-2 font-mono text-xs")}
          />
        )}
      </div>

      <Button
        type="submit"
        disabled={loading}
        size="sm"
        className="w-full gap-2"
      >
        {loading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Play className="h-4 w-4" />
        )}
        Run Verification
      </Button>
    </form>
  );
}
