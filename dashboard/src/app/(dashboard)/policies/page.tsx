"use client";

import React, { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Plus,
  Play,
  Lock,
  CheckCircle,
  FileText,
  Layers,
} from "lucide-react";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import type {
  PolicyListResponse,
  PolicyCondition,
  PolicyRule,
  PolicyJsonDocument,
  EvaluatePolicyResponse,
  PolicyDetailResponse,
} from "@/types/policy";
import PolicyListTab from "./_components/PolicyListTab";
import CreatePolicyTab from "./_components/CreatePolicyTab";
import EvaluateTab from "./_components/EvaluateTab";
import PolicyDetailModal from "./_components/PolicyDetailModal";

async function fetchPolicies(): Promise<PolicyListResponse> {
  const res = await fetch("/api/policies");
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

function emptyCondition(): PolicyCondition {
  return { field: "", operator: "eq", value: "" };
}

function emptyRule(): PolicyRule {
  return {
    rule_id: `rule_${Date.now()}`,
    effect: "deny",
    description: "",
    priority: 100,
    conditions: [emptyCondition()],
  };
}

function freshForm(): PolicyJsonDocument {
  return {
    policy_set_id: "",
    version: "1.0",
    description: "",
    default_effect: "deny",
    rules: [emptyRule()],
  };
}

export default function PoliciesPage() {
  return (
    <Suspense>
      <PoliciesPageInner />
    </Suspense>
  );
}

function PoliciesPageInner() {
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const initialTab = searchParams.get("tab");
  const [activeTab, setActiveTab] = useState<
    "list" | "create" | "evaluate"
  >(
    initialTab === "create" || initialTab === "evaluate"
      ? initialTab
      : "list",
  );
  const { data: policies, isLoading } = useQuery({
    queryKey: ["policies"],
    queryFn: fetchPolicies,
    staleTime: 15000,
  });

  const [createForm, setCreateForm] = useState(freshForm);
  const [evalPolicyId, setEvalPolicyId] = useState("");
  const [evalContext, setEvalContext] = useState("{\n  \n}");
  const [evalResult, setEvalResult] =
    useState<EvaluatePolicyResponse | null>(null);
  const [viewPolicyId, setViewPolicyId] = useState<
    string | null
  >(null);
  const [deleteConfirm, setDeleteConfirm] = useState<
    string | null
  >(null);

  // --- Mutations ---

  const createMutation = useMutation({
    mutationFn: async (doc: PolicyJsonDocument) => {
      const res = await fetch("/api/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ policy_json: doc }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.detail || err.error || "Failed to create policy",
        );
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      setCreateForm(freshForm());
      setActiveTab("list");
    },
  });

  const loadMutation = useMutation({
    mutationFn: async (id: string) => {
      const encoded = encodeURIComponent(id);
      const res = await fetch(`/api/policies/${encoded}/load`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to load policy");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const lockMutation = useMutation({
    mutationFn: async (args: { id: string; locked: boolean }) => {
      const encoded = encodeURIComponent(args.id);
      const res = await fetch(`/api/policies/${encoded}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ locked: args.locked }),
      });
      if (!res.ok) throw new Error("Failed to update policy");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const encoded = encodeURIComponent(id);
      const res = await fetch(`/api/policies/${encoded}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to delete policy");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      setDeleteConfirm(null);
    },
  });

  const activateMutation = useMutation({
    mutationFn: async (dbId: number) => {
      const res = await fetch(
        `/api/policies/${dbId}/activate`,
        { method: "POST" },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.detail || err.error || "Failed to activate policy",
        );
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: async (dbId: number) => {
      const res = await fetch(
        `/api/policies/${dbId}/deactivate`,
        { method: "POST" },
      );
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.detail || err.error
            || "Failed to deactivate policy",
        );
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const evaluateMutation = useMutation({
    mutationFn: async () => {
      let ctx: Record<string, unknown>;
      try {
        ctx = JSON.parse(evalContext);
      } catch {
        throw new Error("Invalid JSON in request context");
      }
      const res = await fetch("/api/policies/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          policy_set_id: evalPolicyId || null,
          request_context: ctx,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(
          err.detail || err.error || "Evaluation failed",
        );
      }
      return res.json();
    },
    onSuccess: (data: EvaluatePolicyResponse) => {
      setEvalResult(data);
    },
  });

  const {
    data: viewPolicyDetail,
    isLoading: detailLoading,
    error: detailError,
  } = useQuery({
    queryKey: ["policy-detail", viewPolicyId],
    queryFn: async () => {
      if (!viewPolicyId) return null;
      const encoded = encodeURIComponent(viewPolicyId);
      const res = await fetch(
        `/api/policies/${encoded}/detail`,
      );
      if (!res.ok) {
        throw new Error(
          "Failed to fetch policy detail",
        );
      }
      return res.json() as Promise<PolicyDetailResponse>;
    },
    enabled: !!viewPolicyId,
  });

  // --- Derived data ---

  const dbPolicies = policies?.db_policies || [];
  const loadedIds = new Set(policies?.loaded_policies || []);
  const totalCount = dbPolicies.length;
  const loadedCount = dbPolicies.filter((p) =>
    loadedIds.has(p.policy_set_id),
  ).length;
  const lockedCount = dbPolicies.filter((p) => p.locked).length;

  // --- Rule builder helpers ---

  const addRule = () => {
    setCreateForm((prev) => ({
      ...prev,
      rules: [...prev.rules, emptyRule()],
    }));
  };

  const removeRule = (idx: number) => {
    setCreateForm((prev) => ({
      ...prev,
      rules: prev.rules.filter((_, i) => i !== idx),
    }));
  };

  const updateRule = (
    idx: number,
    updates: Partial<PolicyRule>,
  ) => {
    setCreateForm((prev) => ({
      ...prev,
      rules: prev.rules.map((r, i) =>
        i === idx ? { ...r, ...updates } : r,
      ),
    }));
  };

  const addCondition = (ruleIdx: number) => {
    setCreateForm((prev) => ({
      ...prev,
      rules: prev.rules.map((r, i) =>
        i === ruleIdx
          ? { ...r, conditions: [...r.conditions, emptyCondition()] }
          : r,
      ),
    }));
  };

  const removeCondition = (ruleIdx: number, condIdx: number) => {
    setCreateForm((prev) => ({
      ...prev,
      rules: prev.rules.map((r, i) =>
        i === ruleIdx
          ? {
              ...r,
              conditions: r.conditions.filter(
                (_, j) => j !== condIdx,
              ),
            }
          : r,
      ),
    }));
  };

  const updateCondition = (
    ruleIdx: number,
    condIdx: number,
    updates: Partial<PolicyCondition>,
  ) => {
    setCreateForm((prev) => ({
      ...prev,
      rules: prev.rules.map((r, i) =>
        i === ruleIdx
          ? {
              ...r,
              conditions: r.conditions.map((c, j) =>
                j === condIdx ? { ...c, ...updates } : c,
              ),
            }
          : r,
      ),
    }));
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">Policy Engine</h1>
          <p className="text-muted-foreground">
            Declarative policy-as-code rules for AI governance
          </p>
        </div>
        <Button size="sm" onClick={() => setActiveTab("create")}>
          <Plus className="mr-2 h-4 w-4" />
          Create Policy
        </Button>
      </div>

      {/* Stats */}
      <Card>
        <CardContent className="py-0">
          <div
            className={
              "grid grid-cols-2 sm:grid-cols-4 divide-y"
              + " sm:divide-y-0 sm:divide-x divide-border"
            }
          >
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <Layers className="h-3.5 w-3.5 text-info" />
              <p className="text-lg font-semibold tabular-nums">
                {isLoading ? "..." : totalCount}
              </p>
              <p className="text-xs text-muted-foreground">
                Total Policies
              </p>
            </div>
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <CheckCircle
                className="h-3.5 w-3.5 text-success"
              />
              <p className="text-lg font-semibold tabular-nums">
                {isLoading ? "..." : loadedCount}
              </p>
              <p className="text-xs text-muted-foreground">
                Loaded (Active)
              </p>
            </div>
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <Lock className="h-3.5 w-3.5 text-warning" />
              <p className="text-lg font-semibold tabular-nums">
                {isLoading ? "..." : lockedCount}
              </p>
              <p className="text-xs text-muted-foreground">
                Locked
              </p>
            </div>
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <FileText className="h-3.5 w-3.5 text-info" />
              <p className="text-lg font-semibold tabular-nums">
                {isLoading
                  ? "..."
                  : dbPolicies.reduce(
                      (sum, p) => sum + (p.rule_count || 0),
                      0,
                    )}
              </p>
              <p className="text-xs text-muted-foreground">
                Total Rules
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-border pb-2">
        <Button
          variant={activeTab === "list" ? "primary" : "ghost"}
          size="sm"
          onClick={() => setActiveTab("list")}
        >
          <FileText className="mr-2 h-4 w-4" />
          All Policies
        </Button>
        <Button
          variant={activeTab === "create" ? "primary" : "ghost"}
          size="sm"
          onClick={() => setActiveTab("create")}
        >
          <Plus className="mr-2 h-4 w-4" />
          Create
        </Button>
        <Button
          variant={activeTab === "evaluate" ? "primary" : "ghost"}
          size="sm"
          onClick={() => setActiveTab("evaluate")}
        >
          <Play className="mr-2 h-4 w-4" />
          Evaluate
        </Button>
      </div>

      {/* Policy List Tab */}
      {activeTab === "list" && (
        <PolicyListTab
          dbPolicies={dbPolicies}
          loadedIds={loadedIds}
          isLoading={isLoading}
          deleteConfirm={deleteConfirm}
          setDeleteConfirm={setDeleteConfirm}
          onView={(id) => setViewPolicyId(id)}
          onLoad={(id) => loadMutation.mutate(id)}
          onLock={(id, locked) =>
            lockMutation.mutate({ id, locked })
          }
          onDelete={(id) => deleteMutation.mutate(id)}
          onActivate={(dbId) => activateMutation.mutate(dbId)}
          onDeactivate={(dbId) => deactivateMutation.mutate(dbId)}
          actionPending={
            loadMutation.isPending ||
            lockMutation.isPending ||
            deleteMutation.isPending ||
            activateMutation.isPending ||
            deactivateMutation.isPending
          }
          activateError={
            activateMutation.isError
              ? (activateMutation.error as Error).message
              : null
          }
          deactivateError={
            deactivateMutation.isError
              ? (deactivateMutation.error as Error).message
              : null
          }
          onCreateClick={() => setActiveTab("create")}
        />
      )}

      {/* Create Tab */}
      {activeTab === "create" && (
        <CreatePolicyTab
          form={createForm}
          setForm={setCreateForm}
          onSubmit={(doc) => createMutation.mutate(doc)}
          submitPending={createMutation.isPending}
          submitError={
            createMutation.isError
              ? (createMutation.error as Error).message
              : null
          }
          onCancel={() => setActiveTab("list")}
          addRule={addRule}
          removeRule={removeRule}
          updateRule={updateRule}
          addCondition={addCondition}
          removeCondition={removeCondition}
          updateCondition={updateCondition}
        />
      )}

      {/* Evaluate Tab */}
      {activeTab === "evaluate" && (
        <EvaluateTab
          dbPolicies={dbPolicies}
          evalPolicyId={evalPolicyId}
          setEvalPolicyId={setEvalPolicyId}
          evalContext={evalContext}
          setEvalContext={setEvalContext}
          evalResult={evalResult}
          setEvalResult={setEvalResult}
          onEvaluate={() => evaluateMutation.mutate(undefined)}
          evalPending={evaluateMutation.isPending}
          evalError={
            evaluateMutation.isError
              ? (evaluateMutation.error as Error).message
              : null
          }
        />
      )}

      {viewPolicyId && (
        <PolicyDetailModal
          policy={viewPolicyDetail ?? null}
          isLoading={detailLoading}
          error={
            detailError
              ? (detailError as Error).message
              : null
          }
          onClose={() => setViewPolicyId(null)}
        />
      )}
    </div>
  );
}
