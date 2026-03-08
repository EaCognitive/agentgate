import React from "react";
import {
  Play,
  Loader2,
  AlertTriangle,
  FileText,
  CheckCircle,
  XCircle,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type {
  PolicyListResponse,
  EvaluatePolicyResponse,
} from "@/types/policy";
import { SELECT_CLASS } from "../_constants";

export interface EvaluateTabProps {
  dbPolicies: PolicyListResponse["db_policies"];
  evalPolicyId: string;
  setEvalPolicyId: (v: string) => void;
  evalContext: string;
  setEvalContext: (v: string) => void;
  evalResult: EvaluatePolicyResponse | null;
  setEvalResult: (v: EvaluatePolicyResponse | null) => void;
  onEvaluate: () => void;
  evalPending: boolean;
  evalError: string | null;
}

export default function EvaluateTab({
  dbPolicies,
  evalPolicyId,
  setEvalPolicyId,
  evalContext,
  setEvalContext,
  evalResult,
  setEvalResult,
  onEvaluate,
  evalPending,
  evalError,
}: EvaluateTabProps) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Play className="h-5 w-5" />
            Evaluate Policy
          </CardTitle>
          <CardDescription>
            Test a policy against a request context
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5">
              Policy Set
            </label>
            <select
              value={evalPolicyId}
              onChange={(e) =>
                setEvalPolicyId(e.target.value)
              }
              className={`w-full ${SELECT_CLASS}`}
            >
              <option value="">
                Default (first loaded)
              </option>
              {dbPolicies.map((p) => (
                <option
                  key={p.policy_set_id}
                  value={p.policy_set_id}
                >
                  {p.policy_set_id} (v{p.version})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">
              Request Context (JSON)
            </label>
            <textarea
              value={evalContext}
              onChange={(e) =>
                setEvalContext(e.target.value)
              }
              className={
                "w-full h-48 rounded-lg border border-border " +
                "bg-background px-4 py-3 font-mono text-sm " +
                "focus:border-primary focus:outline-none " +
                "focus:ring-1 focus:ring-primary resize-none"
              }
              placeholder={
                '{"user_role": "agent", "action": "read"}'
              }
            />
          </div>
          <div className="flex gap-2">
            <Button
              onClick={onEvaluate}
              disabled={evalPending}
            >
              {evalPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-2 h-4 w-4" />
              )}
              Evaluate
            </Button>
            {evalResult && (
              <Button
                variant="ghost"
                onClick={() => setEvalResult(null)}
              >
                Clear
              </Button>
            )}
          </div>
          {evalError && (
            <div className="flex items-center gap-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4" />
              {evalError}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Evaluation Result
          </CardTitle>
          <CardDescription>
            Policy decision and matched rules
          </CardDescription>
        </CardHeader>
        <CardContent>
          {evalPending ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : evalResult ? (
            <EvaluationResultDisplay result={evalResult} />
          ) : (
            <div className="flex h-64 flex-col items-center justify-center text-center text-muted-foreground">
              <Play className="mb-2 h-12 w-12 opacity-30" />
              <p>Run an evaluation</p>
              <p className="text-xs">
                Results will appear here
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/* ------------------------------------------------------------ */
/*  Evaluation Result Display                                    */
/* ------------------------------------------------------------ */

function EvaluationResultDisplay({
  result,
}: {
  result: EvaluatePolicyResponse;
}) {
  return (
    <div className="space-y-4">
      <div
        className={`rounded-lg p-4 ${
          result.allowed
            ? "bg-success-50 border border-success-200"
            : "bg-danger-50 border border-danger-200"
        }`}
      >
        <div className="flex items-center gap-3">
          {result.allowed ? (
            <CheckCircle className="h-8 w-8 text-success" />
          ) : (
            <XCircle className="h-8 w-8 text-danger" />
          )}
          <div>
            <p className="text-lg font-semibold">
              {result.allowed ? "ALLOWED" : "DENIED"}
            </p>
            <p className="text-sm text-muted-foreground">
              Effect: {result.effect}
            </p>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <div className="rounded-lg bg-muted/30 p-3">
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Reason
          </p>
          <p className="text-sm">{result.reason}</p>
        </div>
        <div className="rounded-lg bg-muted/30 p-3">
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Policy Set
          </p>
          <p className="text-sm font-mono">
            {result.policy_set_id}
          </p>
        </div>
        {result.matched_rules.length > 0 && (
          <div className="rounded-lg bg-muted/30 p-3">
            <p className="text-xs font-medium text-muted-foreground mb-2">
              Matched Rules
            </p>
            <div className="flex flex-wrap gap-1.5">
              {result.matched_rules.map((r) => (
                <Badge key={r} variant="outline">
                  {r}
                </Badge>
              ))}
            </div>
          </div>
        )}
        <div className="rounded-lg bg-muted/30 p-3">
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Evaluation Time
          </p>
          <p className="text-sm">
            {result.evaluation_time_ms.toFixed(2)} ms
          </p>
        </div>
      </div>
    </div>
  );
}
