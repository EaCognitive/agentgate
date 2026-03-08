import React from "react";
import {
  Plus,
  Loader2,
  AlertTriangle,
  Shield,
  Trash2,
  X,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import type {
  PolicyJsonDocument,
  PolicyRule,
  PolicyCondition,
  PolicyEffect,
  PolicyOperator,
} from "@/types/policy";
import {
  OPERATORS,
  INPUT_CLASS,
  SELECT_CLASS,
} from "../_constants";

export interface CreatePolicyTabProps {
  form: PolicyJsonDocument;
  setForm: React.Dispatch<
    React.SetStateAction<PolicyJsonDocument>
  >;
  onSubmit: (doc: PolicyJsonDocument) => void;
  submitPending: boolean;
  submitError: string | null;
  onCancel: () => void;
  addRule: () => void;
  removeRule: (idx: number) => void;
  updateRule: (idx: number, u: Partial<PolicyRule>) => void;
  addCondition: (ruleIdx: number) => void;
  removeCondition: (ruleIdx: number, condIdx: number) => void;
  updateCondition: (
    ruleIdx: number,
    condIdx: number,
    u: Partial<PolicyCondition>,
  ) => void;
}

export default function CreatePolicyTab({
  form,
  setForm,
  onSubmit,
  submitPending,
  submitError,
  onCancel,
  addRule,
  removeRule,
  updateRule,
  addCondition,
  removeCondition,
  updateCondition,
}: CreatePolicyTabProps) {
  return (
    <div className="space-y-6">
      {/* Metadata */}
      <Card>
        <CardHeader>
          <CardTitle>Policy Metadata</CardTitle>
          <CardDescription>
            Define the basic properties of your policy set
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1.5">
                Policy ID
              </label>
              <input
                type="text"
                value={form.policy_set_id}
                onChange={(e) =>
                  setForm((prev) => ({
                    ...prev,
                    policy_set_id: e.target.value,
                  }))
                }
                placeholder="e.g. pii-protection-v1"
                className={INPUT_CLASS}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5">
                Version
              </label>
              <input
                type="text"
                value={form.version}
                onChange={(e) =>
                  setForm((prev) => ({
                    ...prev,
                    version: e.target.value,
                  }))
                }
                placeholder="1.0"
                className={INPUT_CLASS}
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">
              Description
            </label>
            <input
              type="text"
              value={form.description || ""}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  description: e.target.value,
                }))
              }
              placeholder="Describe what this policy does..."
              className={INPUT_CLASS}
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1.5">
              Default Effect
            </label>
            <select
              value={form.default_effect}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  default_effect: e.target
                    .value as PolicyEffect,
                }))
              }
              className={SELECT_CLASS}
            >
              <option value="deny">
                Deny (block by default)
              </option>
              <option value="allow">
                Allow (permit by default)
              </option>
            </select>
          </div>
        </CardContent>
      </Card>

      {/* Rules */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Rules</CardTitle>
              <CardDescription>
                Define conditions that determine allow/deny
                decisions
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={addRule}
            >
              <Plus className="mr-2 h-4 w-4" />
              Add Rule
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {form.rules.map((rule, ruleIdx) => (
            <RuleEditor
              key={ruleIdx}
              rule={rule}
              index={ruleIdx}
              canRemove={form.rules.length > 1}
              onRemove={() => removeRule(ruleIdx)}
              onUpdate={(u) => updateRule(ruleIdx, u)}
              onAddCondition={() => addCondition(ruleIdx)}
              onRemoveCondition={(ci) =>
                removeCondition(ruleIdx, ci)
              }
              onUpdateCondition={(ci, u) =>
                updateCondition(ruleIdx, ci, u)
              }
            />
          ))}
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex items-center justify-between">
        {submitError && (
          <div className="flex items-center gap-2 text-sm text-destructive">
            <AlertTriangle className="h-4 w-4" />
            {submitError}
          </div>
        )}
        <div className="ml-auto flex gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            onClick={() => onSubmit(form)}
            disabled={
              !form.policy_set_id.trim() || submitPending
            }
          >
            {submitPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Shield className="mr-2 h-4 w-4" />
            )}
            Create Policy
          </Button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------ */
/*  Rule Editor                                                  */
/* ------------------------------------------------------------ */

interface RuleEditorProps {
  rule: PolicyRule;
  index: number;
  canRemove: boolean;
  onRemove: () => void;
  onUpdate: (u: Partial<PolicyRule>) => void;
  onAddCondition: () => void;
  onRemoveCondition: (condIdx: number) => void;
  onUpdateCondition: (
    condIdx: number,
    u: Partial<PolicyCondition>,
  ) => void;
}

function RuleEditor({
  rule,
  index,
  canRemove,
  onRemove,
  onUpdate,
  onAddCondition,
  onRemoveCondition,
  onUpdateCondition,
}: RuleEditorProps) {
  return (
    <div className="rounded-lg border border-border p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">
          Rule {index + 1}
        </h4>
        {canRemove && (
          <Button
            variant="ghost"
            size="sm"
            onClick={onRemove}
            className="h-7 text-destructive hover:text-destructive"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div>
          <label className="block text-xs font-medium mb-1 text-muted-foreground">
            Rule ID
          </label>
          <input
            type="text"
            value={rule.rule_id}
            onChange={(e) =>
              onUpdate({ rule_id: e.target.value })
            }
            className={INPUT_CLASS}
          />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1 text-muted-foreground">
            Effect
          </label>
          <select
            value={rule.effect}
            onChange={(e) =>
              onUpdate({
                effect: e.target.value as PolicyEffect,
              })
            }
            className={`w-full ${SELECT_CLASS}`}
          >
            <option value="deny">Deny</option>
            <option value="allow">Allow</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium mb-1 text-muted-foreground">
            Priority
          </label>
          <input
            type="number"
            value={rule.priority ?? 100}
            onChange={(e) =>
              onUpdate({
                priority:
                  parseInt(e.target.value) || 100,
              })
            }
            className={INPUT_CLASS}
          />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1 text-muted-foreground">
            Description
          </label>
          <input
            type="text"
            value={rule.description || ""}
            onChange={(e) =>
              onUpdate({ description: e.target.value })
            }
            className={INPUT_CLASS}
            placeholder="Optional"
          />
        </div>
      </div>

      {/* Conditions */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground">
            Conditions (all must match)
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={onAddCondition}
            className="h-6 text-xs"
          >
            <Plus className="mr-1 h-3 w-3" />
            Add
          </Button>
        </div>
        {rule.conditions.map((cond, condIdx) => (
          <div
            key={condIdx}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={cond.field}
              onChange={(e) =>
                onUpdateCondition(condIdx, {
                  field: e.target.value,
                })
              }
              placeholder="field"
              className={`flex-1 ${INPUT_CLASS}`}
            />
            <select
              value={cond.operator}
              onChange={(e) =>
                onUpdateCondition(condIdx, {
                  operator: e.target
                    .value as PolicyOperator,
                })
              }
              className={SELECT_CLASS}
            >
              {OPERATORS.map((op) => (
                <option key={op.value} value={op.value}>
                  {op.label}
                </option>
              ))}
            </select>
            {cond.operator !== "exists" &&
              cond.operator !== "not_exists" && (
                <input
                  type="text"
                  value={String(cond.value ?? "")}
                  onChange={(e) =>
                    onUpdateCondition(condIdx, {
                      value: e.target.value,
                    })
                  }
                  placeholder="value"
                  className={`flex-1 ${INPUT_CLASS}`}
                />
              )}
            {rule.conditions.length > 1 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  onRemoveCondition(condIdx)
                }
                className="h-8 w-8 p-0 text-destructive hover:text-destructive"
              >
                <X className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
