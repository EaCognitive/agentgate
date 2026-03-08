import type { PolicyOperator } from "@/types/policy";

export const OPERATORS: { value: PolicyOperator; label: string }[] = [
  { value: "eq", label: "Equals" },
  { value: "neq", label: "Not Equals" },
  { value: "in", label: "In" },
  { value: "not_in", label: "Not In" },
  { value: "contains", label: "Contains" },
  { value: "not_contains", label: "Not Contains" },
  { value: "matches", label: "Matches (Regex)" },
  { value: "gt", label: "Greater Than" },
  { value: "lt", label: "Less Than" },
  { value: "gte", label: "Greater or Equal" },
  { value: "lte", label: "Less or Equal" },
  { value: "exists", label: "Exists" },
  { value: "not_exists", label: "Not Exists" },
];

export const INPUT_CLASS =
  "w-full rounded-lg border border-border bg-background " +
  "px-3 py-2 text-sm focus:border-primary " +
  "focus:outline-none focus:ring-1 focus:ring-primary";

export const SELECT_CLASS =
  "rounded-lg border border-border bg-background " +
  "px-3 py-2 text-sm focus:border-primary " +
  "focus:outline-none focus:ring-1 focus:ring-primary";
