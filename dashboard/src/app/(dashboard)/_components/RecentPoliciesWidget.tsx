"use client";

import React from "react";
import Link from "next/link";
import { Scale, Plus, ChevronRight } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import type { PolicyListResponse } from "@/types/policy";

interface RecentPoliciesWidgetProps {
  policies?: PolicyListResponse;
  isLoading: boolean;
}

/**
 * Shows the five most recently added policies with
 * status badges. Each row is clickable and navigates
 * to the policies management page.
 */
export default function RecentPoliciesWidget({
  policies,
  isLoading,
}: RecentPoliciesWidgetProps) {
  const dbPolicies = policies?.db_policies ?? [];
  const recent = dbPolicies.slice(-5).reverse();

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-start gap-2">
            <Scale
              className="mt-0.5 h-4 w-4 text-info"
            />
            <div>
              <CardTitle>Recent Policies</CardTitle>
              <CardDescription>
                Latest policy definitions
              </CardDescription>
            </div>
          </div>
          <Link href="/policies?tab=create">
            <Button variant="outline" size="sm">
              <Plus className="mr-1.5 h-3.5 w-3.5" />
              New Policy
            </Button>
          </Link>
        </div>
      </CardHeader>
      <CardContent className="flex-1">
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton
                key={i}
                className="h-10 w-full"
              />
            ))}
          </div>
        ) : recent.length === 0 ? (
          <div className="flex h-32 flex-col items-center justify-center gap-3 text-muted-foreground">
            <Scale
              className="h-10 w-10 opacity-40"
            />
            <span className="text-sm">
              No policies yet
            </span>
            <Link href="/policies?tab=create">
              <Button variant="outline" size="sm">
                <Plus className="mr-1.5 h-3.5 w-3.5" />
                Create Policy
              </Button>
            </Link>
          </div>
        ) : (
          <div className="space-y-1.5">
            {recent.map((p) => (
              <Link
                key={p.policy_set_id}
                href="/policies"
                className="group flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2.5 text-sm transition-colors hover:bg-muted/50"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className="truncate font-mono text-xs"
                    title={p.policy_set_id}
                  >
                    {p.policy_set_id}
                  </span>
                  <span className="text-xs text-muted-foreground shrink-0">
                    v{p.version}
                  </span>
                  <span className="text-xs text-muted-foreground shrink-0">
                    {p.rule_count}
                    {" "}rule{p.rule_count !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  {p.is_active && (
                    <Badge variant="success">
                      Active
                    </Badge>
                  )}
                  {p.locked && (
                    <Badge variant="blocked">
                      Locked
                    </Badge>
                  )}
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
      <CardFooter>
        <Link
          href="/policies"
          className="text-sm text-primary hover:underline"
        >
          Manage all policies
        </Link>
      </CardFooter>
    </Card>
  );
}
