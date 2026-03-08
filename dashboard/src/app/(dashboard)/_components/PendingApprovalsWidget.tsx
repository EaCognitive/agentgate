"use client";

import React from "react";
import Link from "next/link";
import { ClipboardCheck } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
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
import type { Approval } from "@/types/index";

interface PendingApprovalsWidgetProps {
  approvals?: Approval[];
  isLoading: boolean;
}

/**
 * Compact list of the most recent pending approvals
 * with quick-review links.
 */
export default function PendingApprovalsWidget({
  approvals,
  isLoading,
}: PendingApprovalsWidgetProps) {
  const items = (approvals ?? []).slice(0, 5);

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="flex items-start gap-2">
          <ClipboardCheck
            className="mt-0.5 h-4 w-4 text-warning"
          />
          <div>
            <CardTitle>
              Pending Approvals
            </CardTitle>
            <CardDescription>
              Items awaiting review
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1">
        {isLoading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="flex h-32 flex-col items-center justify-center text-muted-foreground">
            <ClipboardCheck
              className="mb-3 h-10 w-10 opacity-40"
            />
            <span className="text-sm">
              All caught up -- no pending approvals
            </span>
          </div>
        ) : (
          <div className="space-y-2">
            {items.map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2 text-sm"
              >
                <span
                  className="truncate font-mono text-xs"
                  title={item.tool}
                >
                  {item.tool}
                </span>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge variant="pending">
                    pending
                  </Badge>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    {formatDistanceToNow(
                      new Date(item.created_at),
                      { addSuffix: true },
                    )}
                  </span>
                  <Link href="/approvals">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-xs"
                    >
                      Review
                    </Button>
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
      <CardFooter>
        <Link
          href="/approvals"
          className="text-sm text-primary hover:underline"
        >
          View all
        </Link>
      </CardFooter>
    </Card>
  );
}
