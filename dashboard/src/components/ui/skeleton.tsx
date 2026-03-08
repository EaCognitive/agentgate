import React from "react";
import { cn } from "@/lib/utils";

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string;
}

export function Skeleton({ className, ...props }: SkeletonProps) {
  return (
    <div
      className={cn("skeleton", className)}
      {...props}
    />
  );
}

export function SkeletonText({ className, lines = 1 }: { className?: string; lines?: number }) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton
          key={i}
          className={cn(
            "h-4",
            i === lines - 1 && lines > 1 ? "w-3/4" : "w-full"
          )}
        />
      ))}
    </div>
  );
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div className={cn("rounded-lg border border-border bg-card/60 p-6", className)}>
      <Skeleton className="mb-4 h-4 w-1/3" />
      <Skeleton className="h-8 w-1/2" />
    </div>
  );
}

export function SkeletonTable({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex gap-4 border-b border-border pb-3">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-4 flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="flex gap-4 py-3">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={colIndex} className="h-4 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

// Pre-computed heights to avoid Math.random() during render
const CHART_BAR_HEIGHTS = [65, 42, 78, 55, 38, 70, 48, 62, 45, 72, 50, 68];

export function SkeletonChart({ className }: { className?: string }) {
  return (
    <div className={cn("flex h-80 items-end justify-between gap-2 px-4", className)}>
      {Array.from({ length: 12 }).map((_, i) => (
        <Skeleton
          key={i}
          className="flex-1"
          style={{ height: `${CHART_BAR_HEIGHTS[i]}%` }}
        />
      ))}
    </div>
  );
}
