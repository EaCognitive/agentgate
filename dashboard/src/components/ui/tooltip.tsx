/**
 * Simple Tooltip Component
 *
 * @author Erick | Founding Principal AI Architect
 */

"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

interface TooltipProviderProps {
  children: React.ReactNode;
  delayDuration?: number;
}

export function TooltipProvider({
  children,
}: TooltipProviderProps) {
  return <>{children}</>;
}

interface TooltipProps {
  children: React.ReactNode;
}

export function Tooltip({ children }: TooltipProps) {
  return <>{children}</>;
}

interface TooltipTriggerProps {
  children: React.ReactNode;
  asChild?: boolean;
}

export function TooltipTrigger({
  children,
  asChild,
}: TooltipTriggerProps) {
  return <>{children}</>;
}

interface TooltipContentProps {
  children: React.ReactNode;
  className?: string;
  side?: "top" | "right" | "bottom" | "left";
  sideOffset?: number;
}

export function TooltipContent({
  children,
  className,
  side = "top",
  sideOffset = 4,
}: TooltipContentProps) {
  // This is a simplified tooltip - for full functionality, use @radix-ui/react-tooltip
  return (
    <div
      role="tooltip"
      className={cn(
        "z-50 overflow-hidden rounded-md border border-border bg-popover px-3 py-1.5 text-sm text-popover-foreground shadow-md animate-in fade-in-0 zoom-in-95",
        "absolute hidden group-hover:block",
        {
          "bottom-full mb-2": side === "top",
          "top-full mt-2": side === "bottom",
          "right-full mr-2": side === "left",
          "left-full ml-2": side === "right",
        },
        className
      )}
    >
      {children}
    </div>
  );
}
