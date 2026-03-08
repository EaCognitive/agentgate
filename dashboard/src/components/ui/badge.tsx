import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium transition-smooth",
  {
    variants: {
      variant: {
        success:
          "bg-accent/15 text-accent border border-accent/30 hover:bg-accent/25",
        failed:
          "bg-destructive/15 text-destructive border border-destructive/30 hover:bg-destructive/25",
        blocked:
          "bg-warning-100 text-warning border border-warning-200 hover:bg-warning-200",
        pending:
          "bg-muted/50 text-muted-foreground border border-muted hover:bg-muted/70",
        info:
          "bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25",
        default:
          "bg-muted text-muted-foreground border border-muted/50",
        outline:
          "bg-transparent text-foreground border border-border hover:bg-muted/50",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  );
}

interface StatusBadgeProps {
  status: "success" | "failed" | "blocked" | "pending" | "info";
  label: string;
  icon?: React.ReactNode;
}

function StatusBadge({ status, label, icon }: StatusBadgeProps) {
  return (
    <Badge variant={status} className="flex items-center gap-1">
      {icon}
      {label}
    </Badge>
  );
}

export { Badge, StatusBadge, badgeVariants };
