import React from "react";
import { cn } from "@/lib/utils";
import { TrendingUp, TrendingDown } from "lucide-react";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children?: React.ReactNode;
}

const Card = React.forwardRef<HTMLDivElement, CardProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "rounded-lg border border-border bg-card p-6 text-card-foreground",
        "transition-all duration-200 ease-in-out",
        "hover:border-border/80",
        className
      )}
      {...props}
    />
  )
);
Card.displayName = "Card";

interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {}

const CardHeader = React.forwardRef<HTMLDivElement, CardHeaderProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("flex flex-col space-y-1.5 pb-4", className)}
      {...props}
    />
  )
);
CardHeader.displayName = "CardHeader";

interface CardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {}

const CardTitle = React.forwardRef<HTMLHeadingElement, CardTitleProps>(
  ({ className, ...props }, ref) => (
    <h3
      ref={ref}
      className={cn("text-lg font-semibold leading-none tracking-tight", className)}
      {...props}
    />
  )
);
CardTitle.displayName = "CardTitle";

interface CardDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {}

const CardDescription = React.forwardRef<HTMLParagraphElement, CardDescriptionProps>(
  ({ className, ...props }, ref) => (
    <p
      ref={ref}
      className={cn("text-sm text-muted-foreground", className)}
      {...props}
    />
  )
);
CardDescription.displayName = "CardDescription";

interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {}

const CardContent = React.forwardRef<HTMLDivElement, CardContentProps>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("pt-0", className)} {...props} />
  )
);
CardContent.displayName = "CardContent";

interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {}

const CardFooter = React.forwardRef<HTMLDivElement, CardFooterProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn("flex items-center pt-4", className)}
      {...props}
    />
  )
);
CardFooter.displayName = "CardFooter";

interface StatCardProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  value: string | number;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  icon?: React.ReactNode;
  description?: string;
}

const StatCard = React.forwardRef<HTMLDivElement, StatCardProps>(
  ({ title, value, trend, icon, description, className, ...props }, ref) => (
    <Card ref={ref} className={cn("relative overflow-hidden", className)} {...props}>
      {/* Subtle gradient background for visual interest */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50 pointer-events-none" />

      <div className="relative flex items-start justify-between">
        <div className="flex-1 space-y-1">
          <CardDescription className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {title}
          </CardDescription>
          <div className="flex items-baseline gap-2">
            <div className="text-3xl font-bold tracking-tight">{value}</div>
            {trend && (
              <div
                className={cn(
                  "flex items-center gap-1 rounded-full px-1.5 py-0.5 text-xs font-medium",
                  trend.isPositive
                    ? "bg-success-50 text-success"
                    : "bg-danger-50 text-danger"
                )}
              >
                {trend.isPositive ? (
                  <TrendingUp className="h-3 w-3" />
                ) : (
                  <TrendingDown className="h-3 w-3" />
                )}
                {trend.value}%
              </div>
            )}
          </div>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
        {icon && (
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            {icon}
          </div>
        )}
      </div>
    </Card>
  )
);
StatCard.displayName = "StatCard";

export {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
  StatCard,
};
