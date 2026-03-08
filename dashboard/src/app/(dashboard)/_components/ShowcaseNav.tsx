import Link from "next/link";
import { ArrowLeft, ArrowRight } from "lucide-react";

interface ShowcaseNavProps {
  previousHref?: string;
  previousLabel?: string;
  nextHref?: string;
  nextLabel?: string;
}

/**
 * Cross-page navigation footer for the investor showcase flow.
 */
export default function ShowcaseNav({
  previousHref,
  previousLabel,
  nextHref,
  nextLabel,
}: ShowcaseNavProps) {
  return (
    <div
      className={
        "flex items-center rounded-xl border border-border "
        + "bg-card/80 px-6 py-4 shadow-sm "
        + (previousHref && nextHref
          ? "justify-between"
          : nextHref
            ? "justify-end"
            : "justify-start")
      }
    >
      {previousHref && previousLabel && (
        <Link
          href={previousHref}
          className={
            "flex items-center gap-2 text-sm font-medium "
            + "text-muted-foreground transition-colors "
            + "hover:text-foreground"
          }
        >
          <ArrowLeft className="h-4 w-4" />
          {previousLabel}
        </Link>
      )}
      {nextHref && nextLabel && (
        <Link
          href={nextHref}
          className={
            "flex items-center gap-2 text-sm font-medium "
            + "text-primary transition-colors "
            + "hover:text-primary/80"
          }
        >
          {nextLabel}
          <ArrowRight className="h-4 w-4" />
        </Link>
      )}
    </div>
  );
}
