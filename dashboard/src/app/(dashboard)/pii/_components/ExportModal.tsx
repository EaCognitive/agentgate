"use client";

import { Download, FileText, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ExportModalProps {
  onClose: () => void;
  onExport: (format: "csv" | "json") => void;
  isPending: boolean;
}

/**
 * Modal dialog for exporting the PII audit log in CSV or
 * JSON format.
 */
export default function ExportModal({
  onClose,
  onExport,
  isPending,
}: ExportModalProps) {
  return (
    <div
      className={
        "fixed inset-0 z-50 flex items-center justify-center"
        + " bg-black/50 backdrop-blur-sm"
      }
    >
      <div
        className={
          "mx-4 w-full max-w-md rounded-xl border"
          + " border-border bg-card p-6 shadow-2xl"
        }
      >
        <h2
          className={
            "text-xl font-semibold text-foreground"
            + " flex items-center gap-2"
          }
        >
          <Download className="h-5 w-5" />
          Export Audit Log
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Download the PII audit log for compliance reporting
          or analysis.
        </p>

        <div className="mt-6 space-y-3">
          <Button
            variant="outline"
            className="w-full justify-start"
            onClick={() => onExport("csv")}
            disabled={isPending}
          >
            {isPending ? (
              <Loader2
                className="mr-2 h-4 w-4 animate-spin"
              />
            ) : (
              <FileText className="mr-2 h-4 w-4" />
            )}
            Export as CSV
            <span
              className={
                "ml-auto text-xs text-muted-foreground"
              }
            >
              Spreadsheet format
            </span>
          </Button>
          <Button
            variant="outline"
            className="w-full justify-start"
            onClick={() => onExport("json")}
            disabled={isPending}
          >
            {isPending ? (
              <Loader2
                className="mr-2 h-4 w-4 animate-spin"
              />
            ) : (
              <FileText className="mr-2 h-4 w-4" />
            )}
            Export as JSON
            <span
              className={
                "ml-auto text-xs text-muted-foreground"
              }
            >
              Machine readable
            </span>
          </Button>
        </div>

        <Button
          variant="ghost"
          className="mt-4 w-full"
          onClick={onClose}
        >
          Cancel
        </Button>
      </div>
    </div>
  );
}
