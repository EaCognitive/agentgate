"use client";

import {
  Key,
  AlertTriangle,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";

interface KeyRotationStats {
  encryption_key_age_days: number;
  last_key_rotation: string | null;
}

interface KeyRotationModalProps {
  stats: KeyRotationStats | undefined;
  onClose: () => void;
  onRotate: () => void;
  isPending: boolean;
}

/**
 * Modal dialog for confirming encryption key rotation.
 */
export default function KeyRotationModal({
  stats,
  onClose,
  onRotate,
  isPending,
}: KeyRotationModalProps) {
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
          <Key className="h-5 w-5 text-warning" />
          Rotate Encryption Keys
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">
          This will generate new encryption keys and re-encrypt
          all stored PII data. This operation may take several
          minutes and cannot be undone.
        </p>

        <div
          className={
            "mt-4 rounded-lg bg-warning-50 p-3"
            + " text-warning"
          }
        >
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 mt-0.5" />
            <div className="text-sm">
              <p className="font-medium">Warning</p>
              <p>
                Ensure you have a backup before proceeding.
                Active sessions may be affected.
              </p>
            </div>
          </div>
        </div>

        {stats && (
          <div
            className={
              "mt-4 rounded-lg bg-muted/30 p-3 text-sm"
            }
          >
            <p className="text-muted-foreground">
              Current key age:{" "}
              <span className="text-foreground font-medium">
                {stats.encryption_key_age_days} days
              </span>
            </p>
            {stats.last_key_rotation && (
              <p className="text-muted-foreground">
                Last rotation:{" "}
                <span className="text-foreground font-medium">
                  {format(
                    new Date(stats.last_key_rotation),
                    "MMM d, yyyy",
                  )}
                </span>
              </p>
            )}
          </div>
        )}

        <div className="mt-6 flex gap-3">
          <Button
            variant="ghost"
            className="flex-1"
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button
            variant="danger"
            className="flex-1"
            onClick={onRotate}
            disabled={isPending}
          >
            {isPending ? (
              <Loader2
                className="mr-2 h-4 w-4 animate-spin"
              />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            Rotate Keys
          </Button>
        </div>
      </div>
    </div>
  );
}
