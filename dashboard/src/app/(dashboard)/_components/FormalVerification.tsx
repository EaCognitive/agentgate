"use client";

import React from "react";
import { BadgeCheck } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { CertificateStats } from "@/lib/hooks";

interface FormalVerificationProps {
  certStats?: CertificateStats;
  isLoading: boolean;
}

/**
 * Certificate decision statistics and proof type
 * breakdown for formal verification results.
 */
export default function FormalVerification({
  certStats,
  isLoading,
}: FormalVerificationProps) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start gap-2">
          <BadgeCheck
            className="mt-0.5 h-4 w-4 text-violet-500"
          />
          <div>
            <CardTitle>
              Formal Verification
            </CardTitle>
            <CardDescription>
              Certificate decision statistics
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : !certStats ? (
          <div className="flex h-48 flex-col items-center justify-center text-muted-foreground">
            <BadgeCheck
              className="mb-3 h-10 w-10 opacity-40"
            />
            <span className="text-sm">
              No verification data
            </span>
            <span className="mt-1 text-xs opacity-70">
              Data will appear once certificates are issued
            </span>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-2xl font-bold tabular-nums">
                  {certStats.total_decisions ?? 0}
                </div>
                <div className="text-xs text-muted-foreground">
                  Total
                </div>
              </div>
              <div>
                <div className="text-2xl font-bold tabular-nums text-success">
                  {certStats.admissible ?? 0}
                </div>
                <div className="text-xs text-muted-foreground">
                  Admissible
                </div>
              </div>
              <div>
                <div className="text-2xl font-bold tabular-nums text-danger">
                  {certStats.inadmissible ?? 0}
                </div>
                <div className="text-xs text-muted-foreground">
                  Inadmissible
                </div>
              </div>
            </div>
            {certStats.by_proof_type
              && Object.keys(
                certStats.by_proof_type,
              ).length > 0 && (
                <div className="space-y-2">
                  <div className="text-sm font-medium">
                    By Proof Type
                  </div>
                  {Object.entries(
                    certStats.by_proof_type,
                  ).map(
                    ([proofType, proofCount]) => (
                      <div
                        key={proofType}
                        className="flex items-center justify-between text-sm"
                      >
                        <span className="text-muted-foreground">
                          {proofType}
                        </span>
                        <span className="font-medium tabular-nums">
                          {proofCount}
                        </span>
                      </div>
                    ),
                  )}
                </div>
              )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
