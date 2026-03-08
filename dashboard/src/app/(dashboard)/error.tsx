/**
 * Dashboard Error Boundary
 *
 * Implements D-02 from the architectural audit - prevents information leakage
 * by providing a sanitized error UI for dashboard pages.
 *
 * @author Erick | Founding Principal AI Architect
 */

'use client';

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log error for debugging (sanitized - no sensitive data)
    console.error('Dashboard error:', {
      message: error.message,
      digest: error.digest,
    });
  }, [error]);

  return (
    <div className="flex min-h-[60vh] items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardContent className="pt-8 text-center">
          <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
            <AlertTriangle className="h-8 w-8 text-destructive" />
          </div>

          <h2 className="mb-2 text-xl font-bold">Something went wrong</h2>

          <p className="mb-6 text-muted-foreground">
            We encountered an error loading this page. Please try again or
            contact support if the problem persists.
          </p>

          {/* Error digest for support reference */}
          {error.digest && (
            <p className="mb-6 rounded-lg bg-muted p-2 text-xs text-muted-foreground">
              Reference: {error.digest}
            </p>
          )}

          <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
            <Button onClick={reset} className="gap-2">
              <RefreshCw className="h-4 w-4" />
              Try Again
            </Button>

            <Button variant="outline" onClick={() => window.history.back()} className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              Go Back
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
