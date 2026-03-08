/**
 * Global Error Handler
 *
 * Implements D-02 from the architectural audit - prevents information leakage
 * by providing a sanitized error UI instead of exposing stack traces.
 *
 * This component handles errors that occur outside of nested error boundaries.
 *
 * @author Erick | Founding Principal AI Architect
 */

'use client';

import { useEffect } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log error to monitoring service (sanitized)
    // In production, this would send to Sentry, DataDog, etc.
    console.error('Global error caught:', {
      message: error.message,
      digest: error.digest,
      // Never log full stack traces to client-side console in production
      // Stack trace is only logged server-side
    });
  }, [error]);

  return (
    <html>
      <body>
        <div className="flex min-h-screen items-center justify-center bg-gray-950 p-4">
          <div className="w-full max-w-md rounded-xl border border-gray-800 bg-gray-900 p-8 text-center shadow-2xl">
            <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-red-500/10">
              <AlertTriangle className="h-8 w-8 text-red-500" />
            </div>

            <h1 className="mb-2 text-xl font-bold text-white">
              Something went wrong
            </h1>

            <p className="mb-6 text-gray-400">
              We encountered an unexpected error. Our team has been notified and
              is working to fix the issue.
            </p>

            {/* Show error digest for support reference (safe to expose) */}
            {error.digest && (
              <p className="mb-6 text-xs text-gray-500">
                Error Reference: {error.digest}
              </p>
            )}

            <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
              <button
                onClick={reset}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700"
              >
                <RefreshCw className="h-4 w-4" />
                Try Again
              </button>

              <button
                onClick={() => window.location.href = '/'}
                className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-gray-700"
              >
                <Home className="h-4 w-4" />
                Go Home
              </button>
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
