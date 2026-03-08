import { getServerSession } from 'next-auth';
import { headers as getRequestHeaders } from 'next/headers';
import { authOptions } from '@/lib/auth';

function normalizeBackendBase(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, '');
  return trimmed.replace(/\/api$/, '');
}

function resolveApiUrl(): string {
  // Prefer explicit AgentGate backend envs over generic API_URL to avoid
  // collisions with front-end tooling that may set API_URL to dashboard origin.
  const candidates = [
    process.env.AGENTGATE_API_URL,
    process.env.NEXT_PUBLIC_API_URL,
    process.env.API_URL,
  ];

  for (const candidate of candidates) {
    if (candidate && candidate.trim()) {
      return normalizeBackendBase(candidate);
    }
  }

  // Local default for non-container dev; docker compose sets API_URL explicitly.
  return 'http://localhost:8000';
}

/**
 * Get authentication headers for backend API requests.
 * Returns headers with Bearer token if authenticated, null otherwise.
 */
export async function getAuthHeaders(): Promise<Record<string, string> | null> {
  const session = await getServerSession(authOptions);
  if (!session?.user || !session?.accessToken) {
    // Fallback for CLI / SDK calls routed through dashboard API endpoints:
    // accept incoming Bearer token when NextAuth session cookies are absent.
    try {
      const incomingHeaders = await getRequestHeaders();
      const authHeader = incomingHeaders.get('authorization');
      if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
        return {
          'Content-Type': 'application/json',
          'Authorization': authHeader,
        };
      }
    } catch {
      // No request context available; keep unauthenticated behavior.
    }
    return null;
  }
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${session.accessToken}`,
  };
}

/**
 * Get the backend API URL from environment.
 */
export const API_URL = resolveApiUrl();
