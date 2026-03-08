/**
 * React Query hooks for AgentGate dashboard
 * Simplified version that makes direct API calls
 */

import {
  useQuery,
  useMutation,
  useQueryClient,
} from '@tanstack/react-query';
import type {
  Approval,
  ApprovalFilters,
  PaginatedResponse,
  RuntimeSolverStatus,
  Trace,
} from '@/types/index';
import type { PolicyListResponse } from '@/types/policy';

// Use relative paths to hit Next.js API routes that proxy to the backend
async function fetchApi<T>(endpoint: string): Promise<T> {
  const res = await fetch(endpoint);
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const errorMsg = errorData.error || errorData.detail || `API error: ${res.status}`;
    throw new Error(errorMsg);
  }
  return res.json();
}

async function postApi<T>(endpoint: string, data?: unknown): Promise<T> {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: data ? JSON.stringify(data) : undefined,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const errorMsg = errorData.error || errorData.detail || `API error: ${res.status}`;
    throw new Error(errorMsg);
  }
  return res.json();
}

/**
 * Hook to fetch dashboard overview statistics
 */
export function useOverview() {
  return useQuery({
    queryKey: ['overview'],
    queryFn: () => fetchApi<{
      total_calls: number;
      success_count: number;
      blocked_count: number;
      failed_count: number;
      success_rate: number;
      total_cost: number;
      pending_approvals: number;
    }>('/api/overview'),
    staleTime: 30000,
  });
}

/**
 * Hook to fetch approvals with filter support
 */
export function useApprovals(filters?: ApprovalFilters) {
  return useQuery({
    queryKey: ['approvals', filters],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters?.status) params.set('status', filters.status);
      if (filters?.tool) params.set('tool', filters.tool);
      if (filters?.page) params.set('page', String(filters.page));
      if (filters?.page_size) params.set('limit', String(filters.page_size));
      const url = `/api/approvals${params.toString() ? `?${params}` : ''}`;
      const response = await fetchApi<Approval[] | PaginatedResponse<Approval>>(url);
      // Handle both array and paginated response formats
      if (Array.isArray(response)) {
        return { items: response };
      }
      return response;
    },
    staleTime: 30000,
  });
}

/**
 * Hook to fetch pending approvals
 */
export function usePendingApprovals() {
  return useQuery({
    queryKey: ['approvals', 'pending'],
    queryFn: () => fetchApi<Approval[]>('/api/approvals/pending'),
    staleTime: 0, // Always refetch when invalidated
    gcTime: 0, // Don't cache
  });
}

/**
 * Mutation hook to decide on an approval
 */
export function useDecideApproval() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ id, approved, reason }: { id: string; approved: boolean; reason?: string }) => {
      return postApi(`/api/approvals/${id}/decide`, { approved, reason });
    },
    onSuccess: () => {
      // Force immediate refetch by invalidating and refetching
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      queryClient.invalidateQueries({ queryKey: ['overview'] });
      queryClient.refetchQueries({ queryKey: ['approvals', 'pending'] });
    },
  });
}

export interface TimelineBucket {
  time: string;
  success: number;
  failed: number;
  blocked: number;
}

export interface ToolStat {
  tool: string;
  total: number;
  success: number;
  failed: number;
  blocked: number;
  avg_duration_ms: number;
  total_cost: number;
}

export interface CertificateStats {
  success: boolean;
  total_decisions: number;
  admissible: number;
  inadmissible: number;
  by_result: Record<string, number>;
  by_proof_type: Record<string, number>;
  period_hours: number;
}

export interface AuditStats {
  total_events: number;
  by_action: Record<string, number>;
  by_status: Record<string, number>;
}

/**
 * Hook to fetch 24-hour activity timeline
 */
export function useTimeline() {
  return useQuery({
    queryKey: ['timeline'],
    queryFn: () => fetchApi<TimelineBucket[]>(
      '/api/traces/timeline?hours=24&bucket_minutes=60',
    ),
    staleTime: 60000,
  });
}

/**
 * Hook to fetch tool usage statistics
 */
export function useToolStats() {
  return useQuery({
    queryKey: ['toolStats'],
    queryFn: () => fetchApi<ToolStat[]>(
      '/api/traces/tools?hours=24',
    ),
    staleTime: 60000,
  });
}

/**
 * Hook to fetch certificate verification statistics
 */
export function useCertificateStats() {
  return useQuery({
    queryKey: ['certificateStats'],
    queryFn: () => fetchApi<CertificateStats>(
      '/api/certificates/stats?hours=24',
    ),
    staleTime: 60000,
  });
}

/**
 * Hook to fetch audit log statistics
 */
export function useAuditStats() {
  return useQuery({
    queryKey: ['auditStats'],
    queryFn: () => fetchApi<AuditStats>(
      '/api/audit/stats?hours=24',
    ),
    staleTime: 60000,
  });
}

/**
 * Hook to fetch pending approval count
 */
export function usePendingCount() {
  return useQuery({
    queryKey: ['pendingCount'],
    queryFn: () => fetchApi<{ count: number }>(
      '/api/approvals/pending/count',
    ),
    staleTime: 30000,
  });
}

/**
 * Hook to fetch all policies.
 * Shares the ["policies"] query key with the policies page
 * so both views hit the same cache.
 */
export function usePolicies() {
  return useQuery({
    queryKey: ['policies'],
    queryFn: () => fetchApi<PolicyListResponse>(
      '/api/policies',
    ),
    staleTime: 30000,
  });
}

/**
 * On-demand trace lookup by ID.
 * Only fetches when traceId is non-empty.
 */
export function useTraceLookup(traceId: string) {
  return useQuery({
    queryKey: ['trace', traceId],
    queryFn: () => fetchApi<Trace>(
      `/api/traces/${encodeURIComponent(traceId)}`,
    ),
    enabled: traceId.length > 0,
    retry: false,
    staleTime: 60000,
  });
}

/**
 * Hook to fetch Z3 runtime solver status
 */
export function useRuntimeStatus() {
  return useQuery({
    queryKey: ['runtimeStatus'],
    queryFn: () => fetchApi<RuntimeSolverStatus>(
      '/api/security/admissibility/runtime-status',
    ),
    staleTime: 60000,
  });
}
