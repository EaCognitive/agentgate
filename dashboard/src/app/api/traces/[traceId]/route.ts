import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

interface TraceRouteContext {
  params: Promise<{ traceId: string }>;
}

/**
 * Proxy GET requests to the backend trace lookup
 * endpoint by trace ID.
 */
export async function GET(
  _request: NextRequest,
  context: TraceRouteContext,
) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 },
      );
    }

    const { traceId } = await context.params;
    const url = (
      `${API_URL}/api/traces/${encodeURIComponent(traceId)}`
    );

    const res = await fetch(url, { headers });
    if (!res.ok) {
      return NextResponse.json(
        { error: 'Trace not found' },
        { status: res.status },
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Trace lookup error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch trace' },
      { status: 500 },
    );
  }
}
