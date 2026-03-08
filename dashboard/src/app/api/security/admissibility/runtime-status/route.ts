import { NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

/**
 * GET proxy for admissibility runtime status.
 * Forwards to backend GET /api/security/admissibility/runtime-status
 */
export async function GET() {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 },
      );
    }

    const url = (
      `${API_URL}/api/security/admissibility/runtime-status`
    );

    const res = await fetch(url, { headers });
    if (!res.ok) {
      return NextResponse.json(
        { error: 'API error' },
        { status: res.status },
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Runtime status fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch runtime status' },
      { status: 500 },
    );
  }
}
