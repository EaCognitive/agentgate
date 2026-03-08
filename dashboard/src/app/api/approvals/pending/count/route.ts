import { NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

/**
 * Proxy route for fetching pending approval count.
 * Returns { count: number } derived from the pending approvals list.
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

    const res = await fetch(
      `${API_URL}/api/approvals/pending`,
      { headers },
    );

    if (!res.ok) {
      if (res.status === 403) {
        return NextResponse.json({ count: 0 });
      }
      return NextResponse.json(
        { error: 'API error' },
        { status: res.status },
      );
    }

    const data = await res.json();
    const count = Array.isArray(data) ? data.length : 0;
    return NextResponse.json({ count });
  } catch (error) {
    console.error('Pending count fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch pending count' },
      { status: 500 },
    );
  }
}
