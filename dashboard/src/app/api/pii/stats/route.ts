import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const url = new URL(`${API_URL}/api/pii/stats`);
    searchParams.forEach((value, key) => url.searchParams.set(key, value));

    const res = await fetch(url.toString(), { headers });

    if (!res.ok) {
      // Return safe defaults if PII permission denied
      if (res.status === 403) {
        return NextResponse.json({
          total_pii_stored: 0,
          total_pii_retrieved: 0,
          total_sessions: 0,
          active_sessions: 0,
          integrity_failures: 0,
          access_denied_count: 0,
          encryption_key_age_days: 0,
          last_key_rotation: null,
        });
      }
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('PII stats fetch error:', error);
    return NextResponse.json({ error: 'Failed to fetch PII stats' }, { status: 500 });
  }
}
