import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const url = new URL(`${API_URL}/api/pii/audit`);
    searchParams.forEach((value, key) => url.searchParams.set(key, value));

    const res = await fetch(url.toString(), { headers });

    if (!res.ok) {
      if (res.status === 403) {
        return NextResponse.json([]);
      }
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('PII audit fetch error:', error);
    return NextResponse.json({ error: 'Failed to fetch PII audit log' }, { status: 500 });
  }
}
