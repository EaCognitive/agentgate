import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const searchParams = request.nextUrl.searchParams;
    const url = new URL(`${API_URL}/api/pii/sessions`);
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
    console.error('PII sessions fetch error:', error);
    return NextResponse.json({ error: 'Failed to fetch PII sessions' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const res = await fetch(`${API_URL}/api/pii/sessions`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return NextResponse.json(data, { status: res.status });
    }
    return NextResponse.json(data, { status: 201 });
  } catch (error) {
    console.error('PII sessions create error:', error);
    return NextResponse.json({ error: 'Failed to create PII session' }, { status: 500 });
  }
}
