import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET() {
  try {
    const headers = await getAuthHeaders();
    if (!headers) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

    const res = await fetch(`${API_URL}/api/settings`, { headers });
    if (!res.ok) return NextResponse.json({ error: 'API error' }, { status: res.status });

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Settings fetch error:', error);
    return NextResponse.json({ error: 'Failed to fetch settings' }, { status: 500 });
  }
}

export async function PUT(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

    const body = await request.json();
    const res = await fetch(`${API_URL}/api/settings`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) return NextResponse.json({ error: 'API error' }, { status: res.status });

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Settings update error:', error);
    return NextResponse.json({ error: 'Failed to update settings' }, { status: 500 });
  }
}
