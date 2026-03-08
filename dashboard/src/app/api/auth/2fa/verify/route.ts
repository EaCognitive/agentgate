import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const code = body?.code as string | undefined;
    if (!code) {
      return NextResponse.json({ error: 'Code required' }, { status: 400 });
    }

    const res = await fetch(`${API_URL}/api/auth/verify-2fa`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Verify 2FA error:', error);
    return NextResponse.json({ error: 'Failed to verify 2FA' }, { status: 500 });
  }
}
