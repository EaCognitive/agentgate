import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const password = body?.code || body?.password;
    if (!password) {
      return NextResponse.json({ error: 'Password required' }, { status: 400 });
    }

    const res = await fetch(`${API_URL}/api/auth/disable-2fa`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ password }),
    });
    if (!res.ok) {
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Disable 2FA error:', error);
    return NextResponse.json({ error: 'Failed to disable 2FA' }, { status: 500 });
  }
}
