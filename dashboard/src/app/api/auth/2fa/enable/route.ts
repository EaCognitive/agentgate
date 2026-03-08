import { NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function POST() {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const res = await fetch(`${API_URL}/api/auth/enable-2fa`, { method: 'POST', headers });
    if (!res.ok) {
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Enable 2FA error:', error);
    return NextResponse.json({ error: 'Failed to enable 2FA' }, { status: 500 });
  }
}
