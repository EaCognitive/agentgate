import { NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET() {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const res = await fetch(`${API_URL}/api/auth/passkey/list`, { headers });
    if (!res.ok) {
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }
    const data = await res.json();
    // Normalize shape for UI
    const mapped = data.map((item: any) => ({
      id: item.credential_id,
      name: item.name,
      created_at: item.created_at,
      last_used: item.last_used,
      device_type: (item.transports || []).includes('internal') ? 'Device' : 'Security Key',
    }));
    return NextResponse.json(mapped);
  } catch (error) {
    console.error('Passkeys fetch error:', error);
    return NextResponse.json({ error: 'Failed to fetch passkeys' }, { status: 500 });
  }
}
