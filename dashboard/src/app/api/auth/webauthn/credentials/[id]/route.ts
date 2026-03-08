import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await params;
    const res = await fetch(`${API_URL}/api/auth/passkey/${id}`, { method: 'DELETE', headers });
    if (!res.ok) {
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Passkey delete error:', error);
    return NextResponse.json({ error: 'Failed to revoke passkey' }, { status: 500 });
  }
}
