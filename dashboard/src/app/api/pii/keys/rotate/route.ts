import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const res = await fetch(`${API_URL}/api/pii/keys/rotate`, {
      method: 'POST',
      headers,
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      return NextResponse.json(
        { error: errorData.detail || 'Failed to rotate keys' },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('PII key rotation error:', error);
    return NextResponse.json(
      { error: 'Failed to rotate encryption keys' },
      { status: 500 }
    );
  }
}
