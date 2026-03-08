import { NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET() {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const res = await fetch(
      `${API_URL}/api/approvals/pending`,
      { headers }
    );

    if (!res.ok) {
      if (res.status === 403) {
        return NextResponse.json([]);
      }
      return NextResponse.json(
        { error: 'API error' },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Pending approvals fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch pending approvals' },
      { status: 500 }
    );
  }
}
