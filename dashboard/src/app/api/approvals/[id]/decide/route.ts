import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { id } = await params;
    const body = await request.json();

    const res = await fetch(
      `${API_URL}/api/approvals/${id}/decide`,
      {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      return NextResponse.json(
        {
          error:
            errorData.detail || 'Failed to process decision',
        },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Approval decision error:', error);
    return NextResponse.json(
      { error: 'Failed to process approval decision' },
      { status: 500 }
    );
  }
}
