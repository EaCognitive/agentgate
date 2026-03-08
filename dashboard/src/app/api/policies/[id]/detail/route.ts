import { NextRequest, NextResponse } from 'next/server';
import { API_URL, getAuthHeaders } from '@/lib/api-auth';

interface PolicyDetailRouteContext {
  params: Promise<{ id: string }>;
}

export async function GET(
  _request: NextRequest,
  context: PolicyDetailRouteContext,
) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 },
      );
    }

    const { id } = await context.params;
    const response = await fetch(
      `${API_URL}/api/policies/${id}/detail`,
      { method: 'GET', headers },
    );

    if (!response.ok) {
      const errorData = await response
        .json()
        .catch(() => ({}));
      return NextResponse.json(
        {
          error: errorData.detail
            || 'Failed to fetch policy detail',
        },
        { status: response.status },
      );
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Policy detail proxy error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch policy detail' },
      { status: 500 },
    );
  }
}
