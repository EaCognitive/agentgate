import { NextRequest, NextResponse } from 'next/server';
import { API_URL, getAuthHeaders } from '@/lib/api-auth';

interface PolicyDeactivateRouteContext {
  params: Promise<{ id: string }>;
}

async function proxyResponse(response: Response): Promise<NextResponse> {
  if (response.status === 204) {
    return new NextResponse(null, { status: response.status });
  }

  const bodyText = await response.text();
  if (!bodyText) {
    return new NextResponse(null, { status: response.status });
  }

  try {
    const parsed = JSON.parse(bodyText);
    return NextResponse.json(parsed, { status: response.status });
  } catch {
    const contentType = response.headers.get('content-type') || 'text/plain; charset=utf-8';
    return new NextResponse(bodyText, {
      status: response.status,
      headers: { 'content-type': contentType },
    });
  }
}

export async function POST(_request: NextRequest, context: PolicyDeactivateRouteContext) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await context.params;
    const response = await fetch(`${API_URL}/api/policies/${id}/deactivate`, {
      method: 'POST',
      headers,
    });
    return proxyResponse(response);
  } catch (error) {
    console.error('Policy deactivate proxy error:', error);
    return NextResponse.json({ error: 'Failed to deactivate policy' }, { status: 500 });
  }
}
