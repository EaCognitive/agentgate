import { NextRequest, NextResponse } from 'next/server';
import { API_URL, getAuthHeaders } from '@/lib/api-auth';

interface PolicyLoadRouteContext {
  params: Promise<{ id: string }>;
}

function passthroughTextResponse(response: Response, bodyText: string): NextResponse {
  const contentType = response.headers.get('content-type') || 'text/plain; charset=utf-8';
  return new NextResponse(bodyText, {
    status: response.status,
    headers: {
      'content-type': contentType,
    },
  });
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
    return passthroughTextResponse(response, bodyText);
  }
}

export async function POST(_request: NextRequest, context: PolicyLoadRouteContext) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id } = await context.params;
    const response = await fetch(`${API_URL}/api/policies/${id}/load`, {
      method: 'POST',
      headers,
    });
    return proxyResponse(response);
  } catch (error) {
    console.error('Policy load proxy error:', error);
    return NextResponse.json({ error: 'Failed to load policy' }, { status: 500 });
  }
}
