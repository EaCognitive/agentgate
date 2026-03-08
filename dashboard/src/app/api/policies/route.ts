import { NextRequest, NextResponse } from 'next/server';
import { API_URL, getAuthHeaders } from '@/lib/api-auth';

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

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const url = new URL(`${API_URL}/api/policies`);
    request.nextUrl.searchParams.forEach((value, key) => {
      url.searchParams.set(key, value);
    });

    const response = await fetch(url.toString(), { headers });
    return proxyResponse(response);
  } catch (error) {
    console.error('Policies list proxy error:', error);
    return NextResponse.json({ error: 'Failed to list policies' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const response = await fetch(`${API_URL}/api/policies`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    return proxyResponse(response);
  } catch (error) {
    console.error('Policies create proxy error:', error);
    return NextResponse.json({ error: 'Failed to create policy' }, { status: 500 });
  }
}
