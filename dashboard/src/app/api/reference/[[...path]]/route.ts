import { NextRequest, NextResponse } from 'next/server';
import { API_URL } from '@/lib/api-auth';

interface ReferenceProxyContext {
  params: Promise<{ path?: string[] }>;
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function toBackendPath(pathSegments: string[]): string | null {
  if (pathSegments.some((segment) => segment.includes('..'))) {
    return null;
  }

  if (pathSegments.length === 0) {
    return '/api/reference';
  }

  if (pathSegments.length === 1 && pathSegments[0] === 'openapi.json') {
    return '/openapi.json';
  }

  return `/${pathSegments.join('/')}`;
}

function rewriteScalarHtml(html: string): string {
  return html
    .replace(/(["'])\/openapi\.json\1/g, '$1/api/reference/openapi.json$1')
    .replace(/(["'])\/static\//g, '$1/api/reference/static/')
    .replace(/(url:\s*['"])\/openapi\.json(['"])/g, '$1/api/reference/openapi.json$2');
}

function forwardHeaders(upstream: Headers): Headers {
  const headers = new Headers();
  upstream.forEach((value, key) => {
    const normalized = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(normalized)) {
      return;
    }
    headers.set(key, value);
  });
  return headers;
}

async function proxyReference(
  request: NextRequest,
  context: ReferenceProxyContext,
  method: 'GET' | 'HEAD',
) {
  const { path } = await context.params;
  const pathSegments = path ?? [];
  const backendPath = toBackendPath(pathSegments);
  if (!backendPath) {
    return NextResponse.json(
      { error: 'Invalid API reference path' },
      { status: 400 },
    );
  }

  const backendUrl = new URL(backendPath, `${API_URL}/`);
  request.nextUrl.searchParams.forEach((value, key) => {
    backendUrl.searchParams.set(key, value);
  });

  const requestHeaders: Record<string, string> = {
    Accept: request.headers.get('accept') ?? '*/*',
  };
  const authHeader = request.headers.get('authorization');
  if (authHeader) {
    requestHeaders.Authorization = authHeader;
  }

  const upstream = await fetch(backendUrl.toString(), {
    method,
    headers: requestHeaders,
  });

  const contentType = upstream.headers.get('content-type')?.toLowerCase() ?? '';
  const headers = forwardHeaders(upstream.headers);

  if (method === 'HEAD') {
    return new NextResponse(null, { status: upstream.status, headers });
  }

  if (contentType.includes('text/html')) {
    const html = await upstream.text();
    const rewritten = rewriteScalarHtml(html);
    headers.set('content-type', 'text/html; charset=utf-8');
    headers.set('cache-control', 'no-store');
    return new NextResponse(rewritten, { status: upstream.status, headers });
  }

  const body = await upstream.arrayBuffer();
  return new NextResponse(body, { status: upstream.status, headers });
}

export async function GET(request: NextRequest, context: ReferenceProxyContext) {
  try {
    return await proxyReference(request, context, 'GET');
  } catch (error) {
    console.error('API reference proxy error:', error);
    return NextResponse.json({ error: 'Failed to load API reference' }, { status: 500 });
  }
}

export async function HEAD(request: NextRequest, context: ReferenceProxyContext) {
  try {
    return await proxyReference(request, context, 'HEAD');
  } catch (error) {
    console.error('API reference proxy HEAD error:', error);
    return new NextResponse(null, { status: 500 });
  }
}
