import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { apiWrapper, parseRequestBody, ApiError } from '@/lib/api-wrapper';
import { API_URL } from '@/lib/api-auth';

const SetupCompleteSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(12).max(128),
  name: z.string().min(1).max(120).default('Admin'),
  generate_api_key: z.boolean().default(true),
  api_key_name: z.string().max(128).default('mcp-default'),
});

export const POST = apiWrapper(async (request: NextRequest) => {
  const body = await parseRequestBody(request, SetupCompleteSchema);

  const incomingOrigin = request.headers.get('origin')?.trim();
  const resolvedOrigin = incomingOrigin || request.nextUrl.origin;
  const origin = resolvedOrigin.replace('://0.0.0.0:', '://localhost:');

  const refererHeader = request.headers.get('referer')?.trim();
  let referer = refererHeader || `${origin}/setup`;
  referer = referer.replace('://0.0.0.0:', '://localhost:');

  const response = await fetch(`${API_URL}/api/setup/complete`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: origin,
      Referer: referer,
    },
    body: JSON.stringify(body),
    cache: 'no-store',
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const detail = data.detail || data.error || 'Initial setup failed';
    if (response.status === 409) {
      throw ApiError.conflict(detail);
    }
    if (response.status === 400) {
      throw ApiError.badRequest(detail);
    }
    if (response.status === 403) {
      throw ApiError.forbidden(detail);
    }
    throw ApiError.internal(detail);
  }

  return NextResponse.json(data, { status: 200 });
});
