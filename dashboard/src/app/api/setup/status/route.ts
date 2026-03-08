import { NextResponse } from 'next/server';
import { apiWrapper, ApiError } from '@/lib/api-wrapper';
import { API_URL } from '@/lib/api-auth';

export const GET = apiWrapper(async () => {
  const response = await fetch(`${API_URL}/api/setup/status`, {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' },
    cache: 'no-store',
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw ApiError.internal(data.detail || 'Failed to retrieve setup status');
  }

  return NextResponse.json(data, { status: 200 });
});
