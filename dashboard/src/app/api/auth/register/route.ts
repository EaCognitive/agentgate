/**
 * User Registration API Route
 *
 * Implements D-01 (Zod validation) and D-02 (standardized error handling)
 * from the architectural audit.
 *
 * This is a critical security endpoint - input validation is essential.
 */

import { NextRequest, NextResponse } from 'next/server';
import { apiWrapper, parseRequestBody, ApiError } from '@/lib/api-wrapper';
import { RegisterRequestSchema } from '@/lib/api-schemas';
import { API_URL } from '@/lib/api-auth';

export const POST = apiWrapper(async (request: NextRequest) => {
  // Validate request body with strict Zod schema
  // This ensures password strength, valid email, etc.
  const body = await parseRequestBody(request, RegisterRequestSchema);

  const res = await fetch(`${API_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    if (res.status === 409) {
      throw ApiError.conflict('An account with this email already exists');
    }
    if (res.status === 403) {
      throw ApiError.forbidden(
        (typeof data.detail === 'string' && data.detail) || 'Local signup is disabled'
      );
    }
    if (res.status === 400) {
      throw ApiError.badRequest(data.detail || 'Invalid registration data');
    }
    throw ApiError.internal('Registration failed. Please try again.');
  }

  return NextResponse.json(data, { status: 201 });
});
