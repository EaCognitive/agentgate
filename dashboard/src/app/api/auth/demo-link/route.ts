import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';

/**
 * Time-limited demo access link.
 *
 * Validates a signed JWT token (HS256) with an expiration claim,
 * authenticates against the backend as the demo user, and redirects
 * to /login with the resulting access token for auto-auth.
 *
 * Generate a link:
 *   python3 scripts/generate_demo_link.py --days 7
 *
 * The token is a standard JWT signed with DEMO_LINK_SECRET.
 * Expired tokens are rejected automatically.
 */

const DEMO_EMAIL = process.env.DEMO_ACCOUNT_EMAIL || 'demo@agentgate.io';
const DEMO_PASSWORD = process.env.DEMO_ACCOUNT_PASSWORD || 'AgentGate2025.Demo';

function resolveApiUrl(): string {
  const candidates = [
    process.env.API_URL,
    process.env.AGENTGATE_API_URL,
    process.env.NEXT_PUBLIC_API_URL,
  ];
  for (const c of candidates) {
    if (c?.trim()) return c.trim().replace(/\/+$/, '');
  }
  return 'http://localhost:8000';
}

/** Base64url decode (no padding). */
function base64UrlDecode(input: string): Buffer {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

/** Verify HS256 JWT and return the payload, or null on failure. */
function verifyJwt(
  token: string,
  secret: string,
): { exp: number; iss?: string } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signatureB64] = parts;

  // Verify signature
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = Buffer.from(secret, 'utf-8');
  const expected = crypto
    .createHmac('sha256', key)
    .update(signingInput)
    .digest();
  const actual = base64UrlDecode(signatureB64);

  if (
    expected.length !== actual.length
    || !crypto.timingSafeEqual(expected, actual)
  ) {
    return null;
  }

  // Decode header and verify algorithm
  try {
    const header = JSON.parse(
      base64UrlDecode(headerB64).toString('utf-8'),
    );
    if (header.alg !== 'HS256') return null;
  } catch {
    return null;
  }

  // Decode payload
  try {
    const payload = JSON.parse(
      base64UrlDecode(payloadB64).toString('utf-8'),
    );
    if (typeof payload.exp !== 'number') return null;
    return payload;
  } catch {
    return null;
  }
}

export async function GET(request: NextRequest) {
  const secret = process.env.DEMO_LINK_SECRET;
  if (!secret) {
    return NextResponse.json(
      { error: 'Demo link is not configured' },
      { status: 404 },
    );
  }

  const rawToken = request.nextUrl.searchParams.get('token');
  if (!rawToken) {
    return NextResponse.json(
      { error: 'Missing token' },
      { status: 403 },
    );
  }

  // Accept both dot-separated JWTs and tilde-separated (LinkedIn-safe)
  const token = rawToken.replaceAll('~', '.');

  // Validate JWT signature and decode payload
  const payload = verifyJwt(token, secret);
  if (!payload) {
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 403 },
    );
  }

  // Check expiration
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (payload.exp <= nowSeconds) {
    return NextResponse.json(
      { error: 'This demo link has expired' },
      { status: 410 },
    );
  }

  // Authenticate as the demo user against the backend
  const apiUrl = resolveApiUrl();
  try {
    const res = await fetch(`${apiUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: DEMO_EMAIL,
        password: DEMO_PASSWORD,
      }),
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: 'Demo account login failed' },
        { status: 502 },
      );
    }

    const data = await res.json();
    const accessToken = data.access_token;
    if (!accessToken) {
      return NextResponse.json(
        { error: 'No access token returned' },
        { status: 502 },
      );
    }

    const ip = request.headers.get('x-forwarded-for')
      ?.split(',')[0]?.trim()
      || request.headers.get('x-real-ip')
      || 'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    console.info(
      '[DEMO_LINK_ACCESS]',
      JSON.stringify({
        ip,
        user_agent: userAgent,
        email: DEMO_EMAIL,
        expires: new Date(payload.exp * 1000).toISOString(),
        accessed_at: new Date().toISOString(),
      }),
    );

    const dashboardUrl = process.env.NEXTAUTH_URL
      || request.nextUrl.origin;
    const loginUrl = new URL('/login', dashboardUrl);
    loginUrl.searchParams.set('provider_token', accessToken);
    loginUrl.searchParams.set('provider_hint', 'demo_link');
    loginUrl.searchParams.set('callbackUrl', '/verification');

    return NextResponse.redirect(loginUrl.toString());
  } catch {
    return NextResponse.json(
      { error: 'Failed to reach backend' },
      { status: 502 },
    );
  }
}
