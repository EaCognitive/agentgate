import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';

/**
 * Short demo access link with multi-user support.
 *
 * Token formats (backward-compatible):
 *   Legacy  (16 chars): base64url( 4-byte expiry + 8-byte HMAC )
 *     -> always maps to user index 0
 *   Current (18 chars): base64url( 1-byte user_index + 4-byte expiry + 8-byte HMAC )
 *
 * Demo accounts are loaded from env vars:
 *   DEMO_ACCOUNT_EMAIL   / DEMO_ACCOUNT_PASSWORD   -> index 0
 *   DEMO_ACCOUNT_EMAIL_1 / DEMO_ACCOUNT_PASSWORD_1 -> index 1
 *   DEMO_ACCOUNT_EMAIL_2 / DEMO_ACCOUNT_PASSWORD_2 -> index 2
 *   ...up to index 9
 *
 * Generate:  python3 scripts/generate_demo_link.py --days 7 --user 1
 */

interface DemoAccount {
  email: string;
  password: string;
}

function getDemoAccount(index: number): DemoAccount | null {
  if (index === 0) {
    const email = process.env.DEMO_ACCOUNT_EMAIL;
    const password = process.env.DEMO_ACCOUNT_PASSWORD;
    if (email && password) return { email, password };
    return null;
  }
  const email = process.env[`DEMO_ACCOUNT_EMAIL_${index}`];
  const password = process.env[`DEMO_ACCOUNT_PASSWORD_${index}`];
  if (email && password) return { email, password };
  return null;
}

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

interface LegacyPayload { userIndex: 0; exp: number }
interface CurrentPayload { userIndex: number; exp: number }
type TokenPayload = LegacyPayload | CurrentPayload;

function verifyToken(
  token: string,
  secret: string,
): TokenPayload | null {
  const padded = token + '='.repeat((4 - (token.length % 4)) % 4);
  let buf: Buffer;
  try {
    buf = Buffer.from(padded, 'base64');
  } catch {
    return null;
  }

  const key = Buffer.from(secret, 'utf-8');

  // Legacy format: 12 bytes (4 expiry + 8 mac), user index always 0
  if (buf.length === 12) {
    const expiryBytes = buf.subarray(0, 4);
    const macPrefix = buf.subarray(4, 12);

    const fullMac = crypto
      .createHmac('sha256', key)
      .update(expiryBytes)
      .digest();

    if (!crypto.timingSafeEqual(macPrefix, fullMac.subarray(0, 8))) {
      return null;
    }
    return { userIndex: 0, exp: expiryBytes.readUInt32BE(0) };
  }

  // Current format: 13 bytes (1 user_index + 4 expiry + 8 mac)
  if (buf.length === 13) {
    const userIndex = buf[0];
    const signedPart = buf.subarray(0, 5); // user_index + expiry
    const macPrefix = buf.subarray(5, 13);

    const fullMac = crypto
      .createHmac('sha256', key)
      .update(signedPart)
      .digest();

    if (!crypto.timingSafeEqual(macPrefix, fullMac.subarray(0, 8))) {
      return null;
    }
    return { userIndex, exp: buf.readUInt32BE(1) };
  }

  return null;
}

function buildRevokedHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Access Terminated - AgentGate</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;800&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{
    background:#0a0a0a;
    color:#e5e5e5;
    font-family:'Manrope',system-ui,sans-serif;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
  }
  .container{
    text-align:center;
    max-width:520px;
    padding:2.5rem;
  }
  .shield{
    width:80px;height:80px;
    margin:0 auto 2rem;
    opacity:0.85;
  }
  .shield svg{width:100%;height:100%}
  .badge{
    display:inline-block;
    background:rgba(220,38,38,0.12);
    border:1px solid rgba(220,38,38,0.4);
    color:#f87171;
    font-size:0.7rem;
    font-weight:600;
    letter-spacing:0.12em;
    text-transform:uppercase;
    padding:0.35rem 1rem;
    border-radius:999px;
    margin-bottom:1.5rem;
  }
  h1{
    font-size:1.5rem;
    font-weight:800;
    letter-spacing:-0.02em;
    line-height:1.3;
    margin-bottom:0.75rem;
  }
  h1 span{color:#f87171}
  .sub{
    color:#737373;
    font-size:0.9rem;
    line-height:1.6;
    margin-bottom:2rem;
  }
  .contact{
    display:inline-flex;
    align-items:center;
    gap:0.5rem;
    background:#016339;
    color:#fff;
    font-weight:600;
    font-size:0.85rem;
    padding:0.7rem 1.5rem;
    border-radius:8px;
    text-decoration:none;
    transition:background 0.2s;
  }
  .contact:hover{background:#017a45}
  .footer{
    margin-top:3rem;
    color:#404040;
    font-size:0.7rem;
    letter-spacing:0.05em;
  }
</style>
</head>
<body>
<div class="container">
  <div class="shield">
    <svg viewBox="0 0 24 24" fill="none" stroke="#f87171"
         stroke-width="1.5" stroke-linecap="round"
         stroke-linejoin="round">
      <path d="M12 2l7 4v5c0 5.25-3.5 9.74-7
        11-3.5-1.26-7-5.75-7-11V6l7-4z"/>
      <line x1="9" y1="9" x2="15" y2="15"/>
      <line x1="15" y1="9" x2="9" y2="15"/>
    </svg>
  </div>
  <div class="badge">Access Revoked</div>
  <h1>USER REFUSED DEMO &mdash;<br/><span>KEY HAS BEEN TERMINATED</span></h1>
  <p class="sub">
    This demo access link has been permanently revoked.<br/>
    The token is no longer valid and cannot be reactivated.
  </p>
  <a class="contact" href="mailto:erick@eacognitive.com?subject=AgentGate%20Demo%20Access">
    Contact erick@eacognitive.com for access
  </a>
  <p class="footer">AGENTGATE SECURITY</p>
</div>
</body>
</html>`;
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ token: string }> },
) {
  const secret = process.env.DEMO_LINK_SECRET;
  if (!secret) {
    return NextResponse.json(
      { error: 'Demo link is not configured' },
      { status: 404 },
    );
  }

  const { token } = await params;
  if (!token) {
    return NextResponse.json(
      { error: 'Missing token' },
      { status: 403 },
    );
  }

  const revokedRaw = process.env.REVOKED_DEMO_TOKENS ?? '';
  const revokedSet = new Set(
    revokedRaw.split(',').map((t) => t.trim()).filter(Boolean),
  );
  if (revokedSet.has(token)) {
    return new Response(buildRevokedHtml(), {
      status: 403,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  const payload = verifyToken(token, secret);
  if (!payload) {
    return NextResponse.json(
      { error: 'Invalid token' },
      { status: 403 },
    );
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (payload.exp <= nowSeconds) {
    return NextResponse.json(
      { error: 'This link has expired' },
      { status: 410 },
    );
  }

  const account = getDemoAccount(payload.userIndex);
  if (!account) {
    return NextResponse.json(
      { error: 'Demo account not configured' },
      { status: 404 },
    );
  }

  const apiUrl = resolveApiUrl();
  try {
    const res = await fetch(`${apiUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: account.email,
        password: account.password,
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
        email: account.email,
        user_index: payload.userIndex,
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
