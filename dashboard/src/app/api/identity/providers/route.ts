import { NextResponse } from 'next/server';
import { API_URL } from '@/lib/api-auth';

export async function GET() {
  try {
    const res = await fetch(`${API_URL}/api/auth/providers`, {
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    });
    if (!res.ok) {
      return NextResponse.json({ error: 'API error' }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Identity providers fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch provider configuration' },
      { status: 500 }
    );
  }
}
