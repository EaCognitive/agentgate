import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 },
      );
    }

    const { searchParams } = request.nextUrl;
    const hours = searchParams.get('hours') || '24';
    const url = `${API_URL}/api/traces/tools?hours=${hours}`;

    const res = await fetch(url, { headers });
    if (!res.ok) {
      return NextResponse.json(
        { error: 'API error' },
        { status: res.status },
      );
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Tools fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch tools' },
      { status: 500 },
    );
  }
}
