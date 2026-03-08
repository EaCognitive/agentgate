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
    const bucketMinutes = searchParams.get('bucket_minutes') || '60';
    const url = (
      `${API_URL}/api/traces/timeline`
      + `?hours=${hours}&bucket_minutes=${bucketMinutes}`
    );

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
    console.error('Timeline fetch error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch timeline' },
      { status: 500 },
    );
  }
}
