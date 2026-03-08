import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const searchParams = request.nextUrl.searchParams;
    const url = new URL(`${API_URL}/api/pii/audit/export`);
    searchParams.forEach((value, key) => {
      url.searchParams.set(key, value);
    });

    const res = await fetch(url.toString(), { headers });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      return NextResponse.json(
        { error: errorData.detail || 'Failed to export audit' },
        { status: res.status }
      );
    }

    const format = searchParams.get('format') || 'csv';
    const contentType = format === 'json'
      ? 'application/json'
      : 'text/csv';

    const blob = await res.blob();
    return new NextResponse(blob, {
      headers: {
        'Content-Type': contentType,
        'Content-Disposition':
          `attachment; filename="pii-audit.${format}"`,
      },
    });
  } catch (error) {
    console.error('PII audit export error:', error);
    return NextResponse.json(
      { error: 'Failed to export PII audit log' },
      { status: 500 }
    );
  }
}
