import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

export async function GET(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json([], { status: 200 });
    }

    const searchParams = request.nextUrl.searchParams;
    const url = new URL(`${API_URL}/api/prompt-templates`);
    searchParams.forEach((value, key) => {
      url.searchParams.set(key, value);
    });

    const res = await fetch(url.toString(), { headers });

    if (!res.ok) {
      // Return empty array if endpoint not available
      return NextResponse.json([]);
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    // Gracefully return empty if backend has no templates endpoint
    return NextResponse.json([]);
  }
}
