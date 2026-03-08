import { NextRequest, NextResponse } from 'next/server';
import { getAuthHeaders, API_URL } from '@/lib/api-auth';

/**
 * POST proxy for admissibility evaluation.
 * Forwards to backend POST /api/security/admissibility/evaluate
 */
export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 },
      );
    }

    const body = await request.json();
    const url = `${API_URL}/api/security/admissibility/evaluate`;

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    const resData = await res.json().catch(() => ({}));

    // Backend returns 403 for INADMISSIBLE decisions with the full
    // certificate wrapped in FastAPI's `detail` field. Unwrap it so
    // the dashboard receives a consistent AdmissibilityResponse shape.
    if (res.status === 403 && resData.detail?.certificate) {
      return NextResponse.json(resData.detail);
    }

    if (!res.ok) {
      return NextResponse.json(
        { error: resData.detail || 'Evaluation failed' },
        { status: res.status },
      );
    }

    return NextResponse.json(resData);
  } catch (error) {
    console.error('Admissibility evaluate proxy error:', error);
    return NextResponse.json(
      { error: 'Failed to evaluate admissibility' },
      { status: 500 },
    );
  }
}
