import { NextRequest, NextResponse } from "next/server";
import { getAuthHeaders, API_URL } from "@/lib/api-auth";

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const res = await fetch(`${API_URL}/api/pii/detect`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: "Backend error", detail: await res.text() },
        { status: res.status }
      );
    }

    const data = await res.json();
    // Transform: backend returns 'detections', frontend expects 'entities'
    return NextResponse.json({
      entities: data.detections || [],
      redacted_text: data.redacted_text || "",
      engine: data.engine,
    });
  } catch (error) {
    console.error("PII detect proxy error:", error);
    return NextResponse.json(
      { error: "Failed to call PII detection" },
      { status: 500 }
    );
  }
}
