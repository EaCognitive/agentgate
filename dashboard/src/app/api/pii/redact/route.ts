import { NextRequest, NextResponse } from "next/server";
import { getAuthHeaders, API_URL } from "@/lib/api-auth";

export async function POST(request: NextRequest) {
  try {
    const headers = await getAuthHeaders();
    if (!headers) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const res = await fetch(`${API_URL}/api/pii/redact`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text();
      return NextResponse.json(
        { error: "Backend error", detail: err },
        { status: res.status },
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error("PII redact proxy error:", error);
    return NextResponse.json(
      { error: "Failed to call PII redaction" },
      { status: 500 },
    );
  }
}
