/**
 * Helper functions for the playground chat route.
 *
 * All backend-calling utilities, session management, and local PII
 * detection logic live here.
 */
import { API_URL } from "@/lib/api-auth";

import {
  SessionState,
  MiddlewareResult,
  LOCAL_PII_PATTERNS,
  PLAYGROUND_PII_SESSION_PREFIX,
  OPENAI_SYSTEM_PROMPT,
} from "./types";

// ---------------------------------------------------------------------------
// Session state (in-memory per instance -- acceptable for a demo)
// ---------------------------------------------------------------------------
export const sessions: Record<string, SessionState> = {};

export function getScopedPIISessionId(sessionId: string): string {
  return `${PLAYGROUND_PII_SESSION_PREFIX}${sessionId}`;
}

export function getAuthenticatedUserId(
  headers: Record<string, string>,
): string | null {
  const authHeader =
    headers.Authorization ?? headers.authorization;
  if (
    !authHeader
    || !authHeader.toLowerCase().startsWith("bearer ")
  ) {
    return null;
  }

  const token = authHeader.slice("bearer ".length).trim();
  const tokenSegments = token.split(".");
  if (tokenSegments.length < 2 || !tokenSegments[1]) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(tokenSegments[1], "base64url").toString(
        "utf8",
      ),
    ) as { sub?: unknown };
    if (
      typeof payload.sub === "string"
      && payload.sub.trim()
    ) {
      return payload.sub.trim();
    }
  } catch {
    return null;
  }

  return null;
}

export function collectLocalPIIHints(
  text: string,
): { type: string; original: string; masked: string }[] {
  const hints: {
    type: string;
    original: string;
    masked: string;
  }[] = [];
  const counters: Record<string, number> = {};

  for (const patternDef of LOCAL_PII_PATTERNS) {
    const matches = Array.from(text.matchAll(patternDef.pattern));
    patternDef.pattern.lastIndex = 0;
    if (matches.length === 0) {
      continue;
    }

    for (const match of matches) {
      counters[patternDef.type] =
        (counters[patternDef.type] || 0) + 1;
      const hintToken =
        `<${patternDef.type}_LOCAL_${counters[patternDef.type]}>`;
      hints.push({
        type: patternDef.type,
        original: match[0],
        masked: hintToken,
      });
    }
  }

  return hints;
}

export function getSession(id: string): SessionState {
  if (!sessions[id]) {
    sessions[id] = {
      callCount: 0,
      totalCost: 0,
      budget: 1.0,
      rateLimit: 20,
      windowStart: Date.now(),
      conversationHistory: [],
      piiSessionInitialized: false,
    };
  }
  const s = sessions[id];
  if (Date.now() - s.windowStart > 60000) {
    s.callCount = 0;
    s.windowStart = Date.now();
  }
  return s;
}

// ---------------------------------------------------------------------------
// Call OpenAI Chat Completions API
// ---------------------------------------------------------------------------
export async function callOpenAI(
  message: string,
  history: { role: string; content: string }[],
): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return "I'm currently unable to process your request.";
  }

  const messages = [
    { role: "system", content: OPENAI_SYSTEM_PROMPT },
    ...history.slice(-10).map((m) => ({
      role: m.role,
      content: m.content,
    })),
    { role: "user", content: message },
  ];

  try {
    const res = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages,
          max_tokens: 1024,
          temperature: 0.7,
        }),
      },
    );

    if (!res.ok) {
      const errorBody = await res.text();
      console.error(
        "OpenAI API error:",
        res.status,
        errorBody,
      );
      return "I'm currently unable to process your request.";
    }

    const data = await res.json();
    return (
      data.choices?.[0]?.message?.content?.trim()
      ?? "I'm currently unable to process your request."
    );
  } catch (err) {
    console.error("OpenAI API call failed:", err);
    return "I'm currently unable to process your request.";
  }
}

// ---------------------------------------------------------------------------
// Call real backend PII redaction (Presidio + spaCy NLP)
// ---------------------------------------------------------------------------
export async function callBackendPIIRedact(
  text: string,
  sessionId: string,
  headers: Record<string, string>,
): Promise<{
  redacted_text: string;
  mappings: { token: string; type: string; score: number }[];
  pii_count: number;
  session_id: string;
  rehydration_mode: string;
  scoped: boolean;
} | null> {
  try {
    const res = await fetch(`${API_URL}/api/pii/redact`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        text,
        score_threshold: 0.4,
        session_id: sessionId,
      }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.error("Backend PII redaction failed:", {
      error:
        err instanceof Error ? err.message : String(err),
      text_length: text.length,
      api_url: `${API_URL}/api/pii/redact`,
    });
    return null;
  }
}

export async function callBackendPIIRestore(
  text: string,
  sessionId: string,
  headers: Record<string, string>,
): Promise<
  | {
      success: true;
      restoredText: string;
      rehydrated: boolean;
      unknownTokens: string[];
    }
  | {
      success: false;
      status: number;
      reason: string;
      errorCode?: string;
      unknownTokens?: string[];
    }
> {
  try {
    const res = await fetch(`${API_URL}/api/pii/restore`, {
      method: "POST",
      headers,
      body: JSON.stringify({ text, session_id: sessionId }),
    });

    if (res.ok) {
      const payload = await res.json();
      return {
        success: true,
        restoredText: payload.restored_text ?? text,
        rehydrated: Boolean(payload.rehydrated),
        unknownTokens: Array.isArray(payload.unknown_tokens)
          ? payload.unknown_tokens
          : [],
      };
    }

    let reason = `PII restore failed (${res.status})`;
    let errorCode: string | undefined;
    let unknownTokens: string[] | undefined;
    const errorPayload = await res.json().catch(async () => ({
      detail: await res.text().catch(() => ""),
    }));
    const detail = errorPayload?.detail ?? errorPayload;
    if (typeof detail === "string" && detail.length > 0) {
      reason = detail;
    } else if (detail && typeof detail === "object") {
      if (
        typeof detail.message === "string"
        && detail.message.length > 0
      ) {
        reason = detail.message;
      }
      if (typeof detail.error === "string") {
        errorCode = detail.error;
      }
      if (Array.isArray(detail.unknown_tokens)) {
        unknownTokens = detail.unknown_tokens;
      }
    }

    return {
      success: false,
      status: res.status,
      reason,
      errorCode,
      unknownTokens,
    };
  } catch (err) {
    return {
      success: false,
      status: 0,
      reason:
        err instanceof Error ? err.message : String(err),
    };
  }
}

// ---------------------------------------------------------------------------
// Log to the real audit trail
// ---------------------------------------------------------------------------
export async function logAuditEntry(
  headers: Record<string, string>,
  eventType: string,
  result: string,
  details: Record<string, unknown>,
): Promise<void> {
  try {
    await fetch(`${API_URL}/api/audit`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        event_type: eventType,
        tool: "playground",
        result,
        details,
      }),
    });
  } catch (err) {
    console.error("Audit logging failed:", {
      error:
        err instanceof Error ? err.message : String(err),
      event_type: eventType,
      result,
      timestamp: new Date().toISOString(),
    });
  }
}

// ---------------------------------------------------------------------------
// Ensure a backend PII session exists for this playground
// conversation
// ---------------------------------------------------------------------------
export async function ensurePIISession(
  headers: Record<string, string>,
  sessionId: string,
): Promise<boolean> {
  const scopedSessionId =
    getScopedPIISessionId(sessionId);
  const authenticatedUserId =
    getAuthenticatedUserId(headers);
  if (!authenticatedUserId) {
    console.warn(
      "PII session initialization failed: unable to resolve "
        + "authenticated user from access token",
      { session_id: scopedSessionId },
    );
    return false;
  }

  try {
    const res = await fetch(
      `${API_URL}/api/pii/sessions`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          session_id: scopedSessionId,
          user_id: authenticatedUserId,
          agent_id: "dashboard-playground",
          purpose:
            "Playground PII redaction and restoration flow",
        }),
      },
    );

    if (res.ok) {
      return true;
    }

    const errorText = await res.text();
    const normalized = errorText.toLowerCase();
    if (
      res.status === 409
      || normalized.includes("unique")
      || normalized.includes("already exists")
    ) {
      // Session already exists in backend; treat as
      // initialized.
      return true;
    }

    console.warn(
      "PII session initialization failed:",
      res.status,
      errorText,
    );
    return false;
  } catch (err) {
    console.error("PII session initialization failed:", {
      error:
        err instanceof Error ? err.message : String(err),
      session_id: sessionId,
    });
    return false;
  }
}

// ---------------------------------------------------------------------------
// Log trace to real backend so dashboard pages stay wired
// to playground usage
// ---------------------------------------------------------------------------
export async function logTrace(
  headers: Record<string, string>,
  data: {
    sessionId: string;
    message: string;
    processedMessage: string;
    aiResponse: string;
    blocked: boolean;
    blockReason?: string;
    blockRisk?: string;
    callCost: number;
    durationMs: number;
    templateId?: number | null;
    middlewareResults: MiddlewareResult[];
  },
): Promise<{ success: boolean; error?: string }> {
  try {
    const traceId =
      `pg_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const res = await fetch(`${API_URL}/api/traces`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        trace_id: traceId,
        tool: "playground_chat",
        status: data.blocked ? "blocked" : "success",
        blocked_by: data.blocked
          ? (data.blockReason ?? "playground_validator")
          : null,
        error: data.blocked
          ? (data.blockRisk ?? null)
          : null,
        cost: data.blocked ? 0 : data.callCost,
        duration_ms: data.durationMs,
        session_id: data.sessionId,
        agent_id: "dashboard-playground",
        inputs: {
          original_message: data.message,
          processed_message: data.processedMessage,
          template_id: data.templateId ?? null,
        },
        output: {
          response: data.aiResponse,
          blocked: data.blocked,
          middleware_results: data.middlewareResults.map(
            (m) => ({
              name: m.name,
              action: m.action,
              passed: m.passed,
            }),
          ),
        },
      }),
    });

    if (!res.ok) {
      const errorText = await res.text();
      console.error(
        "Trace logging failed:",
        res.status,
        errorText,
      );
      return {
        success: false,
        error: `HTTP ${res.status}: ${errorText}`,
      };
    }

    return { success: true };
  } catch (err) {
    console.error("Trace logging exception:", err);
    return { success: false, error: String(err) };
  }
}

export function getThreatSeverity(
  threatType: string,
): "critical" | "high" | "medium" | "low" {
  if (threatType.toLowerCase().includes("sql")) {
    return "critical";
  }
  if (threatType.toLowerCase().includes("shell")) {
    return "high";
  }
  if (threatType.toLowerCase().includes("code")) {
    return "high";
  }
  if (threatType.toLowerCase().includes("xss")) {
    return "medium";
  }
  return "low";
}

export async function logThreatEvent(
  headers: Record<string, string>,
  data: {
    sessionId: string;
    message: string;
    threatType: string;
    threatRisk: string;
  },
): Promise<void> {
  try {
    const res = await fetch(
      `${API_URL}/api/security/threats`,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          event_type: "playground_threat_blocked",
          severity: getThreatSeverity(data.threatType),
          target: "playground_chat",
          description: `${data.threatType} blocked in playground`,
          metadata_json: {
            source: "playground",
            session_id: data.sessionId,
            risk: data.threatRisk,
            message_preview: data.message.slice(0, 200),
          },
        }),
      },
    );

    if (!res.ok) {
      const body = await res.text();
      console.warn(
        "Threat logging failed:",
        res.status,
        body,
      );
    }
  } catch (err) {
    console.error("Threat logging exception:", err);
  }
}
