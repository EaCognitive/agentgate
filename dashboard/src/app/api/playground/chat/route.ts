import { NextRequest, NextResponse } from "next/server";
import { getAuthHeaders, API_URL } from "@/lib/api-auth";

import {
  MiddlewareResult,
  DANGEROUS_OPS,
} from "./_lib/types";

import {
  sessions,
  getScopedPIISessionId,
  collectLocalPIIHints,
  getSession,
  callOpenAI,
  callBackendPIIRedact,
  callBackendPIIRestore,
  logAuditEntry,
  ensurePIISession,
  logTrace,
  logThreatEvent,
} from "./_lib/helpers";

// ---------------------------------------------------------------------------
// POST /api/playground/chat
// ---------------------------------------------------------------------------
export async function POST(req: NextRequest) {
  try {
    const {
      message,
      sessionId = "default",
      templateId = null,
      middleware = {},
    } = await req.json();

    if (!message || typeof message !== "string") {
      return NextResponse.json(
        { error: "Message required" },
        { status: 400 },
      );
    }

    const session = getSession(sessionId);
    const middlewareResults: MiddlewareResult[] = [];
    let processedMessage = message;
    let blocked = false;
    let blockReason: string | undefined;
    let blockRisk: string | undefined;

    const settings = {
      piiProtection: middleware.piiProtection !== false,
      validator: middleware.validator !== false,
      rateLimiter: middleware.rateLimiter !== false,
      costTracker: middleware.costTracker !== false,
    };

    // Obtain auth headers to call real backend
    const headers = await getAuthHeaders();

    // ----------------------------------------------------------------
    // 1. PII PROTECTION -- call real backend when possible
    // ----------------------------------------------------------------
    let piiFound: {
      type: string;
      original: string;
      masked: string;
    }[] = [];
    const localPIIHints = collectLocalPIIHints(message);
    const scopedPIISessionId =
      getScopedPIISessionId(sessionId);
    let backendRedacted = false;
    let piiProtectionFailureReason: string | null = null;

    if (
      settings.piiProtection
      && headers
      && !session.piiSessionInitialized
    ) {
      session.piiSessionInitialized =
        await ensurePIISession(headers, sessionId);
    }

    if (
      headers
      && settings.piiProtection
      && session.piiSessionInitialized
    ) {
      const backendResult = await callBackendPIIRedact(
        message,
        scopedPIISessionId,
        headers,
      );
      if (backendResult && backendResult.pii_count > 0) {
        backendRedacted = true;
        piiFound = backendResult.mappings.map(
          (mapping, index) => ({
            type: mapping.type,
            original:
              localPIIHints[index]?.original
              ?? "[vault-managed]",
            masked: mapping.token,
          }),
        );
        if (settings.piiProtection) {
          processedMessage = backendResult.redacted_text;
        }
      }
    }

    if (!backendRedacted && localPIIHints.length > 0) {
      piiFound = localPIIHints;
      if (settings.piiProtection) {
        piiProtectionFailureReason =
          "Scoped backend redaction unavailable; "
          + "fail-closed policy blocked message to "
          + "prevent PII leakage.";
        blocked = true;
        blockReason = "PII protection unavailable";
        blockRisk =
          "PII detected locally but backend tokenization "
          + "was unavailable for the session.";
      }
    }

    if (piiFound.length > 0) {
      const piiAction = settings.piiProtection
        ? backendRedacted
          ? "PROTECTED"
          : "BLOCKED"
        : "EXPOSED";
      middlewareResults.push({
        name: "PII Protection",
        enabled: settings.piiProtection,
        passed: settings.piiProtection
          ? backendRedacted
          : true,
        action: piiAction,
        before: message,
        after:
          settings.piiProtection && backendRedacted
            ? processedMessage
            : message,
        piiFound: piiFound.map((p) => ({
          type: p.type,
          original: p.original,
          masked: p.masked,
        })),
        details: settings.piiProtection
          ? backendRedacted
            ? `Protected ${piiFound.length} sensitive item(s) `
              + "using scoped backend tokenization. AI receives "
              + "synthetic placeholders and response rehydration "
              + "is enforced through backend restore."
            : piiProtectionFailureReason
              ?? "PII protection is enabled, but scoped "
                + "backend tokenization was unavailable."
          : `WARNING: ${piiFound.length} PII item(s) would be `
            + "sent to external AI in clear text: "
            + piiFound.map((p) => p.type).join(", "),
      });
    } else {
      middlewareResults.push({
        name: "PII Protection",
        enabled: settings.piiProtection,
        passed: true,
        action: "CLEAN",
        details: "No sensitive data detected in message",
      });
    }

    // ----------------------------------------------------------------
    // 2. SECURITY VALIDATOR
    // ----------------------------------------------------------------
    let threatDetected: {
      type: string;
      risk: string;
    } | null = null;
    for (const { pattern, type, risk } of DANGEROUS_OPS) {
      if (pattern.test(message)) {
        threatDetected = { type, risk };
        break;
      }
    }

    if (threatDetected) {
      middlewareResults.push({
        name: "Security Validator",
        enabled: settings.validator,
        passed: !settings.validator,
        action: settings.validator ? "BLOCKED" : "ALLOWED",
        details: settings.validator
          ? `Blocked ${threatDetected.type} attempt. `
            + `Risk: ${threatDetected.risk}`
          : `DANGER: ${threatDetected.type} would be `
            + `executed! Risk: ${threatDetected.risk}`,
      });

      if (settings.validator) {
        blocked = true;
        blockReason = threatDetected.type;
        blockRisk = threatDetected.risk;
      }
    } else {
      middlewareResults.push({
        name: "Security Validator",
        enabled: settings.validator,
        passed: true,
        action: "SAFE",
        details: "No security threats detected",
      });
    }

    // ----------------------------------------------------------------
    // 3. RATE LIMITER
    // ----------------------------------------------------------------
    session.callCount++;
    const remaining =
      session.rateLimit - session.callCount;
    const rateLimited =
      session.callCount > session.rateLimit;

    middlewareResults.push({
      name: "Rate Limiter",
      enabled: settings.rateLimiter,
      passed: !rateLimited || !settings.rateLimiter,
      action: rateLimited
        ? settings.rateLimiter
          ? "BLOCKED"
          : "OVER LIMIT"
        : `${remaining}/${session.rateLimit}`,
      details: rateLimited
        ? settings.rateLimiter
          ? "Rate limit exceeded. Prevents abuse "
            + "and runaway costs."
          : `${session.callCount} calls made! Without `
            + "limits, this could cost $$$ in API fees."
        : `${remaining} requests remaining this minute`,
    });

    if (
      rateLimited
      && settings.rateLimiter
      && !blocked
    ) {
      blocked = true;
      blockReason = "Rate limit exceeded";
      blockRisk = "Prevents abuse, controls costs";
    }

    // ----------------------------------------------------------------
    // 4. COST TRACKER
    // ----------------------------------------------------------------
    const callCost = 0.003;
    const wouldExceed =
      session.totalCost + callCost > session.budget;

    if (!blocked) {
      if (wouldExceed && settings.costTracker) {
        middlewareResults.push({
          name: "Cost Tracker",
          enabled: settings.costTracker,
          passed: false,
          action: "BLOCKED",
          details:
            `Budget exhausted `
            + `($${session.totalCost.toFixed(2)}`
            + `/$${session.budget.toFixed(2)}). `
            + "Prevents billing surprises.",
        });
        blocked = true;
        blockReason = "Budget limit reached";
        blockRisk = "Prevents unexpected charges";
      } else {
        if (!blocked) session.totalCost += callCost;
        middlewareResults.push({
          name: "Cost Tracker",
          enabled: settings.costTracker,
          passed: true,
          action: `$${session.totalCost.toFixed(3)}`,
          details: settings.costTracker
            ? `Tracking: $${session.totalCost.toFixed(3)} `
              + `of $${session.budget.toFixed(2)} `
              + "budget used"
            : "No budget controls. Current session: "
              + `$${session.totalCost.toFixed(3)}`,
        });
      }
    }

    // ----------------------------------------------------------------
    // 5. GENERATE RESPONSE
    // ----------------------------------------------------------------
    let aiResponse: string;
    let aiResponseWithPlaceholders = "";
    const rehydrationState: {
      attempted: boolean;
      rehydrated: boolean;
      reason: string | null;
    } = {
      attempted: false,
      rehydrated: false,
      reason: null,
    };
    const startedAt = Date.now();

    if (blocked) {
      aiResponse =
        `**Request Blocked**\n\n`
        + "This request was intercepted by AgentGate "
        + "before reaching the model.\n\n"
        + `**Classification:** ${blockReason}\n`
        + `**Risk:** ${blockRisk}\n\n`
        + "In production, this event would be logged to "
        + "the audit trail and surfaced on the Security "
        + "Threats dashboard. Toggle the corresponding "
        + "protection off in the sidebar to observe what "
        + "would happen without governance in place.";
    } else {
      session.conversationHistory.push({
        role: "user",
        content: processedMessage,
      });
      aiResponseWithPlaceholders = await callOpenAI(
        processedMessage,
        session.conversationHistory,
      );

      aiResponse = aiResponseWithPlaceholders;

      if (
        settings.piiProtection
        && backendRedacted
        && headers
      ) {
        rehydrationState.attempted = true;
        const restoreResult =
          await callBackendPIIRestore(
            aiResponseWithPlaceholders,
            scopedPIISessionId,
            headers,
          );
        if (restoreResult.success) {
          aiResponse = restoreResult.restoredText;
          rehydrationState.rehydrated =
            restoreResult.rehydrated;
          if (!restoreResult.rehydrated) {
            rehydrationState.reason =
              "No known scoped placeholders were "
              + "present in the model response.";
          }
        } else {
          rehydrationState.reason = restoreResult.reason;
          if (
            restoreResult.errorCode === "unknown_token"
            || restoreResult.errorCode
              === "token_integrity_failure"
          ) {
            blocked = true;
            blockReason = "PII token integrity failure";
            blockRisk = restoreResult.reason;
            aiResponse =
              `**Response Blocked**\n\n`
              + "The model response included token "
              + "content that failed scoped vault "
              + "validation.\n\n"
              + `**Reason:** ${restoreResult.reason}\n\n`
              + "The response was withheld under "
              + "fail-closed policy.";
          }
        }
      }

      if (
        !blocked
        && aiResponseWithPlaceholders.length > 0
      ) {
        session.conversationHistory.push({
          role: "assistant",
          content: aiResponseWithPlaceholders,
        });
      }

      if (session.conversationHistory.length > 20) {
        session.conversationHistory =
          session.conversationHistory.slice(-20);
      }
    }

    const piiResult = middlewareResults.find(
      (m) => m.name === "PII Protection",
    );
    if (piiResult) {
      piiResult.rehydration = rehydrationState;
      if (
        rehydrationState.attempted
        && rehydrationState.reason
      ) {
        piiResult.details =
          `${piiResult.details ?? ""} Rehydration: `
          + `${rehydrationState.reason}`.trim();
      }
    }

    // ----------------------------------------------------------------
    // 6. PERSIST TO REAL BACKEND -- Audit, PII Vault,
    //    Cost Tracking
    // ----------------------------------------------------------------
    if (headers) {
      const auditDetails: Record<string, unknown> = {
        session_id: sessionId,
        user_message: message,
        ai_response: aiResponse,
        pii_detected: piiFound.length,
        pii_types: piiFound.map((p) => p.type),
        security_threat: threatDetected?.type ?? null,
        blocked,
        middleware_settings: settings,
        cost: session.totalCost,
      };

      // Log to audit trail
      await logAuditEntry(
        headers,
        blocked
          ? "playground_blocked"
          : "playground_chat",
        blocked ? "blocked" : "success",
        auditDetails,
      );

      // Persist a trace entry so traces/cost dashboards
      // reflect playground usage.
      const traceResult = await logTrace(headers, {
        sessionId,
        message,
        processedMessage,
        aiResponse,
        blocked,
        blockReason,
        blockRisk,
        callCost,
        durationMs: Date.now() - startedAt,
        templateId,
        middlewareResults,
      });

      if (!traceResult.success) {
        console.warn(
          "Failed to log trace to backend:",
          traceResult.error,
        );
      }

      if (blocked && threatDetected) {
        await logThreatEvent(headers, {
          sessionId,
          message,
          threatType: threatDetected.type,
          threatRisk: threatDetected.risk,
        });
      }
    }

    // ----------------------------------------------------------------
    // 7. BUILD RESPONSE
    // ----------------------------------------------------------------
    const risksWithout = [];
    if (piiFound.length > 0) {
      risksWithout.push(
        `${piiFound.length} PII items sent to external AI `
          + `(${piiFound.map((p) => p.type).join(", ")})`,
      );
    }
    if (threatDetected) {
      risksWithout.push(
        `${threatDetected.type} attack executed`,
      );
    }

    return NextResponse.json({
      response: aiResponse,
      blocked,
      blockReason,
      middlewareResults,
      whatWasSentToAI: processedMessage,
      originalMessage: message,
      risksWithoutAgentGate: risksWithout,
      stats: {
        callCount: session.callCount,
        rateLimit: session.rateLimit,
        rateLimitRemaining: Math.max(
          0,
          session.rateLimit - session.callCount,
        ),
        totalCost: session.totalCost,
        budget: session.budget,
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Internal error" },
      { status: 500 },
    );
  }
}

export async function DELETE(req: NextRequest) {
  const sessionId =
    new URL(req.url).searchParams.get("sessionId")
    || "default";
  const headers = await getAuthHeaders();
  let piiSessionCleared = false;
  if (headers) {
    const scopedPIISessionId =
      getScopedPIISessionId(sessionId);
    try {
      const response = await fetch(
        `${API_URL}/api/pii/sessions/`
          + `${encodeURIComponent(scopedPIISessionId)}`,
        {
          method: "DELETE",
          headers,
        },
      );
      piiSessionCleared =
        response.ok || response.status === 404;
    } catch (error) {
      console.warn(
        "Failed to clear backend PII session "
          + "during reset",
        error,
      );
    }
  }
  delete sessions[sessionId];
  return NextResponse.json({
    success: true,
    piiSessionCleared,
  });
}
