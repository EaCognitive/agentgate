/**
 * Shared type definitions and constants for the playground chat route.
 */

// ---------------------------------------------------------------------------
// Session state (in-memory per instance -- acceptable for a demo)
// ---------------------------------------------------------------------------
export interface SessionState {
  callCount: number;
  totalCost: number;
  budget: number;
  rateLimit: number;
  windowStart: number;
  conversationHistory: { role: string; content: string }[];
  piiSessionInitialized: boolean;
}

export interface MiddlewareResult {
  name: string;
  enabled: boolean;
  passed: boolean;
  action: string;
  before?: string;
  after?: string;
  piiFound?: { type: string; original: string; masked: string }[];
  rehydration?: {
    attempted: boolean;
    rehydrated: boolean;
    reason?: string | null;
  };
  details?: string;
}

// ---------------------------------------------------------------------------
// Security patterns (validated locally -- the backend threat detector is
// middleware-level and not exposed as a callable endpoint)
// ---------------------------------------------------------------------------
export const DANGEROUS_OPS = [
  {
    pattern: /\bDROP\s+(TABLE|DATABASE)/i,
    type: "SQL Injection",
    risk: "Data loss, system compromise",
  },
  {
    pattern: /\bDELETE\s+FROM/i,
    type: "SQL Injection",
    risk: "Data deletion",
  },
  {
    pattern: /\brm\s+-rf/i,
    type: "Shell Injection",
    risk: "System destruction",
  },
  {
    pattern: /\bexec\s*\(|eval\s*\(/i,
    type: "Code Injection",
    risk: "Remote code execution",
  },
  {
    pattern: /<script|javascript:/i,
    type: "XSS Attack",
    risk: "Cross-site scripting",
  },
];

// Lightweight local PII regex for the comparison panel. The real detection
// is done server-side by Presidio + spaCy via /api/pii/redact.
// This is only a hinting layer for the UI and never the source of truth.
export const LOCAL_PII_PATTERNS: {
  type: string;
  pattern: RegExp;
}[] = [
  {
    type: "SSN",
    pattern: /\b(\d{3})[-\s]?(\d{2})[-\s]?(\d{4})\b/g,
  },
  {
    type: "CREDIT_CARD",
    pattern:
      /\b(\d{4})[-\s]?(\d{4})[-\s]?(\d{4})[-\s]?(\d{4})\b/g,
  },
  {
    type: "EMAIL",
    pattern:
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  },
  {
    type: "PHONE",
    pattern: /\b(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4})\b/g,
  },
  {
    type: "API_KEY",
    pattern:
      /\b(sk-[a-zA-Z0-9]{20,}|api[_-]?key[=:]\s*['"]?[a-zA-Z0-9]{20,})/gi,
  },
];

export const PLAYGROUND_PII_SESSION_PREFIX = "playground_";

// ---------------------------------------------------------------------------
// Call OpenAI Chat Completions API
// ---------------------------------------------------------------------------
export const OPENAI_SYSTEM_PROMPT =
  "You are a helpful AI assistant. Answer the user's questions " +
  "directly and concisely.";
