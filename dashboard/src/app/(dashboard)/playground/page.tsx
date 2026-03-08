"use client";

import React, { useState, useRef, useEffect } from "react";
import {
  Send,
  Bot,
  User,
  Loader2,
  CheckCircle2,
  XCircle,
  Shield,
  Zap,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
  Lock,
  Clock,
  DollarSign,
  Eye,
  EyeOff,
  RefreshCw,
  ArrowRight,
  ExternalLink,
  Database,
  FileText,
  TrendingUp,
  Sparkles,
} from "lucide-react";
import Link from "next/link";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface MiddlewareResult {
  name: string;
  enabled: boolean;
  passed: boolean;
  action: string;
  before?: string;
  after?: string;
  piiFound?: { type: string; original: string; masked: string }[];
  details?: string;
}

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  blocked?: boolean;
  middlewareResults?: MiddlewareResult[];
  originalMessage?: string;
  whatWasSentToAI?: string;
  risksWithoutAgentGate?: string[];
}

interface Stats {
  callCount: number;
  rateLimit: number;
  rateLimitRemaining: number;
  totalCost: number;
  budget: number;
}

interface MiddlewareSettings {
  piiProtection: boolean;
  validator: boolean;
  rateLimiter: boolean;
  costTracker: boolean;
}

const DEMO_SCENARIOS = [
  {
    label: "Normal Chat",
    prompt: "Hello! Can you help me write a professional email?",
    description: "See normal AI conversation flow",
  },
  {
    label: "PII Exposure Risk",
    prompt: "My SSN is 123-45-6789 and my email is john.smith@company.com",
    description: "Watch PII get detected & masked",
  },
  {
    label: "SQL Injection Attack",
    prompt: "DROP TABLE users; SELECT * FROM passwords",
    description: "See malicious queries blocked",
  },
  {
    label: "Credit Card Leak",
    prompt: "Process payment for card 4111-1111-1111-1111",
    description: "PCI compliance protection",
  },
];

export default function PlaygroundPage() {
  const [sessionId, setSessionId] = useState("default");

  useEffect(() => {
    const stored = localStorage.getItem("playground_session_id");
    if (stored) {
      setSessionId(stored);
    } else {
      const newId = `pg_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      localStorage.setItem("playground_session_id", newId);
      setSessionId(newId);
    }
  }, []);

  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [stats, setStats] = useState<Stats>({
    callCount: 0,
    rateLimit: 20,
    rateLimitRemaining: 20,
    totalCost: 0,
    budget: 1.0,
  });
  const [middleware, setMiddleware] = useState<MiddlewareSettings>({
    piiProtection: true,
    validator: true,
    rateLimiter: true,
    costTracker: true,
  });
  const [lastResults, setLastResults] = useState<MiddlewareResult[]>([]);
  const [showComparison, setShowComparison] = useState<Message | null>(null);
  const [copied, setCopied] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Prompt template state
  const [templates, setTemplates] = useState<any[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState<number | null>(null);
  const [showTemplatePreview, setShowTemplatePreview] = useState(false);

  // Only auto-scroll when user sends a message, not when AI responds
  // This prevents viewport snapping when right column expands
  const shouldAutoScroll = useRef(false);

  useEffect(() => {
    if (shouldAutoScroll.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
      shouldAutoScroll.current = false;
    }
  }, [messages]);

  // Load prompt templates
  useEffect(() => {
    const fetchTemplates = async () => {
      try {
        const res = await fetch("/api/prompt-templates?active_only=true&limit=20");
        if (res.ok) {
          const data = await res.json();
          setTemplates(data);
        }
      } catch (error) {
        console.error("Failed to load templates:", error);
      }
    };
    fetchTemplates();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: "user",
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);
    shouldAutoScroll.current = true; // Only scroll when user sends message

    try {
      const response = await fetch("/api/playground/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMessage.content,
          middleware,
          sessionId,
          templateId: selectedTemplateId,
        }),
      });

      const data = await response.json();

      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: data.response,
        timestamp: new Date(),
        blocked: data.blocked,
        middlewareResults: data.middlewareResults,
        originalMessage: data.originalMessage,
        whatWasSentToAI: data.whatWasSentToAI,
        risksWithoutAgentGate: data.risksWithoutAgentGate,
      };

      setMessages((prev) => [...prev, assistantMessage]);
      setLastResults(data.middlewareResults || []);

      if (data.stats) {
        setStats(data.stats);
      }

      // Auto-show comparison if PII was found or threat blocked
      if (data.risksWithoutAgentGate?.length > 0 || data.blocked) {
        setShowComparison(assistantMessage);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content: "Error processing request.",
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearChat = async () => {
    await fetch(`/api/playground/chat?sessionId=${sessionId}`, { method: "DELETE" });
    setMessages([]);
    setLastResults([]);
    setShowComparison(null);
    setStats({ callCount: 0, rateLimit: 20, rateLimitRemaining: 20, totalCost: 0, budget: 1.0 });

    // Generate new session ID
    const newId = `pg_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
    localStorage.setItem("playground_session_id", newId);
    window.location.reload(); // Reload to pick up new session ID
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(`from ea_agentgate import Agent
from ea_agentgate.middleware import PIIProtector, Validator, RateLimiter, CostTracker

# Create a governed AI agent
agent = Agent(
    model="gpt-4",
    middleware=[
        PIIProtector(mask_ssn=True, mask_email=True, mask_credit_card=True),
        Validator(block_sql_injection=True, block_xss=True),
        RateLimiter(max_calls=100, window="1m"),
        CostTracker(budget=10.00, alert_threshold=0.8),
    ]
)

# Every AI call is now protected
response = agent.chat("Process user request here...")
print(response)  # PII masked, threats blocked, costs tracked`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleMiddleware = (key: keyof MiddlewareSettings) => {
    setMiddleware((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const allEnabled = Object.values(middleware).every(Boolean);
  const noneEnabled = Object.values(middleware).every((v) => !v);

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Governance Playground</h1>
          <p className="text-muted-foreground">
            Chat with AI and see AgentGate protection in real-time
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Session: <code className="rounded bg-muted px-1 py-0.5">{sessionId}</code>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handleClearChat}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Reset
          </Button>
        </div>
      </div>

      {/* Warning Banner when middleware disabled */}
      {!allEnabled && (
        <div className="rounded-lg border border-warning-200 bg-warning-50 p-3">
          <div className="flex items-center gap-2 text-warning">
            <AlertTriangle className="h-5 w-5" />
            <span className="font-semibold">Protection Disabled</span>
          </div>
          <p className="mt-1 text-sm text-warning">
            {noneEnabled
              ? "All protections are OFF. Your data and system are exposed!"
              : "Some protections are disabled. Toggle them above to see the difference."}
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12 lg:items-start">
        {/* Main Chat Area */}
        <div className="lg:col-span-8">
          <Card className="flex h-[60vh] flex-col lg:h-[calc(100vh-12rem)]">
            {/* Chat Header with Stats */}
            <CardHeader className="border-b py-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
                    <Bot className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-base">AI Assistant</CardTitle>
                    <CardDescription className="text-xs">
                      {allEnabled ? "🛡️ Protected by AgentGate" : "⚠️ Unprotected"}
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <div className="flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className={stats.rateLimitRemaining <= 5 ? "text-warning font-medium" : "text-muted-foreground"}>
                      {stats.rateLimitRemaining} calls left
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <DollarSign className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className={stats.totalCost >= stats.budget * 0.8 ? "text-danger font-medium" : "text-muted-foreground"}>
                      ${stats.totalCost.toFixed(3)}
                    </span>
                  </div>
                </div>
              </div>
            </CardHeader>

            {/* Messages */}
            <CardContent className="flex-1 overflow-y-auto p-4">
              {messages.length === 0 ? (
                <div className="flex h-full flex-col items-center justify-center">
                  <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-primary/20 to-primary/5">
                    <Shield className="h-8 w-8 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold">Try the Demo Scenarios</h3>
                  <p className="mt-1 max-w-md text-center text-sm text-muted-foreground">
                    See how AgentGate protects your AI applications from data leaks, attacks, and cost overruns.
                  </p>
                  <div className="mt-6 grid w-full max-w-lg grid-cols-2 gap-2">
                    {DEMO_SCENARIOS.map((scenario) => (
                      <button
                        key={scenario.label}
                        onClick={() => setInput(scenario.prompt)}
                        className="rounded-lg border border-border bg-card p-3 text-left transition-all hover:border-primary hover:bg-primary/5"
                      >
                        <span className="text-sm font-medium">{scenario.label}</span>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          {scenario.description}
                        </p>
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {messages.map((message) => (
                    <div
                      key={message.id}
                      className={`flex gap-3 ${message.role === "user" ? "justify-end" : ""}`}
                    >
                      {message.role === "assistant" && (
                        <div
                          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${
                            message.blocked ? "bg-danger-50" : "bg-primary/10"
                          }`}
                        >
                          {message.blocked ? (
                            <Shield className="h-4 w-4 text-danger" />
                          ) : (
                            <Bot className="h-4 w-4 text-primary" />
                          )}
                        </div>
                      )}
                      <div className="max-w-[80%] space-y-2">
                        <div
                          className={`rounded-lg px-4 py-3 ${
                            message.role === "user"
                              ? "bg-primary text-primary-foreground"
                              : message.blocked
                              ? "border border-danger-200 bg-danger-50"
                              : "bg-muted"
                          }`}
                        >
                          <div
                            className="prose prose-sm dark:prose-invert max-w-none text-sm"
                            dangerouslySetInnerHTML={{
                              __html: message.content
                                .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
                                .replace(/\n\n/g, "<br/><br/>")
                                .replace(/\n•/g, "<br/>•")
                                .replace(/\n/g, "<br/>"),
                            }}
                          />
                        </div>

                        {/* Show comparison button if there was PII or threat */}
                        {message.role === "assistant" &&
                          (message.risksWithoutAgentGate?.length ?? 0) > 0 && (
                            <button
                              onClick={() => setShowComparison(showComparison?.id === message.id ? null : message)}
                              className="flex items-center gap-1.5 text-xs text-primary hover:underline"
                            >
                              {showComparison?.id === message.id ? (
                                <EyeOff className="h-3.5 w-3.5" />
                              ) : (
                                <Eye className="h-3.5 w-3.5" />
                              )}
                              {showComparison?.id === message.id
                                ? "Hide protection details"
                                : "See what AgentGate protected"}
                            </button>
                          )}

                        {/* Comparison View */}
                        {showComparison?.id === message.id && message.originalMessage && (
                          <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm">
                            <div className="mb-2 flex items-center gap-2 font-medium text-primary">
                              <Shield className="h-4 w-4" />
                              AgentGate Protection Summary
                            </div>

                            <div className="space-y-3">
                              {/* What you typed vs what was sent */}
                              {message.whatWasSentToAI !== message.originalMessage && (
                                <div className="grid gap-2">
                                  <div className="rounded bg-danger-50 p-2">
                                    <div className="mb-1 text-xs font-medium text-danger">
                                      ❌ Without AgentGate (sent to AI):
                                    </div>
                                    <code className="text-xs text-danger">
                                      {message.originalMessage}
                                    </code>
                                  </div>
                                  <div className="flex items-center justify-center">
                                    <ArrowRight className="h-4 w-4 text-primary" />
                                  </div>
                                  <div className="rounded bg-success-50 p-2">
                                    <div className="mb-1 text-xs font-medium text-success">
                                      ✅ With AgentGate (sent to AI):
                                    </div>
                                    <code className="text-xs text-success">
                                      {message.whatWasSentToAI}
                                    </code>
                                  </div>
                                </div>
                              )}

                              {/* Risks prevented */}
                              {message.risksWithoutAgentGate && message.risksWithoutAgentGate.length > 0 && (
                                <div className="rounded bg-warning-50 p-2">
                                  <div className="mb-1 text-xs font-medium text-warning">
                                    ⚠️ Risks Prevented:
                                  </div>
                                  <ul className="text-xs text-warning">
                                    {message.risksWithoutAgentGate.map((risk, i) => (
                                      <li key={i}>• {risk}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                      {message.role === "user" && (
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary">
                          <User className="h-4 w-4 text-primary-foreground" />
                        </div>
                      )}
                    </div>
                  ))}
                  {isLoading && (
                    <div className="flex gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                        <Loader2 className="h-4 w-4 animate-spin text-primary" />
                      </div>
                      <div className="rounded-lg bg-muted px-4 py-3 text-sm text-muted-foreground">
                        Processing through middleware...
                      </div>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </div>
              )}
            </CardContent>

            {/* Input */}
            <div className="border-t p-4 space-y-3">
              {/* Template Selector */}
              {templates.length > 0 && (
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-purple-500" />
                  <select
                    value={selectedTemplateId || ""}
                    onChange={(e) => {
                      const val = e.target.value;
                      setSelectedTemplateId(val ? parseInt(val) : null);
                    }}
                    className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    <option value="">No prompt template (raw input)</option>
                    {templates.map((t: any) => (
                      <option key={t.id} value={t.id}>
                        {t.name} ({t.category.replace(/_/g, " ")})
                      </option>
                    ))}
                  </select>
                  {selectedTemplateId && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setShowTemplatePreview(!showTemplatePreview)}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              )}

              {/* Template Preview */}
              {showTemplatePreview && selectedTemplateId && (
                <div className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-3 text-sm">
                  <div className="font-medium text-purple-700 dark:text-purple-300 mb-1">
                    Selected Template:
                  </div>
                  <div className="text-muted-foreground">
                    {templates.find((t: any) => t.id === selectedTemplateId)?.description || "Template will enhance your prompt"}
                  </div>
                </div>
              )}

              <form onSubmit={handleSubmit} className="flex gap-2">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Type a message (try including an SSN or SQL query)..."
                  className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
                  disabled={isLoading}
                />
                <Button type="submit" disabled={isLoading || !input.trim()}>
                  {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                </Button>
              </form>
            </div>
          </Card>
        </div>

        {/* Sidebar - Middleware Controls */}
        <div className="space-y-4 lg:col-span-4 lg:sticky lg:top-4 lg:max-h-[calc(100vh-12rem)] lg:overflow-y-auto">
          {/* Middleware Toggles */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Zap className="h-4 w-4 text-warning" />
                Protection Controls
              </CardTitle>
              <CardDescription className="text-xs">
                Toggle to see what happens without protection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {/* PII Protection */}
              <button
                onClick={() => toggleMiddleware("piiProtection")}
                className={`flex w-full items-center justify-between rounded-lg border p-3 transition-all ${
                  middleware.piiProtection
                    ? "border-success-200 bg-success-50"
                    : "border-danger-200 bg-danger-50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Lock className={`h-4 w-4 ${middleware.piiProtection ? "text-success" : "text-danger"}`} />
                  <div className="text-left">
                    <div className="text-sm font-medium">PII Protection</div>
                    <div className="text-xs text-muted-foreground">SSN, emails, cards</div>
                  </div>
                </div>
                {middleware.piiProtection ? (
                  <CheckCircle2 className="h-5 w-5 text-success" />
                ) : (
                  <XCircle className="h-5 w-5 text-danger" />
                )}
              </button>

              {/* Security Validator */}
              <button
                onClick={() => toggleMiddleware("validator")}
                className={`flex w-full items-center justify-between rounded-lg border p-3 transition-all ${
                  middleware.validator
                    ? "border-success-200 bg-success-50"
                    : "border-danger-200 bg-danger-50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Shield className={`h-4 w-4 ${middleware.validator ? "text-success" : "text-danger"}`} />
                  <div className="text-left">
                    <div className="text-sm font-medium">Security Validator</div>
                    <div className="text-xs text-muted-foreground">SQL injection, XSS</div>
                  </div>
                </div>
                {middleware.validator ? (
                  <CheckCircle2 className="h-5 w-5 text-success" />
                ) : (
                  <XCircle className="h-5 w-5 text-danger" />
                )}
              </button>

              {/* Rate Limiter */}
              <button
                onClick={() => toggleMiddleware("rateLimiter")}
                className={`flex w-full items-center justify-between rounded-lg border p-3 transition-all ${
                  middleware.rateLimiter
                    ? "border-success-200 bg-success-50"
                    : "border-danger-200 bg-danger-50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Clock className={`h-4 w-4 ${middleware.rateLimiter ? "text-success" : "text-danger"}`} />
                  <div className="text-left">
                    <div className="text-sm font-medium">Rate Limiter</div>
                    <div className="text-xs text-muted-foreground">20 req/min</div>
                  </div>
                </div>
                {middleware.rateLimiter ? (
                  <CheckCircle2 className="h-5 w-5 text-success" />
                ) : (
                  <XCircle className="h-5 w-5 text-danger" />
                )}
              </button>

              {/* Cost Tracker */}
              <button
                onClick={() => toggleMiddleware("costTracker")}
                className={`flex w-full items-center justify-between rounded-lg border p-3 transition-all ${
                  middleware.costTracker
                    ? "border-success-200 bg-success-50"
                    : "border-danger-200 bg-danger-50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <DollarSign className={`h-4 w-4 ${middleware.costTracker ? "text-success" : "text-danger"}`} />
                  <div className="text-left">
                    <div className="text-sm font-medium">Cost Tracker</div>
                    <div className="text-xs text-muted-foreground">$1.00 budget</div>
                  </div>
                </div>
                {middleware.costTracker ? (
                  <CheckCircle2 className="h-5 w-5 text-success" />
                ) : (
                  <XCircle className="h-5 w-5 text-danger" />
                )}
              </button>
            </CardContent>
          </Card>

          {/* Live Middleware Results */}
          {lastResults.length > 0 && (
            <Card>
              <CardHeader className="py-3">
                <CardTitle className="text-sm">Last Request Results</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5">
                {lastResults.map((result, idx) => (
                  <div
                    key={idx}
                    className={`rounded border p-2 text-xs ${
                      !result.enabled
                        ? "border-gray-500/30 bg-gray-500/5"
                        : result.passed
                        ? "border-success-200 bg-success-50"
                        : "border-danger-200 bg-danger-50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{result.name}</span>
                      <span
                        className={
                          !result.enabled
                            ? "text-gray-500 dark:text-gray-400"
                            : result.passed
                            ? "text-success"
                            : "text-danger"
                        }
                      >
                        {result.action}
                      </span>
                    </div>
                    {result.details && (
                      <p className="mt-1 text-muted-foreground">{result.details}</p>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* View in Dashboard Links */}
          {messages.length > 0 && (
            <Card>
              <CardHeader className="py-3">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Database className="h-4 w-4" />
                  View in Dashboard
                </CardTitle>
                <CardDescription className="text-xs">
                  See where this session&apos;s data is stored
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                <Link href="/pii" className="flex items-center justify-between rounded-lg border border-border bg-card p-2 text-xs transition-all hover:border-primary hover:bg-primary/5">
                  <div className="flex items-center gap-2">
                    <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                    <span>Data Protection</span>
                  </div>
                  <ExternalLink className="h-3 w-3 text-muted-foreground" />
                </Link>
              </CardContent>
            </Card>
          )}

          {/* Code Example */}
          <Card>
            <CardHeader className="py-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Terminal className="h-4 w-4" />
                  Python SDK
                </CardTitle>
                <Button variant="ghost" size="sm" onClick={handleCopyCode} className="h-7 px-2">
                  {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded bg-slate-950 p-2 text-[10px] leading-relaxed text-slate-300">
                <code>{`agent = Agent(middleware=[
  PIIProtector(...),
  Validator(...),
  RateLimiter(...),
  CostTracker(...),
])

response = agent.chat("...")`}</code>
              </pre>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
