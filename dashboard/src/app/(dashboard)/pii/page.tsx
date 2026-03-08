"use client";

import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useSession } from "next-auth/react";
import {
  Shield,
  Lock,
  Key,
  AlertTriangle,
  CheckCircle,
  FileText,
  Users,
  Activity,
  RefreshCw,
  Download,
  Search,
} from "lucide-react";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useQuery } from "@tanstack/react-query";

import ComplianceTab from "./_components/ComplianceTab";
import type { ComplianceData } from "./_components/ComplianceTab";
import AuditTab from "./_components/AuditTab";
import type { PIIAuditEntry } from "./_components/AuditTab";
import SessionsTab from "./_components/SessionsTab";
import type { PIISession } from "./_components/SessionsTab";
import DetectionTab from "./_components/DetectionTab";
import KeyRotationModal from "./_components/KeyRotationModal";
import ExportModal from "./_components/ExportModal";

interface PIIStats {
  total_pii_stored: number;
  total_pii_retrieved: number;
  total_sessions: number;
  active_sessions: number;
  integrity_failures: number;
  access_denied_count: number;
  encryption_key_age_days: number;
  last_key_rotation: string | null;
}

async function fetchApi<T>(endpoint: string): Promise<T> {
  const res = await fetch(endpoint);
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

function usePIIStats() {
  return useQuery({
    queryKey: ["pii", "stats"],
    queryFn: () => fetchApi<PIIStats>("/api/pii/stats"),
    staleTime: 30000,
  });
}

function usePIIAudit(limit = 50) {
  return useQuery({
    queryKey: ["pii", "audit", limit],
    queryFn: () =>
      fetchApi<PIIAuditEntry[]>(
        `/api/pii/audit?limit=${limit}`,
      ),
    staleTime: 30000,
  });
}

function usePIISessions() {
  return useQuery({
    queryKey: ["pii", "sessions"],
    queryFn: () =>
      fetchApi<PIISession[]>(
        "/api/pii/sessions?limit=50",
      ),
    staleTime: 30000,
  });
}

function useCompliance() {
  return useQuery({
    queryKey: ["pii", "compliance"],
    queryFn: () =>
      fetchApi<ComplianceData>("/api/pii/compliance"),
    staleTime: 60000,
  });
}

type ActiveTab = "overview" | "audit" | "sessions" | "detection";

export default function PIIVaultPage() {
  const { data: session } = useSession();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<ActiveTab>(
    "overview",
  );
  const [showRotateModal, setShowRotateModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [detectionText, setDetectionText] = useState("");
  const [detectionResults, setDetectionResults] = useState<{
    entities: Array<{
      type: string;
      value: string;
      start: number;
      end: number;
    }>;
    redacted_text: string;
  } | null>(null);
  const [showRedacted, setShowRedacted] = useState(false);
  const [detectionSessionId] = useState(() => {
    const generated =
      `pii_detect_${Date.now()}`
      + `_${Math.random().toString(36).slice(2, 10)}`;
    if (typeof window === "undefined") {
      return generated;
    }
    const stored = window.localStorage.getItem(
      "pii_detection_session_id",
    );
    if (stored) {
      return stored;
    }
    window.localStorage.setItem(
      "pii_detection_session_id",
      generated,
    );
    return generated;
  });
  const [detectionSessionReady, setDetectionSessionReady] =
    useState(false);

  const {
    data: stats,
    isLoading: statsLoading,
  } = usePIIStats();
  const {
    data: auditLog,
    isLoading: auditLoading,
  } = usePIIAudit();
  const {
    data: sessions,
    isLoading: sessionsLoading,
  } = usePIISessions();
  const {
    data: compliance,
    isLoading: complianceLoading,
  } = useCompliance();

  const ensureDetectionSession = async (): Promise<void> => {
    if (detectionSessionReady) {
      return;
    }

    const res = await fetch("/api/pii/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: detectionSessionId,
        user_id: session?.user?.email || "unknown-user",
        agent_id: "dashboard-pii-page",
        purpose:
          "Dashboard PII detection and redaction workflow",
        channel_id: "dashboard",
        conversation_id: detectionSessionId,
      }),
    });

    if (!res.ok) {
      const errorText = await res.text();
      const normalized = errorText.toLowerCase();
      const alreadyExists =
        res.status === 409
        || normalized.includes("unique")
        || normalized.includes("already exists");
      if (!alreadyExists) {
        throw new Error(
          `Failed to initialize PII session: ${errorText}`,
        );
      }
    }

    setDetectionSessionReady(true);
  };

  const rotateKeyMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/pii/keys/rotate", {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to rotate key");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["pii"] });
      setShowRotateModal(false);
    },
  });

  const exportAuditMutation = useMutation({
    mutationFn: async (format: "csv" | "json") => {
      const res = await fetch(
        `/api/pii/audit/export?format=${format}`,
      );
      if (!res.ok) throw new Error("Failed to export audit");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download =
        `pii-audit-${new Date().toISOString().split("T")[0]}`
        + `.${format}`;
      anchor.click();
      URL.revokeObjectURL(url);
    },
    onSuccess: () => {
      setShowExportModal(false);
    },
  });

  const detectPIIMutation = useMutation({
    mutationFn: async (text: string) => {
      const res = await fetch("/api/pii/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) throw new Error("Failed to detect PII");
      return res.json();
    },
    onSuccess: (data) => {
      setDetectionResults(data);
    },
  });

  const redactPIIMutation = useMutation({
    mutationFn: async (text: string) => {
      await ensureDetectionSession();
      const res = await fetch("/api/pii/redact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          session_id: detectionSessionId,
        }),
      });
      if (!res.ok) throw new Error("Failed to redact PII");
      return res.json();
    },
    onSuccess: (data) => {
      setDetectionResults((prev) =>
        prev
          ? { ...prev, redacted_text: data.redacted_text }
          : null,
      );
      setShowRedacted(true);
    },
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold">
            Data Protection
          </h1>
          <p className="text-muted-foreground">
            PII management, compliance checks, and detection
            tools
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowExportModal(true)}
            data-testid="export-button"
          >
            <Download className="mr-2 h-4 w-4" />
            Export Audit Log
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowRotateModal(true)}
            data-testid="rotate-key-button"
          >
            <RefreshCw className="mr-2 h-4 w-4" />
            Rotate Keys
          </Button>
        </div>
      </div>

      {/* Stats */}
      <Card>
        <CardContent className="py-0">
          <div
            className={
              "grid grid-cols-2 sm:grid-cols-4 divide-y"
              + " sm:divide-y-0 sm:divide-x divide-border"
            }
          >
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <Lock className="h-3.5 w-3.5 text-info" />
              <p
                className={
                  "text-lg font-semibold tabular-nums"
                }
              >
                {statsLoading
                  ? "..."
                  : (stats?.total_pii_stored || 0)
                    + (stats?.total_pii_retrieved || 0)}
              </p>
              <p className="text-xs text-muted-foreground">
                PII Operations
              </p>
            </div>
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <Users
                className="h-3.5 w-3.5 text-success"
              />
              <p
                className={
                  "text-lg font-semibold tabular-nums"
                }
              >
                {statsLoading
                  ? "..."
                  : stats?.active_sessions || 0}
              </p>
              <p className="text-xs text-muted-foreground">
                Active Sessions
              </p>
            </div>
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              {(stats?.integrity_failures || 0) > 0 ? (
                <AlertTriangle
                  className="h-3.5 w-3.5 text-danger"
                />
              ) : (
                <CheckCircle
                  className="h-3.5 w-3.5 text-success"
                />
              )}
              <p
                className={
                  "text-lg font-semibold tabular-nums"
                }
              >
                {statsLoading
                  ? "..."
                  : stats?.integrity_failures || 0}
              </p>
              <p className="text-xs text-muted-foreground">
                Integrity Failures
              </p>
            </div>
            <div
              className={
                "flex items-center justify-center"
                + " gap-2 py-3"
              }
            >
              <Key
                className={
                  `h-3.5 w-3.5 ${
                    (stats?.encryption_key_age_days || 0) > 90
                      ? "text-warning"
                      : "text-success"
                  }`
                }
              />
              <p
                className={
                  "text-lg font-semibold tabular-nums"
                }
              >
                {statsLoading
                  ? "..."
                  : `${stats?.encryption_key_age_days || 0}d`}
              </p>
              <p className="text-xs text-muted-foreground">
                Key Age
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-border pb-2">
        <Button
          variant={
            activeTab === "overview" ? "primary" : "ghost"
          }
          size="sm"
          onClick={() => setActiveTab("overview")}
        >
          <Shield className="mr-2 h-4 w-4" />
          Compliance
        </Button>
        <Button
          variant={
            activeTab === "audit" ? "primary" : "ghost"
          }
          size="sm"
          onClick={() => setActiveTab("audit")}
        >
          <FileText className="mr-2 h-4 w-4" />
          Audit Log
        </Button>
        <Button
          variant={
            activeTab === "sessions" ? "primary" : "ghost"
          }
          size="sm"
          onClick={() => setActiveTab("sessions")}
        >
          <Activity className="mr-2 h-4 w-4" />
          Sessions
        </Button>
        <Button
          variant={
            activeTab === "detection" ? "primary" : "ghost"
          }
          size="sm"
          onClick={() => setActiveTab("detection")}
        >
          <Search className="mr-2 h-4 w-4" />
          PII Detection
        </Button>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <ComplianceTab
          compliance={compliance}
          complianceLoading={complianceLoading}
        />
      )}

      {activeTab === "audit" && (
        <AuditTab
          auditLog={auditLog}
          auditLoading={auditLoading}
        />
      )}

      {activeTab === "sessions" && (
        <SessionsTab
          sessions={sessions}
          sessionsLoading={sessionsLoading}
        />
      )}

      {activeTab === "detection" && (
        <DetectionTab
          detectionText={detectionText}
          setDetectionText={setDetectionText}
          detectionResults={detectionResults}
          showRedacted={showRedacted}
          setShowRedacted={setShowRedacted}
          setDetectionResults={setDetectionResults}
          detectPIIMutation={{
            mutate: detectPIIMutation.mutate,
            isPending: detectPIIMutation.isPending,
          }}
          redactPIIMutation={{
            mutate: redactPIIMutation.mutate,
            isPending: redactPIIMutation.isPending,
          }}
        />
      )}

      {/* Key Rotation Modal */}
      {showRotateModal && (
        <KeyRotationModal
          stats={stats}
          onClose={() => setShowRotateModal(false)}
          onRotate={() => rotateKeyMutation.mutate()}
          isPending={rotateKeyMutation.isPending}
        />
      )}

      {/* Export Modal */}
      {showExportModal && (
        <ExportModal
          onClose={() => setShowExportModal(false)}
          onExport={(fmt) => exportAuditMutation.mutate(fmt)}
          isPending={exportAuditMutation.isPending}
        />
      )}
    </div>
  );
}
