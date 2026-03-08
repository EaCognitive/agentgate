"use client";

import React, { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Settings, Save } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface SettingRecord {
  key: string;
  value: any;
  updated_at: string;
}

interface SettingsForm {
  organization_name: string;
  support_email: string;
  data_retention_days: number;
  audit_retention_days: number;
  enable_threat_detection: boolean;
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<SettingsForm | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading, isError, error: loadError } = useQuery({
    queryKey: ["settings"],
    queryFn: async () => {
      const res = await fetch("/api/settings");
      if (!res.ok) throw new Error("Failed to load settings");
      return res.json() as Promise<SettingRecord[]>;
    },
  });

  useEffect(() => {
    if (!data) return;
    const map: any = {};
    data.forEach((setting) => {
      map[setting.key] = setting.value;
    });

    // Use setTimeout to avoid setState during render
    const timeoutId = setTimeout(() => {
      setForm({
        organization_name: map.organization_name || "AgentGate",
        support_email: map.support_email || "support@agentgate.io",
        data_retention_days: Number(map.data_retention_days ?? 30),
        audit_retention_days: Number(map.audit_retention_days ?? 365),
        enable_threat_detection: Boolean(map.enable_threat_detection ?? true),
      });
    }, 0);

    return () => clearTimeout(timeoutId);
  }, [data]);

  const saveSettings = useMutation({
    mutationFn: async () => {
      if (!form) return;
      setError(null);
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ settings: form }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(payload.error || "Failed to update settings");
      }
      return res.json();
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["settings"] }),
    onError: (err: any) => setError(err.message || "Failed to update settings"),
  });

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Settings</h1>
        <p className="text-sm text-muted-foreground">System configuration</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            General
          </CardTitle>
          <CardDescription>Configure system-wide defaults</CardDescription>
        </CardHeader>
        <CardContent>
          {isError && (
            <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {loadError instanceof Error ? loadError.message : "Failed to load settings"}
            </div>
          )}
          {error && (
            <div className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}

          {isLoading || !form ? (
            <div className="space-y-4">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="space-y-2">
                  <div className="skeleton h-4 w-1/4" />
                  <div className="skeleton h-10 w-full rounded-md" />
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium">Organization Name</label>
                <input
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  value={form.organization_name}
                  onChange={(e) => setForm({ ...form, organization_name: e.target.value })}
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium">Support Email</label>
                <input
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  value={form.support_email}
                  onChange={(e) => setForm({ ...form, support_email: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="mb-1 block text-sm font-medium">Data Retention (days)</label>
                  <input
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                    type="number"
                    min={1}
                    value={form.data_retention_days}
                    onChange={(e) => setForm({ ...form, data_retention_days: Number(e.target.value) })}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium">Audit Retention (days)</label>
                  <input
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                    type="number"
                    min={1}
                    value={form.audit_retention_days}
                    onChange={(e) => setForm({ ...form, audit_retention_days: Number(e.target.value) })}
                  />
                </div>
              </div>
              <div className="flex items-center justify-between rounded-md border border-border px-3 py-2">
                <div>
                  <p className="text-sm font-medium">Threat Detection</p>
                  <p className="text-xs text-muted-foreground">Enable/disable detection pipeline</p>
                </div>
                <input
                  type="checkbox"
                  checked={form.enable_threat_detection}
                  onChange={(e) => setForm({ ...form, enable_threat_detection: e.target.checked })}
                  className="h-5 w-5 rounded border border-border accent-primary"
                />
              </div>
              <Button onClick={() => saveSettings.mutate()} disabled={saveSettings.isPending}>
                <Save className="mr-2 h-4 w-4" />
                {saveSettings.isPending ? "Saving..." : "Save Settings"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
