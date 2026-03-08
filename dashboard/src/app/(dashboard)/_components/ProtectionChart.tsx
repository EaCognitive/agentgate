"use client";

import React, { useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { ShieldAlert, Shield } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { TimelineBucket } from "@/lib/hooks";

interface ProtectionChartProps {
  timeline?: TimelineBucket[];
  isLoading: boolean;
}

/**
 * Format an ISO timestamp to HH:MM for axis ticks.
 */
function formatTime(v: string): string {
  const d = new Date(v);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/**
 * Area chart showing requests denied by governance
 * (policy-blocked and rejected) over the last 24 hours.
 */
export default function ProtectionChart({
  timeline,
  isLoading,
}: ProtectionChartProps) {
  const chartData = useMemo(() => {
    if (!timeline) return [];
    return timeline.map((bucket) => ({
      time: bucket.time,
      blocked: bucket.blocked ?? 0,
      failed: bucket.failed ?? 0,
    }));
  }, [timeline]);

  const hasData = useMemo(() => {
    return chartData.some(
      (b) => b.blocked > 0 || b.failed > 0,
    );
  }, [chartData]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start gap-2">
          <ShieldAlert
            className="mt-0.5 h-4 w-4 text-warning"
          />
          <div>
            <CardTitle>Denied Requests</CardTitle>
            <CardDescription>
              Requests blocked or rejected by governance (24h)
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-[310px] w-full" />
        ) : !hasData ? (
          <div className="flex h-[310px] flex-col items-center justify-center text-muted-foreground">
            <Shield
              className="mb-3 h-10 w-10 opacity-40"
            />
            <span className="text-sm">
              No denied requests
            </span>
            <span className="mt-1 text-xs opacity-70">
              All requests passed governance checks
            </span>
          </div>
        ) : (
          <div className="h-[310px] w-full">
            <ResponsiveContainer
              width="100%"
              height="100%"
            >
              <AreaChart
                data={chartData}
                margin={{
                  top: 8,
                  right: 12,
                  left: -8,
                  bottom: 0,
                }}
              >
                <defs>
                  <linearGradient
                    id="gradBlocked"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor="#10b981"
                      stopOpacity={0.55}
                    />
                    <stop
                      offset="100%"
                      stopColor="#10b981"
                      stopOpacity={0}
                    />
                  </linearGradient>
                  <linearGradient
                    id="gradFailed"
                    x1="0"
                    y1="0"
                    x2="0"
                    y2="1"
                  >
                    <stop
                      offset="0%"
                      stopColor="#ef4444"
                      stopOpacity={0.55}
                    />
                    <stop
                      offset="100%"
                      stopColor="#ef4444"
                      stopOpacity={0}
                    />
                  </linearGradient>
                </defs>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="var(--border)"
                  vertical={false}
                />
                <XAxis
                  dataKey="time"
                  tickFormatter={formatTime}
                  stroke="var(--muted-foreground)"
                  fontSize={12}
                  tickLine={false}
                  axisLine={false}
                  dy={8}
                  interval="preserveStartEnd"
                  minTickGap={40}
                />
                <YAxis
                  stroke="var(--muted-foreground)"
                  fontSize={12}
                  allowDecimals={false}
                  tickLine={false}
                  axisLine={false}
                  width={36}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "var(--card)",
                    border:
                      "1px solid var(--border)",
                    borderRadius: "8px",
                    color: "var(--foreground)",
                    fontSize: "12px",
                  }}
                  labelFormatter={formatTime}
                />
                <Legend
                  verticalAlign="top"
                  align="left"
                  height={36}
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{
                    fontSize: "13px",
                    paddingBottom: "8px",
                    paddingLeft: "16px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  stroke="#10b981"
                  strokeWidth={2}
                  fill="url(#gradBlocked)"
                  dot={false}
                  activeDot={{
                    r: 5,
                    strokeWidth: 2,
                    fill: "#fff",
                  }}
                  name="Policy Blocked"
                />
                <Area
                  type="monotone"
                  dataKey="failed"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fill="url(#gradFailed)"
                  dot={false}
                  activeDot={{
                    r: 5,
                    strokeWidth: 2,
                    fill: "#fff",
                  }}
                  name="Rejected"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
