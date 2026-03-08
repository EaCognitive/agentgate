"use client";

import React, { useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Activity, TrendingUp } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const PIE_COLORS = ["#10b981", "#ef4444", "#eab308"];

interface StatusDistributionProps {
  stats?: {
    success_count: number;
    failed_count: number;
    blocked_count: number;
  };
}

/**
 * Donut chart showing the distribution of call outcomes
 * (success / failed / blocked).
 */
export default function StatusDistribution({
  stats,
}: StatusDistributionProps) {
  const blocksData = useMemo(() => {
    if (!stats) return [];
    const total =
      stats.success_count
      + stats.failed_count
      + stats.blocked_count;
    if (total === 0) return [];
    return [
      {
        name: "Success",
        value: stats.success_count,
        percentage: (
          (stats.success_count / total) * 100
        ).toFixed(1),
      },
      {
        name: "Failed",
        value: stats.failed_count,
        percentage: (
          (stats.failed_count / total) * 100
        ).toFixed(1),
      },
      {
        name: "Blocked",
        value: stats.blocked_count,
        percentage: (
          (stats.blocked_count / total) * 100
        ).toFixed(1),
      },
    ].filter((item) => item.value > 0);
  }, [stats]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>
              Status Distribution
            </CardTitle>
            <CardDescription>
              Call outcomes breakdown
            </CardDescription>
          </div>
          {blocksData.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-success">
              <TrendingUp className="h-3.5 w-3.5" />
              <span>
                {blocksData.find(
                  (d) => d.name === "Success",
                )?.percentage || 0}
                % success
              </span>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {blocksData.length === 0 ? (
          <div className="flex h-56 flex-col items-center justify-center text-muted-foreground">
            <Activity
              className="mb-3 h-10 w-10 opacity-40"
            />
            <span className="text-sm">
              No data available
            </span>
            <span className="mt-1 text-xs opacity-70">
              Data will appear once traces are recorded
            </span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-center">
            <div className="h-56 w-full max-w-[240px]">
              <ResponsiveContainer
                width="100%"
                height="100%"
              >
                <PieChart>
                  <Pie
                    data={blocksData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {blocksData.map(
                      (_entry, idx) => (
                        <Cell
                          key={`cell-${idx}`}
                          fill={
                            PIE_COLORS[
                              idx % PIE_COLORS.length
                            ]
                          }
                        />
                      ),
                    )}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor:
                        "var(--card)",
                      border:
                        "1px solid var(--border)",
                      borderRadius: "8px",
                      color: "var(--foreground)",
                    }}
                    itemStyle={{
                      color: "var(--foreground)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-3">
              {blocksData.map((item, idx) => (
                <div
                  key={item.name}
                  className="flex items-center gap-4"
                >
                  <div className="flex items-center gap-2">
                    <div
                      className="h-3 w-3 rounded-full"
                      style={{
                        backgroundColor:
                          PIE_COLORS[idx],
                      }}
                    />
                    <span className="text-sm">
                      {item.name}
                    </span>
                  </div>
                  <span className="text-sm font-semibold tabular-nums">
                    {item.percentage}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
