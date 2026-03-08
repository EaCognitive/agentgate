"use client";

import { CheckCircle, XCircle, FileText } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";

export interface PIIAuditEntry {
  event_id: string;
  timestamp: string;
  event_type: string;
  user_id: string | null;
  session_id: string | null;
  pii_type: string | null;
  success: boolean;
  error_message: string | null;
}

interface AuditTabProps {
  auditLog: PIIAuditEntry[] | undefined;
  auditLoading: boolean;
}

function getEventTypeBadge(type: string) {
  const colors: Record<string, string> = {
    pii_store: "bg-info-100 text-info",
    pii_retrieve: "bg-success-100 text-success",
    pii_delete: "bg-danger-100 text-danger",
    access_denied: "bg-warning-100 text-warning",
    key_rotation: "bg-purple-100 dark:bg-purple-500/20 text-purple-800 dark:text-purple-400",
    pii_integrity_failure: "bg-danger-100 text-danger",
  };
  return (
    <Badge
      className={colors[type] || "bg-gray-500/20 text-gray-600 dark:text-gray-400"}
    >
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

/**
 * Audit log tab displaying tamper-evident PII operation history.
 */
export default function AuditTab({
  auditLog,
  auditLoading,
}: AuditTabProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>PII Audit Log</CardTitle>
        <CardDescription>
          Tamper-evident log of all PII operations with integrity
          verification
        </CardDescription>
      </CardHeader>
      <CardContent>
        {auditLoading ? (
          <div
            className={
              "flex h-64 items-center justify-center"
              + " text-muted-foreground"
            }
          >
            Loading audit log...
          </div>
        ) : auditLog && auditLog.length > 0 ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Event Type</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>PII Type</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditLog.map((entry) => (
                  <TableRow key={entry.event_id}>
                    <TableCell className="text-xs">
                      {format(
                        new Date(entry.timestamp),
                        "MMM d, HH:mm:ss",
                      )}
                    </TableCell>
                    <TableCell>
                      {getEventTypeBadge(entry.event_type)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {entry.user_id || "\u2014"}
                    </TableCell>
                    <TableCell>
                      {entry.pii_type ? (
                        <Badge variant="outline">
                          {entry.pii_type}
                        </Badge>
                      ) : (
                        "\u2014"
                      )}
                    </TableCell>
                    <TableCell>
                      {entry.success ? (
                        <CheckCircle
                          className="h-4 w-4 text-success"
                        />
                      ) : (
                        <XCircle
                          className="h-4 w-4 text-danger"
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div
            className={
              "flex h-64 flex-col items-center justify-center"
              + " text-center text-muted-foreground"
            }
          >
            <FileText className="mb-2 h-12 w-12 opacity-30" />
            <p>No PII audit entries</p>
            <p className="text-xs">
              PII operations will be logged here
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
