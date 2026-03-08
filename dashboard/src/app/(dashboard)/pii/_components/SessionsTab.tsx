"use client";

import { Users } from "lucide-react";
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
import { formatDistanceToNow } from "date-fns";

export interface PIISession {
  session_id: string;
  user_id: string | null;
  purpose?: string;
  created_at: string;
  is_active: boolean;
  store_count: number;
  retrieve_count: number;
}

interface SessionsTabProps {
  sessions: PIISession[] | undefined;
  sessionsLoading: boolean;
}

/**
 * Sessions tab displaying active and historical PII sessions.
 */
export default function SessionsTab({
  sessions,
  sessionsLoading,
}: SessionsTabProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>PII Sessions</CardTitle>
        <CardDescription>
          Active and historical PII handling sessions
        </CardDescription>
      </CardHeader>
      <CardContent>
        {sessionsLoading ? (
          <div
            className={
              "flex h-64 items-center justify-center"
              + " text-muted-foreground"
            }
          >
            Loading sessions...
          </div>
        ) : sessions && sessions.length > 0 ? (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Session ID</TableHead>
                  <TableHead>Purpose</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Access Count</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((piiSession) => (
                  <TableRow key={piiSession.session_id}>
                    <TableCell className="font-mono text-xs">
                      {piiSession.session_id.slice(0, 8)}...
                    </TableCell>
                    <TableCell>
                      {piiSession.purpose || "\u2014"}
                    </TableCell>
                    <TableCell>
                      {piiSession.user_id || "\u2014"}
                    </TableCell>
                    <TableCell>
                      {piiSession.store_count
                        + piiSession.retrieve_count}
                    </TableCell>
                    <TableCell className="text-xs">
                      {formatDistanceToNow(
                        new Date(piiSession.created_at),
                        { addSuffix: true },
                      )}
                    </TableCell>
                    <TableCell>
                      {piiSession.is_active ? (
                        <Badge
                          className={
                            "bg-success-100 text-success"
                          }
                        >
                          Active
                        </Badge>
                      ) : (
                        <Badge
                          className={
                            "bg-gray-500/20 text-gray-600 dark:text-gray-400"
                          }
                        >
                          Closed
                        </Badge>
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
            <Users className="mb-2 h-12 w-12 opacity-30" />
            <p>No PII sessions</p>
            <p className="text-xs">
              Sessions will appear when PII is accessed
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
