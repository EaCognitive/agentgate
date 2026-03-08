"use client";

import {
  Shield,
  Lock,
  AlertTriangle,
  CheckCircle,
  XCircle,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface ComplianceCheck {
  status: "pass" | "warning" | "fail";
  details: string;
}

export interface ComplianceData {
  hipaa: Record<string, ComplianceCheck>;
  soc2: Record<string, ComplianceCheck>;
  recommendations: (string | null)[];
}

interface ComplianceTabProps {
  compliance: ComplianceData | undefined;
  complianceLoading: boolean;
}

function ComplianceStatusBadge({ status }: { status: string }) {
  switch (status) {
    case "pass":
      return (
        <Badge className="bg-success-100 text-success">
          <CheckCircle className="mr-1 h-3 w-3" />
          Pass
        </Badge>
      );
    case "warning":
      return (
        <Badge className="bg-warning-100 text-warning">
          <AlertTriangle className="mr-1 h-3 w-3" />
          Warning
        </Badge>
      );
    case "fail":
      return (
        <Badge className="bg-danger-100 text-danger">
          <XCircle className="mr-1 h-3 w-3" />
          Fail
        </Badge>
      );
    default:
      return <Badge>{status}</Badge>;
  }
}

/**
 * Compliance tab content displaying HIPAA and SOC 2 checks
 * with recommendations.
 */
export default function ComplianceTab({
  compliance,
  complianceLoading,
}: ComplianceTabProps) {
  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        Compliance checks evaluate your current PII handling
        configuration against HIPAA and SOC 2 requirements.
        Results reflect the runtime state of encryption,
        access controls, and audit logging within AgentGate.
      </p>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* HIPAA Compliance */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              HIPAA Compliance
            </CardTitle>
            <CardDescription>
              Health Insurance Portability and Accountability Act
            </CardDescription>
          </CardHeader>
          <CardContent>
            {complianceLoading ? (
              <div className="py-4 text-center text-muted-foreground">
                Loading...
              </div>
            ) : compliance?.hipaa ? (
              <div className="space-y-3">
                {Object.entries(compliance.hipaa).map(
                  ([key, value]) => (
                    <div
                      key={key}
                      className={
                        "flex items-center justify-between gap-4"
                        + " rounded-lg bg-muted/30 px-4 py-3"
                      }
                    >
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium">
                          {key}
                        </p>
                        <p
                          className={
                            "text-xs text-muted-foreground"
                            + " truncate"
                          }
                        >
                          {value.details}
                        </p>
                      </div>
                      <ComplianceStatusBadge
                        status={value.status}
                      />
                    </div>
                  ),
                )}
              </div>
            ) : (
              <div className="py-4 text-center text-muted-foreground">
                No HIPAA compliance data available
              </div>
            )}
          </CardContent>
        </Card>

        {/* SOC 2 Compliance */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5" />
              SOC 2 Compliance
            </CardTitle>
            <CardDescription>
              Service Organization Control 2
            </CardDescription>
          </CardHeader>
          <CardContent>
            {complianceLoading ? (
              <div className="py-4 text-center text-muted-foreground">
                Loading...
              </div>
            ) : compliance?.soc2 ? (
              <div className="space-y-3">
                {Object.entries(compliance.soc2).map(
                  ([key, value]) => (
                    <div
                      key={key}
                      className={
                        "flex items-center justify-between gap-4"
                        + " rounded-lg bg-muted/30 px-4 py-3"
                      }
                    >
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium">
                          {key}
                        </p>
                        <p
                          className={
                            "text-xs text-muted-foreground"
                            + " truncate"
                          }
                        >
                          {value.details}
                        </p>
                      </div>
                      <ComplianceStatusBadge
                        status={value.status}
                      />
                    </div>
                  ),
                )}
              </div>
            ) : (
              <div className="py-4 text-center text-muted-foreground">
                No SOC 2 compliance data available
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recommendations */}
      {compliance?.recommendations
        && compliance.recommendations.filter(Boolean).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-warning" />
              Recommendations
            </CardTitle>
            <CardDescription>
              Based on your current HIPAA and SOC 2 compliance
              posture
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-2 pl-5">
              {compliance.recommendations
                .filter(Boolean)
                .map((rec, idx) => (
                  <li
                    key={idx}
                    className="text-muted-foreground"
                  >
                    {rec}
                  </li>
                ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <p className="text-xs text-muted-foreground/70">
        Compliance status shown here covers HIPAA and SOC 2
        checks only and does not constitute a formal audit.
        Additional frameworks (PCI-DSS, GDPR, etc.) are not
        included in this view.
      </p>
    </div>
  );
}
