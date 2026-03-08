"use client";

import {
  Search,
  FileText,
  Loader2,
  Sparkles,
  EyeOff,
  Copy,
  CheckCircle,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface DetectionEntity {
  type: string;
  value: string;
  start: number;
  end: number;
}

interface DetectionResults {
  entities: DetectionEntity[];
  redacted_text: string;
}

interface DetectionTabProps {
  detectionText: string;
  setDetectionText: (value: string) => void;
  detectionResults: DetectionResults | null;
  showRedacted: boolean;
  setShowRedacted: (value: boolean) => void;
  setDetectionResults: (value: DetectionResults | null) => void;
  detectPIIMutation: {
    mutate: (text: string) => void;
    isPending: boolean;
  };
  redactPIIMutation: {
    mutate: (text: string) => void;
    isPending: boolean;
  };
}

function getEntityTypeBadgeClass(type: string): string {
  const colors: Record<string, string> = {
    EMAIL_ADDRESS: "bg-info-100 text-info",
    PHONE_NUMBER: "bg-success-100 text-success",
    US_SSN: "bg-danger-100 text-danger",
    CREDIT_CARD: "bg-danger-100 text-danger",
    PERSON: "bg-purple-100 dark:bg-purple-500/20 text-purple-800 dark:text-purple-400",
    LOCATION: "bg-warning-100 text-warning",
    DATE_TIME: "bg-info-100 text-info",
    IP_ADDRESS: "bg-warning-100 text-warning",
    US_DRIVER_LICENSE: "bg-danger-100 text-danger",
    US_PASSPORT: "bg-info-100 text-info",
  };
  return colors[type] || "bg-gray-100 dark:bg-gray-500/20 text-gray-800 dark:text-gray-400";
}

/**
 * PII Detection tab with text input, entity detection,
 * and redaction capabilities.
 */
export default function DetectionTab({
  detectionText,
  setDetectionText,
  detectionResults,
  showRedacted,
  setShowRedacted,
  setDetectionResults,
  detectPIIMutation,
  redactPIIMutation,
}: DetectionTabProps) {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            PII Detection Tool
          </CardTitle>
          <CardDescription>
            Enter text to detect and analyze PII entities
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label
              className={
                "block text-sm font-medium"
                + " text-foreground mb-2"
              }
            >
              Input Text
            </label>
            <textarea
              value={detectionText}
              onChange={(e) => setDetectionText(e.target.value)}
              placeholder={
                "Enter text containing PII to analyze..."
                + " (e.g., John Doe's email is"
                + " john@example.com and SSN is"
                + " 123-45-6789)"
              }
              className={
                "w-full h-40 rounded-lg border border-border"
                + " bg-background px-4 py-3 text-sm"
                + " focus:border-primary focus:outline-none"
                + " focus:ring-1 focus:ring-primary resize-none"
              }
              data-testid="pii-detection-input"
            />
          </div>
          <div className="flex gap-2">
            <Button
              onClick={() => {
                detectPIIMutation.mutate(detectionText);
              }}
              disabled={
                !detectionText.trim()
                || detectPIIMutation.isPending
              }
              data-testid="detect-pii-button"
            >
              {detectPIIMutation.isPending ? (
                <Loader2
                  className="mr-2 h-4 w-4 animate-spin"
                />
              ) : (
                <Sparkles className="mr-2 h-4 w-4" />
              )}
              Detect PII
            </Button>
            {detectionResults && !showRedacted && (
              <Button
                variant="outline"
                onClick={() => {
                  redactPIIMutation.mutate(detectionText);
                }}
                disabled={redactPIIMutation.isPending}
                data-testid="redact-pii-button"
              >
                {redactPIIMutation.isPending ? (
                  <Loader2
                    className="mr-2 h-4 w-4 animate-spin"
                  />
                ) : (
                  <EyeOff className="mr-2 h-4 w-4" />
                )}
                Redact PII
              </Button>
            )}
            {detectionResults && (
              <Button
                variant="ghost"
                onClick={() => {
                  setDetectionText("");
                  setDetectionResults(null);
                  setShowRedacted(false);
                }}
              >
                Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Detection Results
          </CardTitle>
          <CardDescription>
            Detected PII entities and their types
          </CardDescription>
        </CardHeader>
        <CardContent>
          {detectPIIMutation.isPending ? (
            <div
              className="flex h-64 items-center justify-center"
            >
              <Loader2
                className="h-8 w-8 animate-spin text-primary"
              />
            </div>
          ) : detectionResults ? (
            <div className="space-y-4">
              {/* Redacted Preview */}
              {showRedacted
                && detectionResults.redacted_text && (
                <div className="rounded-lg bg-muted/50 p-4">
                  <div
                    className={
                      "flex items-center justify-between mb-2"
                    }
                  >
                    <span
                      className={
                        "text-sm font-medium"
                        + " text-muted-foreground"
                      }
                    >
                      Redacted Output
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard.writeText(
                          detectionResults.redacted_text,
                        );
                      }}
                    >
                      <Copy className="h-3 w-3 mr-1" />
                      Copy
                    </Button>
                  </div>
                  <p
                    className={
                      "text-sm font-mono whitespace-pre-wrap"
                    }
                  >
                    {detectionResults.redacted_text}
                  </p>
                </div>
              )}

              {/* Entities Found */}
              <div>
                <h4
                  className={
                    "text-sm font-medium text-foreground mb-3"
                  }
                >
                  Entities Found (
                  {detectionResults.entities?.length || 0})
                </h4>
                {detectionResults.entities
                  && detectionResults.entities.length > 0 ? (
                  <div
                    className={
                      "space-y-2 max-h-80 overflow-y-auto"
                    }
                  >
                    {detectionResults.entities.map(
                      (entity, idx) => (
                        <div
                          key={idx}
                          className={
                            "flex items-center"
                            + " justify-between rounded-lg"
                            + " border border-border p-3"
                          }
                        >
                          <div
                            className={
                              "flex items-center gap-3"
                            }
                          >
                            <Badge
                              className={
                                getEntityTypeBadgeClass(
                                  entity.type,
                                )
                              }
                            >
                              {entity.type}
                            </Badge>
                            <code
                              className={
                                "text-sm font-mono bg-muted"
                                + " px-2 py-1 rounded"
                              }
                            >
                              {entity.value}
                            </code>
                          </div>
                          <span
                            className={
                              "text-xs"
                              + " text-muted-foreground"
                            }
                          >
                            pos {entity.start}-{entity.end}
                          </span>
                        </div>
                      ),
                    )}
                  </div>
                ) : (
                  <div
                    className={
                      "flex flex-col items-center"
                      + " justify-center py-8 text-center"
                      + " text-muted-foreground"
                    }
                  >
                    <CheckCircle
                      className={
                        "h-12 w-12 mb-2 text-success/50"
                      }
                    />
                    <p>No PII detected</p>
                    <p className="text-xs">
                      The text appears to be clean
                    </p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div
              className={
                "flex h-64 flex-col items-center"
                + " justify-center text-center"
                + " text-muted-foreground"
              }
            >
              <Search
                className="mb-2 h-12 w-12 opacity-30"
              />
              <p>Enter text and click Detect</p>
              <p className="text-xs">
                PII entities will be analyzed here
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
