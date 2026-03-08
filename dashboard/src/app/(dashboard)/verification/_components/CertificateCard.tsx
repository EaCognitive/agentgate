"use client";

import type { AdmissibilityResponse } from "@/types/index";
import { cn } from "@/lib/utils";
import { Info } from "lucide-react";

interface CertificateCardProps {
  certificate: AdmissibilityResponse["certificate"];
}

/**
 * Human-readable descriptions for certificate fields.
 */
const CERT_HINTS: Record<string, string> = {
  "Decision ID":
    "Unique identifier for this verification decision.",
  "Context Fingerprint":
    "Cryptographic fingerprint of the action context. "
    + "Proves the input was not altered.",
  "Policy Fingerprint":
    "Cryptographic fingerprint of the policies "
    + "evaluated for this decision.",
  "Proof Fingerprint":
    "Fingerprint of the formal proof structure "
    + "applied to this decision.",
  Signature:
    "Ed25519 digital signature binding the decision to "
    + "the hashes above. Tamper-evident proof of authenticity.",
  "Solver Version":
    "Version identifier of the formal solver that produced "
    + "this certificate.",
  Created:
    "Timestamp when the certificate was issued.",
};

/**
 * Truncates a hash/signature string for display.
 */
function truncateHash(value: string | null, len = 16): string {
  if (!value) {
    return "N/A";
  }
  if (value.length <= len) {
    return value;
  }
  return `${value.slice(0, len)}...`;
}

/**
 * Single row in the certificate detail table.
 */
function Row({
  label,
  value,
  mono = false,
  fullValue,
}: {
  label: string;
  value: string;
  mono?: boolean;
  fullValue?: string;
}) {
  const hint = CERT_HINTS[label];

  return (
    <div className="py-1.5">
      <div className="flex items-start justify-between gap-4">
        <span
          className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground"
          title={hint}
        >
          {label}
          {hint && (
            <Info className="h-3 w-3 shrink-0 text-muted-foreground/50" />
          )}
        </span>
        <span
          className={cn(
            "text-right text-xs text-foreground break-all",
            mono && "font-mono",
          )}
          title={fullValue || value}
        >
          {value}
        </span>
      </div>
      {hint && (
        <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground/70">
          {hint}
        </p>
      )}
    </div>
  );
}

/**
 * Compact display of the signed decision certificate.
 */
export default function CertificateCard({
  certificate,
}: CertificateCardProps) {
  const created = certificate.created_at
    ? new Date(certificate.created_at).toLocaleString()
    : "N/A";

  return (
    <div className="rounded-xl border border-border bg-card/80 p-5 shadow-sm">
      <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        Decision Certificate
      </p>
      <p className="mb-3 text-xs text-muted-foreground/70">
        A cryptographically signed record binding the decision
        to the exact inputs and policies evaluated.
      </p>
      <div className="divide-y divide-border">
        <Row
          label="Decision ID"
          value={certificate.decision_id}
          mono
        />
        <Row
          label="Context Fingerprint"
          value={truncateHash(certificate.alpha_hash)}
          mono
          fullValue={certificate.alpha_hash}
        />
        <Row
          label="Policy Fingerprint"
          value={truncateHash(certificate.gamma_hash)}
          mono
          fullValue={certificate.gamma_hash}
        />
        <Row
          label="Proof Fingerprint"
          value={truncateHash(certificate.theorem_hash)}
          mono
          fullValue={certificate.theorem_hash}
        />
        <Row
          label="Signature"
          value={truncateHash(certificate.signature, 24)}
          mono
          fullValue={certificate.signature || undefined}
        />
        <Row
          label="Solver Version"
          value={certificate.solver_version}
        />
        <Row label="Created" value={created} />
      </div>
    </div>
  );
}
