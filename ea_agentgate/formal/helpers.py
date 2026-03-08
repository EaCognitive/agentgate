"""Shared helpers for formal verification payload handling."""

from __future__ import annotations

from typing import Any


def extract_certificate_payload(detail: Any) -> dict[str, Any] | None:
    """Extract a certificate payload from nested API detail objects."""
    if not isinstance(detail, dict):
        return None

    detail_payload = detail.get("detail")
    if isinstance(detail_payload, dict):
        certificate = detail_payload.get("certificate")
        if isinstance(certificate, dict):
            return certificate

    certificate = detail.get("certificate")
    if isinstance(certificate, dict):
        return certificate
    return None


def extract_failed_predicates(cert: Any) -> list[str]:
    """Pull failed predicate names from a formal certificate payload."""
    payload = cert.proof_payload
    if cert.proof_type.value == "UNSAT_CORE":
        unsat_core = payload.get("unsat_core", [])
        if not isinstance(unsat_core, list):
            return []
        return [str(predicate) for predicate in unsat_core]

    if cert.proof_type.value == "COUNTEREXAMPLE":
        failed_raw = payload.get("failed_predicates", [])
        failed = (
            [str(predicate) for predicate in failed_raw] if isinstance(failed_raw, list) else []
        )
        counterexample = payload.get("counterexample", {})
        counter_pred = counterexample.get("predicate") if isinstance(counterexample, dict) else None
        if counter_pred and counter_pred not in failed:
            failed = [str(counter_pred)] + failed
        return failed

    return []
