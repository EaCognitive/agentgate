#!/usr/bin/env python3
"""Generate structured waiver templates for invalid full-sweep findings."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_json_checked(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = _load_json(path)
    except OSError as error:
        raise RuntimeError(f"{label} read failure: {error}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} invalid JSON: {error}") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must be a JSON object.")
    return payload


def _load_existing_waivers(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    payload = _load_json_checked(path, "waivers.json")
    entries = payload.get("waivers")
    if not isinstance(entries, list):
        raise RuntimeError("waivers.json must contain a waivers list.")
    existing: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        finding_id = entry.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            continue
        existing[finding_id.strip()] = entry
    return existing


def _review_finding_map(review_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = review_payload.get("findings")
    if not isinstance(findings, list):
        return {}
    mapping: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        finding_id = item.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            continue
        mapping[finding_id.strip()] = item
    return mapping


def _invalid_finding_ids(validation_payload: dict[str, Any]) -> list[str]:
    decisions = validation_payload.get("finding_decisions")
    if not isinstance(decisions, list):
        raise RuntimeError("validation_packet.json missing finding_decisions list.")
    finding_ids: list[str] = []
    for entry in decisions:
        if not isinstance(entry, dict):
            continue
        decision = entry.get("decision")
        finding_id = entry.get("finding_id")
        if decision != "invalid":
            continue
        if not isinstance(finding_id, str) or not finding_id.strip():
            continue
        normalized = finding_id.strip()
        if normalized not in finding_ids:
            finding_ids.append(normalized)
    return finding_ids


def build_waivers_template(
    *,
    run_dir: Path,
    output_path: Path,
    approved_by: str,
    reason: str,
    approved_at_utc: str,
) -> dict[str, Any]:
    """Build waiver template payload from workflow artifacts."""
    validation_payload = _load_json_checked(
        run_dir / "validation_packet.json",
        "validation_packet.json",
    )
    review_payload = _load_json_checked(
        run_dir / "review_report.json",
        "review_report.json",
    )
    invalid_ids = _invalid_finding_ids(validation_payload)
    review_map = _review_finding_map(review_payload)
    existing_map = _load_existing_waivers(output_path)

    waivers: list[dict[str, Any]] = []
    for finding_id in sorted(invalid_ids):
        finding = review_map.get(finding_id, {})
        existing = existing_map.get(finding_id, {})
        title = finding.get("title")
        category = finding.get("category")
        evidence_refs = finding.get("evidence_refs")
        waiver = {
            "finding_id": finding_id,
            "title": title if isinstance(title, str) else "",
            "category": category if isinstance(category, str) else "",
            "decision": "waive",
            "approved_by": str(existing.get("approved_by", "")).strip(),
            "approved_at_utc": str(existing.get("approved_at_utc", "")).strip(),
            "reason": str(existing.get("reason", "")).strip(),
            "evidence_refs": evidence_refs if isinstance(evidence_refs, list) else [],
        }
        if approved_by and not waiver["approved_by"]:
            waiver["approved_by"] = approved_by
        if approved_at_utc and not waiver["approved_at_utc"]:
            waiver["approved_at_utc"] = approved_at_utc
        if reason and not waiver["reason"]:
            waiver["reason"] = reason
        waivers.append(waiver)

    payload = {
        "run_id": run_dir.name,
        "generated_at_utc": _utc_now(),
        "source": "validation_packet.finding_decisions",
        "waivers": waivers,
    }
    return payload


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Generate waivers.json template for invalid full-sweep findings."
    )
    parser.add_argument("--run-dir", required=True, help="Workflow run directory.")
    parser.add_argument(
        "--output",
        help="Output waiver file path. Defaults to <run-dir>/waivers.json.",
    )
    parser.add_argument(
        "--approved-by",
        default="",
        help="Optional default approver to set on empty waiver entries.",
    )
    parser.add_argument(
        "--approved-at-utc",
        default="",
        help="Optional default approval timestamp to set on empty waiver entries.",
    )
    parser.add_argument(
        "--reason",
        default="",
        help="Optional default waiver reason to set on empty waiver entries.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output if it already exists.",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser()
    if not run_dir.is_dir():
        payload = {
            "status": "HOLD",
            "failures": [f"Run directory does not exist: {run_dir}"],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    output_path = Path(args.output).expanduser() if args.output else run_dir / "waivers.json"
    if output_path.exists() and not args.overwrite:
        payload = {
            "status": "HOLD",
            "failures": [f"Output exists. Re-run with --overwrite: {output_path}"],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    try:
        payload = build_waivers_template(
            run_dir=run_dir,
            output_path=output_path,
            approved_by=args.approved_by.strip(),
            reason=args.reason.strip(),
            approved_at_utc=args.approved_at_utc.strip(),
        )
    except RuntimeError as error:
        print(json.dumps({"status": "HOLD", "failures": [str(error)]}, indent=2, sort_keys=True))
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {
        "status": "PASS",
        "run_id": run_dir.name,
        "output": str(output_path),
        "waiver_count": len(payload.get("waivers", [])),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
