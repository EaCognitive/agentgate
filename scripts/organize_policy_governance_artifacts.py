#!/usr/bin/env python3
"""Normalize policy-governance artifact storage into canonical layout.

This script moves legacy artifact directories into canonical or archive locations,
then emits an operation manifest for auditability.
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_ROOT = REPO_ROOT / "tests" / "artifacts"
FORMAL_ROOT = ARTIFACTS_ROOT / "algorithm" / "formal_verification"
FORMAL_RUNS = FORMAL_ROOT / "runs"
MCP_ROOT = ARTIFACTS_ROOT / "algorithm" / "policy_governance_validation"
MCP_RUNS = MCP_ROOT / "runs"
ARCHIVE_ROOT = ARTIFACTS_ROOT / "archive" / "legacy"
OPS_ROOT = ARTIFACTS_ROOT / "operations" / "artifact_organization"


@dataclass(frozen=True)
class MovePlan:
    """One filesystem move operation in the artifact organization plan."""

    source: Path
    target_dir: Path
    reason: str


@dataclass(frozen=True)
class MoveRecord:
    """Audit record describing a planned or executed artifact move."""

    source: str
    destination: str
    reason: str
    status: str


def _utc_stamp() -> str:
    """Return a UTC timestamp suffix suitable for manifest names."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _unique_destination(base_dir: Path, name: str) -> Path:
    candidate = base_dir / name
    if not candidate.exists():
        return candidate
    suffix = _utc_stamp()
    return base_dir / f"{name}_{suffix}"


def _build_plans() -> list[MovePlan]:
    plans: list[MovePlan] = []

    for legacy_dir in sorted(ARTIFACTS_ROOT.glob("formal_runtime_forensic_run_*")):
        if legacy_dir.is_dir():
            plans.append(
                MovePlan(
                    source=legacy_dir,
                    target_dir=FORMAL_RUNS,
                    reason="move_forensic_root_to_canonical_runs",
                )
            )

    for pattern in ("chaos_run_*", "chaos_verification_run_*"):
        for legacy_dir in sorted(ARTIFACTS_ROOT.glob(pattern)):
            if legacy_dir.is_dir():
                plans.append(
                    MovePlan(
                        source=legacy_dir,
                        target_dir=ARCHIVE_ROOT / "chaos",
                        reason="archive_legacy_chaos_directory",
                    )
                )

    legacy_mcp_root = ARTIFACTS_ROOT / "algorithm" / "mcp_ground_truth"
    if legacy_mcp_root.is_dir():
        for run_dir in sorted(legacy_mcp_root.iterdir()):
            if run_dir.is_dir():
                plans.append(
                    MovePlan(
                        source=run_dir,
                        target_dir=MCP_RUNS,
                        reason="move_mcp_ground_truth_to_policy_governance_runs",
                    )
                )
    return plans


def _execute_plan(plan: MovePlan, *, apply: bool) -> MoveRecord:
    destination = _unique_destination(plan.target_dir, plan.source.name)
    if not apply:
        return MoveRecord(
            source=str(plan.source.relative_to(REPO_ROOT)),
            destination=str(destination.relative_to(REPO_ROOT)),
            reason=plan.reason,
            status="planned",
        )

    _ensure_dir(plan.target_dir)
    shutil.move(str(plan.source), str(destination))
    return MoveRecord(
        source=str(plan.source.relative_to(REPO_ROOT)),
        destination=str(destination.relative_to(REPO_ROOT)),
        reason=plan.reason,
        status="moved",
    )


def _write_manifest(*, apply: bool, records: list[MoveRecord]) -> Path:
    _ensure_dir(OPS_ROOT)
    stamp = _utc_stamp()
    manifest_path = OPS_ROOT / f"artifact_organization_{stamp}.json"
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "apply_changes": apply,
        "record_count": len(records),
        "records": [record.__dict__ for record in records],
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize policy-governance artifact directory layout.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Apply move operations. Default is dry-run.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute artifact organization and emit a manifest summary."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    apply = bool(args.execute)

    _ensure_dir(FORMAL_RUNS)
    _ensure_dir(MCP_RUNS)
    _ensure_dir(ARCHIVE_ROOT)

    plans = _build_plans()
    records = [_execute_plan(plan, apply=apply) for plan in plans]
    manifest = _write_manifest(apply=apply, records=records)

    print("")
    print("=" * 68)
    print("POLICY GOVERNANCE ARTIFACT ORGANIZATION")
    print("=" * 68)
    print(f"Mode: {'execute' if apply else 'dry-run'}")
    print(f"Operations: {len(records)}")
    print(f"Manifest: {manifest}")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
