#!/usr/bin/env python3
"""Evaluate deterministic regular and waiver drift for workflow runs."""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _find_repo_root(start: Path) -> Path | None:
    resolved = start.resolve()
    for candidate in [resolved, *resolved.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def _collect_allowed_patterns(run_dir: Path, plan_data: dict[str, Any]) -> list[str]:
    objective_patterns: list[str] = []
    objectives = plan_data.get("objectives")
    if isinstance(objectives, list):
        for objective in objectives:
            if not isinstance(objective, dict):
                continue
            allowed_scope = objective.get("allowed_scope")
            if not isinstance(allowed_scope, list):
                continue
            for scope_item in allowed_scope:
                if isinstance(scope_item, str) and scope_item.strip():
                    objective_patterns.append(scope_item.strip())

    baseline_patterns: list[str] = []
    baseline_dirty = plan_data.get("baseline_dirty_paths")
    if isinstance(baseline_dirty, list):
        for dirty_path in baseline_dirty:
            if isinstance(dirty_path, str) and dirty_path.strip():
                baseline_patterns.append(dirty_path.strip())

    run_id = run_dir.name
    return [
        *objective_patterns,
        *baseline_patterns,
        f"tests/artifacts/workflow/{run_id}",
        f"tests/artifacts/workflow/{run_id}/**",
    ]


def _path_allowed(path: str, patterns: list[str]) -> bool:
    normalized_path = path.replace("\\", "/").lstrip("./")
    for pattern in patterns:
        normalized_pattern = pattern.replace("\\", "/").lstrip("./").rstrip("/")
        if not normalized_pattern:
            continue
        if fnmatch.fnmatch(normalized_path, normalized_pattern):
            return True
        if normalized_path == normalized_pattern:
            return True
        if normalized_path.startswith(normalized_pattern + "/"):
            return True
    return False


def _read_dirty_paths(repo_root: Path) -> tuple[list[str], list[str]]:
    process = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    reasons: list[str] = []
    if process.returncode != 0:
        reasons.append(
            "Unable to evaluate regular drift because git status failed: "
            f"{(process.stderr or '').strip()}"
        )
        return [], reasons
    paths: list[str] = []
    for raw_line in process.stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        path_fragment = line[3:].strip() if len(line) >= 4 else line.strip()
        if " -> " in path_fragment:
            path_fragment = path_fragment.split(" -> ", 1)[1].strip()
        normalized = path_fragment.replace("\\", "/").rstrip("/").lstrip("./")
        if normalized:
            paths.append(normalized)
    return paths, reasons


def _waiver_drift_from_validation(
    validation_data: dict[str, Any],
) -> tuple[bool, list[str], list[str]]:
    reasons: list[str] = []
    invalid_ids: list[str] = []
    finding_decisions = validation_data.get("finding_decisions")
    if not isinstance(finding_decisions, list):
        return False, reasons, invalid_ids
    for decision in finding_decisions:
        if not isinstance(decision, dict):
            continue
        if decision.get("decision") != "invalid":
            continue
        finding_id = decision.get("finding_id")
        if isinstance(finding_id, str) and finding_id.strip():
            invalid_ids.append(finding_id.strip())
    if invalid_ids:
        reasons.append(
            "Waiver drift detected: invalid finding decisions are present: "
            + ", ".join(sorted(set(invalid_ids)))
        )
    return bool(invalid_ids), reasons, sorted(set(invalid_ids))


def evaluate_workflow_drift(run_dir: Path) -> dict[str, Any]:
    """Evaluate regular and waiver drift for a workflow run directory."""
    plan_path = run_dir / "plan_proposal.json"
    validation_path = run_dir / "validation_packet.json"
    failures: list[str] = []

    if not plan_path.is_file():
        failures.append("Missing plan_proposal.json for drift evaluation.")
        return {
            "run_id": run_dir.name,
            "regular_drift_detected": True,
            "waiver_drift_detected": True,
            "drift_reasons": failures,
            "regular_out_of_scope_paths": [],
            "invalid_finding_ids": [],
        }
    if not validation_path.is_file():
        failures.append("Missing validation_packet.json for drift evaluation.")
        return {
            "run_id": run_dir.name,
            "regular_drift_detected": True,
            "waiver_drift_detected": True,
            "drift_reasons": failures,
            "regular_out_of_scope_paths": [],
            "invalid_finding_ids": [],
        }

    plan_data = _load_json(plan_path)
    validation_data = _load_json(validation_path)
    if not isinstance(plan_data, dict):
        failures.append("plan_proposal.json must be an object for drift evaluation.")
    if not isinstance(validation_data, dict):
        failures.append("validation_packet.json must be an object for drift evaluation.")
    if failures:
        return {
            "run_id": run_dir.name,
            "regular_drift_detected": True,
            "waiver_drift_detected": True,
            "drift_reasons": failures,
            "regular_out_of_scope_paths": [],
            "invalid_finding_ids": [],
        }

    repo_root = _find_repo_root(run_dir)
    if repo_root is None:
        failures.append("Unable to locate repository root for drift evaluation.")
        return {
            "run_id": run_dir.name,
            "regular_drift_detected": True,
            "waiver_drift_detected": True,
            "drift_reasons": failures,
            "regular_out_of_scope_paths": [],
            "invalid_finding_ids": [],
        }

    allowed_patterns = _collect_allowed_patterns(run_dir, plan_data)
    dirty_paths, dirty_reasons = _read_dirty_paths(repo_root)
    failures.extend(dirty_reasons)

    out_of_scope_paths = [path for path in dirty_paths if not _path_allowed(path, allowed_patterns)]
    regular_drift_detected = bool(out_of_scope_paths or dirty_reasons)
    if out_of_scope_paths:
        failures.append(
            "Regular drift detected: out-of-scope dirty paths: "
            + ", ".join(sorted(set(out_of_scope_paths)))
        )

    waiver_drift_detected, waiver_reasons, invalid_ids = _waiver_drift_from_validation(
        validation_data
    )
    failures.extend(waiver_reasons)

    return {
        "run_id": run_dir.name,
        "regular_drift_detected": regular_drift_detected,
        "waiver_drift_detected": waiver_drift_detected,
        "drift_reasons": failures,
        "regular_out_of_scope_paths": sorted(set(out_of_scope_paths)),
        "invalid_finding_ids": invalid_ids,
    }


def main() -> int:
    """Run drift evaluation from CLI."""
    parser = argparse.ArgumentParser(description="Evaluate workflow drift for a run directory.")
    parser.add_argument("--run-dir", required=True, help="Workflow run directory.")
    args = parser.parse_args()
    run_dir = Path(args.run_dir).expanduser()
    if not run_dir.is_dir():
        payload = {
            "run_id": run_dir.name,
            "regular_drift_detected": True,
            "waiver_drift_detected": True,
            "drift_reasons": [f"Run directory does not exist: {run_dir}"],
            "regular_out_of_scope_paths": [],
            "invalid_finding_ids": [],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    payload = evaluate_workflow_drift(run_dir)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["regular_drift_detected"] or payload["waiver_drift_detected"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
