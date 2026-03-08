#!/usr/bin/env python3
"""Create a deterministic principal reopen handoff from a reopen request."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    """Return a stable UTC timestamp string for reopen artifacts."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def _build_prompt(payload: dict[str, Any]) -> str:
    run_id = payload.get("run_id", "<missing>")
    required_action = payload.get("required_action", "REMEDIATE")
    restart_from = payload.get("restart_from", "/principal present-plan")
    hold_reasons = payload.get("hold_reasons", [])
    reasons_text = "\n".join(f"- {reason}" for reason in hold_reasons) or "- <none provided>"
    return "\n".join(
        [
            "@principal-led-engineering-team",
            "",
            f"Continue run `{run_id}`. Previous gatekeeper result is HOLD.",
            "",
            "Required action:",
            f"- {required_action}",
            "",
            f"Restart from: `{restart_from}`",
            "",
            "Hold reasons:",
            reasons_text,
            "",
            "Do not start a new run id for this remediation unless scope has changed.",
        ]
    )


def main() -> int:
    """Generate the reopen prompt and inbox payload from a reopen request file."""
    parser = argparse.ArgumentParser(description="Create principal reopen prompt artifacts.")
    parser.add_argument("--reopen-request", required=True, help="Path to reopen_request.json")
    parser.add_argument("--run-id", help="Optional run id override")
    args = parser.parse_args()

    request_path = Path(args.reopen_request).expanduser()
    if not request_path.is_file():
        payload = {"status": "HOLD", "failures": [f"Missing reopen request: {request_path}"]}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    request_payload = _load_json(request_path)
    if not isinstance(request_payload, dict):
        payload = {"status": "HOLD", "failures": ["reopen_request.json must be an object."]}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    run_id = args.run_id or request_payload.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        payload = {"status": "HOLD", "failures": ["run_id missing in reopen request."]}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1
    run_id = run_id.strip()

    run_dir = request_path.parent
    prompt_path = run_dir / "principal_reopen_prompt.md"
    prompt_path.write_text(_build_prompt(request_payload) + "\n", encoding="utf-8")

    inbox_payload = {
        "run_id": run_id,
        "created_at_utc": _utc_now(),
        "reopen_request_path": str(request_path),
        "principal_reopen_prompt_path": str(prompt_path),
        "required_action": request_payload.get("required_action", "REMEDIATE"),
        "hold_reasons": request_payload.get("hold_reasons", []),
    }
    _append_jsonl(run_dir.parent / "principal_reopen_inbox.jsonl", inbox_payload)
    _write_json(run_dir / "principal_reopen_inbox_item.json", inbox_payload)

    print(json.dumps({"status": "PASS", **inbox_payload}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
