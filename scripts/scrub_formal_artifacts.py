#!/usr/bin/env python3
"""Scrub formal verification artifacts and verify privacy safety before sharing."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.privacy_sanitizer import detect_sensitive_text
from scripts.privacy_sanitizer import sanitize_text
from scripts.privacy_sanitizer import sanitize_value

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_ROOT = REPO_ROOT / "tests" / "artifacts"
SHARE_ROOT = ARTIFACTS_ROOT / "share"
REPORT_FILENAME = "SCRUB_REPORT.json"
SUMMARY_FILENAME = "SHARE_SUMMARY.txt"
MANIFEST_FILENAME = "MANIFEST.json"
DEFAULT_TEXT_SUFFIXES = {
    ".json",
    ".jsonl",
    ".txt",
    ".log",
    ".csv",
    ".md",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class ScrubConfig:
    """Resolved filesystem configuration for a scrub or verify-only run."""

    source_dir: Path
    output_dir: Path
    verify_only: bool
    overwrite: bool


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scrub formal artifacts and verify that share output contains no sensitive data."
        ),
    )
    parser.add_argument(
        "--source-profile",
        choices=["latest-forensic", "latest-canonical"],
        default="latest-forensic",
        help="Source profile used when --source-dir is not provided.",
    )
    parser.add_argument(
        "--source-dir",
        default="",
        help="Explicit source artifact directory.",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Explicit output directory for scrubbed artifacts.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Scan source directory for sensitive content without creating scrubbed output.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwrite if output directory already exists.",
    )
    return parser


def _discover_source_dir(profile: str) -> Path:
    def has_files(candidate: Path) -> bool:
        return any(path.is_file() for path in candidate.rglob("*"))

    if profile == "latest-canonical":
        candidate = ARTIFACTS_ROOT / "algorithm" / "formal_verification" / "latest"
        if candidate.is_dir() and has_files(candidate):
            return candidate
        raise FileNotFoundError(f"Canonical latest artifacts not found: {candidate}")

    runs = sorted(
        (path for path in ARTIFACTS_ROOT.glob("formal_runtime_forensic_run_*") if path.is_dir()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    for run_dir in runs:
        if has_files(run_dir):
            return run_dir
    raise FileNotFoundError(
        "No formal forensic run directory found under tests/artifacts/. "
        "Run './run verify formal run ...' first or pass --source-dir.",
    )


def _resolve_config(args: argparse.Namespace) -> ScrubConfig:
    source_dir = (
        Path(args.source_dir).resolve()
        if args.source_dir
        else _discover_source_dir(args.source_profile)
    )
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source directory does not exist: {source_dir}")

    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = SHARE_ROOT / f"{source_dir.name}_scrubbed_{stamp}"

    return ScrubConfig(
        source_dir=source_dir,
        output_dir=output_dir,
        verify_only=bool(args.verify_only),
        overwrite=bool(args.overwrite),
    )


def _path_for_report(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


def _sha256_bytes(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def _read_text_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def _sanitize_json_content(raw: str) -> str:
    parsed = json.loads(raw)
    sanitized = sanitize_value(parsed)
    return json.dumps(sanitized, indent=2, sort_keys=True) + "\n"


def _sanitize_jsonl_content(raw: str) -> str:
    sanitized_lines: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            sanitized_lines.append("")
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            sanitized_lines.append(sanitize_text(line))
            continue
        sanitized_lines.append(json.dumps(sanitize_value(parsed), sort_keys=True))
    return "\n".join(sanitized_lines) + "\n"


def _sanitize_text_content(path: Path, raw: str) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return _sanitize_json_content(raw), "json"
        except json.JSONDecodeError:
            return sanitize_text(raw), "text"
    if suffix == ".jsonl":
        return _sanitize_jsonl_content(raw), "jsonl"
    return sanitize_text(raw), "text"


def _detect_findings_in_text(path: Path, raw: str) -> list[dict[str, Any]]:
    findings = detect_sensitive_text(raw)
    if not findings:
        return []
    return [
        {
            "file": str(path),
            "pattern": finding,
        }
        for finding in findings
    ]


def _scan_directory_for_findings(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        raw_text = _read_text_file(path)
        if raw_text is None:
            continue
        findings.extend(_detect_findings_in_text(path.relative_to(root), raw_text))
    return findings


def _scrub_directory(config: ScrubConfig) -> dict[str, Any]:
    if config.verify_only:
        source_file_count = sum(1 for path in config.source_dir.rglob("*") if path.is_file())
        findings = _scan_directory_for_findings(config.source_dir)
        if source_file_count == 0:
            findings.append(
                {
                    "file": ".",
                    "pattern": "empty_source_directory",
                }
            )
        return {
            "mode": "verify_only",
            "source_dir": _path_for_report(config.source_dir),
            "output_dir": None,
            "files_processed": source_file_count,
            "text_files_processed": 0,
            "binary_files_copied": 0,
            "files_changed": 0,
            "manifest_entries": [],
            "finding_count": len(findings),
            "findings": findings,
            "verified_target": _path_for_report(config.source_dir),
            "created_at_utc": _utc_now_iso(),
        }

    if config.output_dir.exists():
        if not config.overwrite:
            raise FileExistsError(
                "Output directory already exists. Use --overwrite or choose --output-dir. "
                f"path={config.output_dir}"
            )
        shutil.rmtree(config.output_dir)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    files_processed = 0
    text_files_processed = 0
    binary_files_copied = 0
    files_changed = 0
    manifest_entries: list[dict[str, Any]] = []

    for source_path in sorted(config.source_dir.rglob("*")):
        if not source_path.is_file():
            continue
        files_processed += 1
        relative_path = source_path.relative_to(config.source_dir)
        destination_path = config.output_dir / relative_path
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        raw_text = _read_text_file(source_path)
        if raw_text is None:
            binary_files_copied += 1
            raw_bytes = source_path.read_bytes()
            destination_path.write_bytes(raw_bytes)
            manifest_entries.append(
                {
                    "path": str(relative_path),
                    "mode": "binary_copy",
                    "changed": False,
                    "source_sha256": _sha256_bytes(raw_bytes),
                    "output_sha256": _sha256_bytes(raw_bytes),
                }
            )
            continue

        text_files_processed += 1
        sanitized_text, strategy = _sanitize_text_content(source_path, raw_text)
        destination_path.write_text(sanitized_text, encoding="utf-8")
        changed = raw_text != sanitized_text
        if changed:
            files_changed += 1
        manifest_entries.append(
            {
                "path": str(relative_path),
                "mode": f"text_{strategy}",
                "changed": changed,
                "source_sha256": _sha256_bytes(raw_text.encode("utf-8")),
                "output_sha256": _sha256_bytes(sanitized_text.encode("utf-8")),
            }
        )

    if files_processed == 0:
        raise RuntimeError(
            f"Source directory has no files to scrub: {_path_for_report(config.source_dir)}",
        )

    findings = _scan_directory_for_findings(config.output_dir)
    return {
        "mode": "scrub_and_verify",
        "source_dir": _path_for_report(config.source_dir),
        "output_dir": _path_for_report(config.output_dir),
        "files_processed": files_processed,
        "text_files_processed": text_files_processed,
        "binary_files_copied": binary_files_copied,
        "files_changed": files_changed,
        "manifest_entries": manifest_entries,
        "finding_count": len(findings),
        "findings": findings,
        "verified_target": _path_for_report(config.output_dir),
        "created_at_utc": _utc_now_iso(),
    }


def _write_report(output_dir: Path, report: dict[str, Any]) -> None:
    report_path = output_dir / REPORT_FILENAME
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest_path = output_dir / MANIFEST_FILENAME
    manifest_payload = {
        "source_dir": report["source_dir"],
        "output_dir": report["output_dir"],
        "created_at_utc": report["created_at_utc"],
        "files": report["manifest_entries"],
    }
    manifest_path.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    summary = (
        "FORMAL ARTIFACT SCRUB SUMMARY\n"
        "============================================================\n"
        f"Source: {report['source_dir']}\n"
        f"Output: {report['output_dir']}\n"
        f"Created (UTC): {report['created_at_utc']}\n"
        f"Files processed: {report['files_processed']}\n"
        f"Text files processed: {report['text_files_processed']}\n"
        f"Binary files copied: {report['binary_files_copied']}\n"
        f"Files changed: {report['files_changed']}\n"
        f"Finding count: {report['finding_count']}\n"
        "============================================================\n"
    )
    (output_dir / SUMMARY_FILENAME).write_text(summary, encoding="utf-8")


def _print_summary(report: dict[str, Any]) -> None:
    print("")
    print("FORMAL ARTIFACT SCRUB RESULT")
    print("============================================================")
    print(f"Mode:             {report['mode']}")
    print(f"Source:           {report['source_dir']}")
    if report["output_dir"]:
        print(f"Output:           {report['output_dir']}")
    print(f"Files processed:  {report['files_processed']}")
    print(f"Files changed:    {report['files_changed']}")
    print(f"Finding count:    {report['finding_count']}")
    if report["finding_count"]:
        print("Findings:")
        for finding in report["findings"][:20]:
            print(f"  - {finding['file']}: {finding['pattern']}")
        if report["finding_count"] > 20:
            print(f"  - ... and {report['finding_count'] - 20} more")
    print("============================================================")


def main() -> int:
    """Run artifact scrubbing or verification and report the result."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        config = _resolve_config(args)
        report = _scrub_directory(config)
        if not config.verify_only:
            _write_report(config.output_dir, report)
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"Artifact scrub failed: {exc}")
        return 1

    _print_summary(report)
    if int(report["finding_count"]) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
