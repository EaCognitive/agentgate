#!/usr/bin/env python3
"""Generate a formal policy-governance verification report package.

The report package is built from formal forensic run artifacts and includes:
- machine-readable manifest with SHA-256 hashes
- engineering report in Markdown
- optional PDF rendering when local toolchain is available

This script does not claim external certification. It assembles implementation
and test evidence for audit review and internal release governance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.privacy_sanitizer import sanitize_value

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_ROOT = REPO_ROOT / "tests" / "artifacts"
DEFAULT_REPORT_ROOT = ARTIFACTS_ROOT / "reports"
REPORT_JSON = "formal_runtime_forensic_report.json"
LEDGER_JSONL = "formal_runtime_forensic_ledger.jsonl"
SUMMARY_TXT = "SUMMARY.txt"
MARKDOWN_REPORT = "POLICY_GOVERNANCE_VERIFICATION_REPORT.md"
LATEX_REPORT = "POLICY_GOVERNANCE_VERIFICATION_REPORT.tex"
PDF_REPORT = "POLICY_GOVERNANCE_VERIFICATION_REPORT.pdf"
MANIFEST_JSON = "REPORT_MANIFEST.json"
FORMAL_LAYOUT_ROOT = ARTIFACTS_ROOT / "algorithm" / "formal_verification"
FORMAL_RUNS_ROOT = FORMAL_LAYOUT_ROOT / "runs"
FORMAL_LATEST_FORENSIC = FORMAL_LAYOUT_ROOT / "latest_forensic"

REQUIRED_REPORT_KEYS = {
    "run_type",
    "started_at_utc",
    "completed_at_utc",
    "elapsed_seconds",
    "config",
    "runtime",
    "git",
    "status_distribution",
    "solver_mode_distribution",
    "solver_backend_distribution",
    "certificate_verify_count",
    "evidence_verify_count",
    "failure_count",
    "failures",
}


@dataclass(frozen=True)
class ReportConfig:
    """Resolved configuration for report generation."""

    source_dir: Path
    output_dir: Path
    output_format: str
    strict_pdf: bool
    title: str


@dataclass(frozen=True)
class RenderResult:
    """Paths for generated report artifacts."""

    markdown_path: Path
    latex_path: Path | None
    pdf_path: Path | None
    manifest_path: Path
    source_dir: Path


@dataclass(frozen=True)
class ArtifactHashes:
    """Hashes for source forensic artifacts."""

    report_hash: str
    ledger_hash: str
    summary_hash: str | None


@dataclass(frozen=True)
class RenderedOutputs:
    """Rendered report outputs and renderer status codes."""

    markdown_path: Path
    latex_path: Path | None
    pdf_path: Path | None
    latex_status: str
    pdf_status: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _discover_source_dir(profile: str) -> Path:
    if profile == "latest-canonical":
        candidate = FORMAL_LAYOUT_ROOT / "latest"
        if candidate.is_dir():
            return candidate
        raise FileNotFoundError(f"Canonical latest directory not found: {candidate}")

    if FORMAL_LATEST_FORENSIC.is_dir():
        return FORMAL_LATEST_FORENSIC

    candidates = sorted(
        (path for path in FORMAL_RUNS_ROOT.glob("formal_runtime_forensic_run_*") if path.is_dir()),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0]

    fallback = FORMAL_LAYOUT_ROOT / "dev_e2e_data_check"
    if fallback.is_dir():
        return fallback

    raise FileNotFoundError(
        "No forensic formal artifacts found. Run './run verify formal run ...' first."
    )


def _slugify_component(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    return normalized.strip("-") or "unknown"


def _resolve_config(args: argparse.Namespace) -> ReportConfig:
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
        output_dir = DEFAULT_REPORT_ROOT / _slugify_component(source_dir.name) / f"package_{stamp}"

    return ReportConfig(
        source_dir=source_dir,
        output_dir=output_dir,
        output_format=args.format,
        strict_pdf=bool(args.strict_pdf),
        title=args.title,
    )


def _load_required_artifacts(
    source_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    report_path = source_dir / REPORT_JSON
    ledger_path = source_dir / LEDGER_JSONL
    summary_path = source_dir / SUMMARY_TXT

    if not report_path.is_file():
        raise FileNotFoundError(f"Missing required report file: {report_path}")
    if not ledger_path.is_file():
        raise FileNotFoundError(f"Missing required ledger file: {ledger_path}")

    report_data = sanitize_value(json.loads(report_path.read_text(encoding="utf-8")))
    if not isinstance(report_data, dict):
        raise RuntimeError("Formal report JSON must be an object")

    missing = sorted(key for key in REQUIRED_REPORT_KEYS if key not in report_data)
    if missing:
        raise RuntimeError(f"Formal report JSON missing required keys: {missing}")

    ledger_entries: list[dict[str, Any]] = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            ledger_entries.append(sanitize_value(parsed))

    summary_text = summary_path.read_text(encoding="utf-8") if summary_path.is_file() else None
    return report_data, ledger_entries, summary_text


def _summarize_ledger(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not entries:
        return {
            "entry_count": 0,
            "result_distribution": {},
            "status_distribution": {},
            "max_elapsed_ms": None,
            "min_elapsed_ms": None,
            "p95_elapsed_ms": None,
        }

    result_distribution: dict[str, int] = {}
    status_distribution: dict[str, int] = {}
    elapsed: list[float] = []

    for entry in entries:
        result = str(entry.get("result", "unknown"))
        result_distribution[result] = result_distribution.get(result, 0) + 1

        status = str(entry.get("admissibility_status_code", "unknown"))
        status_distribution[status] = status_distribution.get(status, 0) + 1

        raw_elapsed = entry.get("elapsed_ms")
        if isinstance(raw_elapsed, (int, float)):
            elapsed.append(float(raw_elapsed))

    elapsed.sort()
    p95_index = int((len(elapsed) - 1) * 0.95) if elapsed else 0
    return {
        "entry_count": len(entries),
        "result_distribution": result_distribution,
        "status_distribution": status_distribution,
        "max_elapsed_ms": max(elapsed) if elapsed else None,
        "min_elapsed_ms": min(elapsed) if elapsed else None,
        "p95_elapsed_ms": elapsed[p95_index] if elapsed else None,
    }


def _artifact_path_for_display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


def _json_block(payload: Any) -> str:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    return f"```json\n{rendered}\n```"


def _wrap_token(text: str, *, width: int = 8) -> str:
    normalized = text.strip()
    if not normalized:
        return normalized
    parts = [normalized[idx : idx + width] for idx in range(0, len(normalized), width)]
    return " ".join(parts)


def _break_path(path_text: str) -> str:
    return path_text.replace("/", "/\u200b")


def _build_compliance_mapping() -> list[dict[str, str]]:
    return [
        {
            "control": "EU AI Act timeline reference (high-risk obligations from August 2, 2026)",
            "status": "context included",
            "evidence": (
                "Document control section records runtime, artifact lineage, and generated "
                "timestamps to support period-bound audit interpretation."
            ),
        },
        {
            "control": "EU AI Act Article 9 (risk management system)",
            "status": "partial technical coverage",
            "evidence": (
                "Fail-fast campaign execution, invariant violation accounting, and deterministic "
                "configuration capture in forensic report artifacts."
            ),
        },
        {
            "control": "EU AI Act Article 10 (data and data governance)",
            "status": "partial technical coverage",
            "evidence": (
                "Sanitized scenario corpus handling and explicit scenario path/version metadata in "
                "forensic report configuration."
            ),
        },
        {
            "control": "EU AI Act Article 12 (event traceability)",
            "status": "partial technical coverage",
            "evidence": (
                "Formal ledger entries, run timestamps, certificate verification count, "
                "and evidence verification count."
            ),
        },
        {
            "control": "EU AI Act Article 15 (robustness/cybersecurity)",
            "status": "partial technical coverage",
            "evidence": (
                "Enforce-mode runtime solver checks, fail-fast violations, and "
                "runtime solver metadata verification."
            ),
        },
        {
            "control": "HIPAA 45 CFR 164.312(b) audit controls",
            "status": "partial technical coverage",
            "evidence": (
                "Decision certificates, proof verification runs, and immutable "
                "evidence-chain records."
            ),
        },
        {
            "control": "HIPAA 45 CFR 164.312(c)(1) integrity",
            "status": "partial technical coverage",
            "evidence": ("Hash-linked evidence chain and certificate signature verification path."),
        },
        {
            "control": "SOC 2 CC7 change/monitoring controls",
            "status": "partial technical coverage",
            "evidence": (
                "Versioned artifacts, git metadata, deterministic run configuration, "
                "and manifest checksums."
            ),
        },
        {
            "control": "External certification/attestation",
            "status": "not included",
            "evidence": "Independent assessor attestation is outside this code/test report scope.",
        },
    ]


def _build_compliance_section() -> str:
    lines: list[str] = []
    mapping = _build_compliance_mapping()
    for index, entry in enumerate(mapping, start=1):
        lines.append(f"{index}. **{entry['control']}**")
        lines.append(f"   - Status: `{entry['status']}`")
        lines.append(f"   - Evidence: {entry['evidence']}")
    return "\n".join(lines)


def _append_section(lines: list[str], heading: str, *content: str) -> None:
    """Append a report section with a heading and content lines."""
    lines.append(heading)
    lines.append("")
    lines.extend(content)
    lines.append("")


def _executive_summary_lines(
    report_data: dict[str, Any],
    runtime_status: dict[str, Any],
) -> list[str]:
    """Build the executive summary block."""
    return [
        f"- Result: `{'PASS' if int(report_data.get('failure_count', 0)) == 0 else 'FAIL'}`",
        f"- Failure Count: `{report_data.get('failure_count')}`",
        (
            f"- Runtime Solver: mode=`{runtime_status.get('configured_mode')}`, "
            f"z3_healthy=`{runtime_status.get('z3_healthy')}`"
        ),
        (
            "- Verification Coverage: "
            f"certificates=`{report_data.get('certificate_verify_count')}`, "
            f"evidence=`{report_data.get('evidence_verify_count')}`"
        ),
        (
            "- Regulatory Timing Reference: EU AI Act high-risk obligations become broadly "
            "applicable on `August 2, 2026`."
        ),
    ]


def _document_control_lines(
    report_data: dict[str, Any],
    source_path: str,
    git_meta: dict[str, Any],
) -> list[str]:
    """Build the document-control block."""
    return [
        f"- Generated UTC: `{_utc_now_iso()}`",
        f"- Run Started UTC: `{report_data.get('started_at_utc')}`",
        f"- Run Completed UTC: `{report_data.get('completed_at_utc')}`",
        f"- Elapsed Seconds: `{report_data.get('elapsed_seconds')}`",
        "- Source Artifact Directory:",
        "```text",
        source_path,
        "```",
        "",
        "- Git Metadata:",
        _json_block(git_meta),
    ]


def _artifact_integrity_lines(hashes: ArtifactHashes) -> list[str]:
    """Build the artifact-integrity block."""
    return [
        "- Source Report SHA-256:",
        "```text",
        _wrap_token(hashes.report_hash),
        "```",
        "",
        "- Source Ledger SHA-256:",
        "```text",
        _wrap_token(hashes.ledger_hash),
        "```",
        "",
        "- Source Summary SHA-256:",
        "```text",
        _wrap_token(hashes.summary_hash or "n/a"),
        "```",
    ]


def _build_markdown_report(
    *,
    title: str,
    report_data: dict[str, Any],
    ledger_summary: dict[str, Any],
    source_dir: Path,
    hashes: ArtifactHashes,
) -> str:
    config = report_data.get("config", {})
    runtime = report_data.get("runtime", {})
    git_meta = report_data.get("git", {})
    runtime_status = runtime.get("runtime_status", {})
    source_path = _break_path(_artifact_path_for_display(source_dir))

    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    _append_section(
        lines,
        "## 1. Executive Summary",
        *_executive_summary_lines(report_data, runtime_status),
    )
    _append_section(
        lines,
        "## 2. Document Control",
        *_document_control_lines(report_data, source_path, git_meta),
    )
    _append_section(lines, "## 3. Runtime Configuration", _json_block(config))
    _append_section(
        lines,
        "## 4. Formal Verification Outcomes",
        "- HTTP Status Distribution:",
        _json_block(report_data.get("status_distribution", {})),
        "",
        "- Solver Mode Distribution:",
        _json_block(report_data.get("solver_mode_distribution", {})),
        "",
        "- Solver Backend Distribution:",
        _json_block(report_data.get("solver_backend_distribution", {})),
        "",
        "- Runtime Status:",
        _json_block(runtime_status),
    )
    _append_section(lines, "## 5. Ledger Statistics", _json_block(ledger_summary))
    _append_section(
        lines,
        "## 6. Artifact Integrity",
        *_artifact_integrity_lines(hashes),
    )
    _append_section(
        lines,
        "## 7. Compliance Mapping (Technical Evidence)",
        _build_compliance_section(),
    )
    _append_section(
        lines,
        "## 8. Scope and Limitations",
        (
            "This report provides technical verification evidence only. "
            "It is not an external certification or attestation. "
            "SOC 2/SOC 3, HIPAA, and EU AI Act conformity requires additional "
            "organizational, legal, and operational controls."
        ),
    )
    return "\n".join(lines)


def _render_latex(markdown_path: Path, latex_path: Path) -> tuple[bool, str]:
    pandoc = shutil.which("pandoc")
    if pandoc is None:
        return False, "pandoc_not_found"

    command = [
        pandoc,
        str(markdown_path),
        "--from",
        "gfm",
        "--to",
        "latex",
        "--standalone",
        "--output",
        str(latex_path),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "pandoc_latex_failed"
        return False, stderr
    return True, "ok"


def _render_pdf(markdown_path: Path, pdf_path: Path) -> tuple[bool, str]:
    pandoc = shutil.which("pandoc")
    if pandoc is None:
        return False, "pandoc_not_found"

    xelatex = shutil.which("xelatex")
    if xelatex is None:
        return False, "xelatex_not_found"

    header_content = "\n".join(
        [
            r"\usepackage{fvextra}",
            (
                r"\DefineVerbatimEnvironment{Highlighting}{Verbatim}"
                r"{breaklines,breakanywhere,commandchars=\\\{\}}"
            ),
            r"\fvset{breaklines=true,breakanywhere=true}",
            r"\sloppy",
            r"\setlength{\emergencystretch}{3em}",
        ]
    )

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".tex",
        delete=False,
    ) as handle:
        handle.write(header_content)
        header_path = Path(handle.name)

    command = [
        pandoc,
        str(markdown_path),
        "--pdf-engine",
        xelatex,
        "--from",
        "gfm",
        "--to",
        "pdf",
        "--variable",
        "geometry:margin=1in",
        "--variable",
        "fontsize=10pt",
        "--variable",
        "papersize=letter",
        "--include-in-header",
        str(header_path),
        "--output",
        str(pdf_path),
    ]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    finally:
        header_path.unlink(missing_ok=True)

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "pandoc_failed"
        return False, stderr
    return True, "ok"


def _manifest_file_entry(path: Path | None, status: str | None = None) -> dict[str, Any]:
    """Build a manifest file entry."""
    entry: dict[str, Any] = {
        "path": _artifact_path_for_display(path) if path else None,
        "sha256": _sha256_file(path) if path else None,
    }
    if status is not None:
        entry["status"] = status
    return entry


def _write_manifest(
    *,
    config: ReportConfig,
    report_data: dict[str, Any],
    outputs: RenderedOutputs,
    source_report: Path,
    source_ledger: Path,
    source_summary: Path | None,
) -> Path:
    """Write the report package manifest."""
    manifest = {
        "generated_at_utc": _utc_now_iso(),
        "report_title": config.title,
        "source_dir": _artifact_path_for_display(config.source_dir),
        "output_dir": _artifact_path_for_display(config.output_dir),
        "run_type": report_data.get("run_type"),
        "git": report_data.get("git", {}),
        "files": {
            "source_report": _manifest_file_entry(source_report),
            "source_ledger": _manifest_file_entry(source_ledger),
            "source_summary": _manifest_file_entry(source_summary),
            "markdown_report": _manifest_file_entry(outputs.markdown_path),
            "latex_report": _manifest_file_entry(outputs.latex_path, outputs.latex_status),
            "pdf_report": _manifest_file_entry(outputs.pdf_path, outputs.pdf_status),
        },
    }
    manifest_dir = config.output_dir / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / MANIFEST_JSON
    manifest_path.write_text(
        json.dumps(sanitize_value(manifest), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _source_artifact_paths(source_dir: Path) -> tuple[Path, Path, Path]:
    """Return the expected forensic artifact paths."""
    return (
        source_dir / REPORT_JSON,
        source_dir / LEDGER_JSONL,
        source_dir / SUMMARY_TXT,
    )


def _artifact_hashes(
    source_report: Path,
    source_ledger: Path,
    source_summary: Path,
) -> ArtifactHashes:
    """Compute source artifact hashes."""
    return ArtifactHashes(
        report_hash=_sha256_file(source_report),
        ledger_hash=_sha256_file(source_ledger),
        summary_hash=_sha256_file(source_summary) if source_summary.is_file() else None,
    )


def _render_optional_outputs(
    config: ReportConfig,
    report_dir: Path,
    markdown_path: Path,
) -> RenderedOutputs:
    """Render optional LaTeX and PDF outputs."""
    latex_path: Path | None = None
    latex_status = "skipped"
    if config.output_format in {"pdf", "both"}:
        latex_candidate = report_dir / LATEX_REPORT
        ok, status = _render_latex(markdown_path, latex_candidate)
        latex_status = status
        if ok:
            latex_path = latex_candidate
        elif config.strict_pdf:
            raise RuntimeError(f"LaTeX generation failed: {status}")

    pdf_path: Path | None = None
    pdf_status = "skipped"
    if config.output_format in {"pdf", "both"}:
        pdf_candidate = report_dir / PDF_REPORT
        ok, status = _render_pdf(markdown_path, pdf_candidate)
        pdf_status = status
        if ok:
            pdf_path = pdf_candidate
        elif config.strict_pdf:
            raise RuntimeError(f"PDF rendering failed: {status}")

    return RenderedOutputs(
        markdown_path=markdown_path,
        latex_path=latex_path,
        pdf_path=pdf_path,
        latex_status=latex_status,
        pdf_status=pdf_status,
    )


def _generate_report(config: ReportConfig) -> RenderResult:
    """Generate the report package from source artifacts."""
    source_report, source_ledger, source_summary = _source_artifact_paths(config.source_dir)
    report_data, ledger_entries, _ = _load_required_artifacts(config.source_dir)
    ledger_summary = _summarize_ledger(ledger_entries)
    hashes = _artifact_hashes(source_report, source_ledger, source_summary)

    config.output_dir.mkdir(parents=True, exist_ok=True)
    report_dir = config.output_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    markdown_content = _build_markdown_report(
        title=config.title,
        report_data=report_data,
        ledger_summary=ledger_summary,
        source_dir=config.source_dir,
        hashes=hashes,
    )
    markdown_path = report_dir / MARKDOWN_REPORT
    markdown_path.write_text(markdown_content, encoding="utf-8")

    outputs = _render_optional_outputs(config, report_dir, markdown_path)
    manifest_path = _write_manifest(
        config=config,
        report_data=report_data,
        outputs=outputs,
        source_report=source_report,
        source_ledger=source_ledger,
        source_summary=source_summary if source_summary.is_file() else None,
    )

    return RenderResult(
        markdown_path=outputs.markdown_path,
        latex_path=outputs.latex_path,
        pdf_path=outputs.pdf_path,
        manifest_path=manifest_path,
        source_dir=config.source_dir,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a policy-governance formal verification report package.",
    )
    parser.add_argument(
        "--source-profile",
        choices=["latest-forensic", "latest-canonical"],
        default="latest-forensic",
        help="Source profile used when --source-dir is not supplied.",
    )
    parser.add_argument(
        "--source-dir",
        default="",
        help="Explicit source artifact directory.",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Explicit report output directory.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "pdf", "both"],
        default="both",
        help="Output format selection.",
    )
    parser.add_argument(
        "--strict-pdf",
        action="store_true",
        help="Fail if PDF rendering is requested but toolchain is unavailable.",
    )
    parser.add_argument(
        "--title",
        default="AgentGate Policy Governance Verification Report",
        help="Document title used in generated report outputs.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the report generator CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = _resolve_config(args)

    result = _generate_report(config)
    print("")
    print("=" * 68)
    print("POLICY GOVERNANCE REPORT PACKAGE COMPLETE")
    print("=" * 68)
    print(f"Source directory: {result.source_dir}")
    print(f"Markdown report: {result.markdown_path}")
    if result.latex_path is not None:
        print(f"LaTeX report:    {result.latex_path}")
    else:
        print("LaTeX report:    not generated")
    if result.pdf_path is not None:
        print(f"PDF report:      {result.pdf_path}")
    else:
        print("PDF report:      not generated")
    print(f"Manifest:        {result.manifest_path}")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
