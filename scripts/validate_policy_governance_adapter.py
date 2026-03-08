#!/usr/bin/env python3
"""Validate MCP policy-governance behavior through live MCP stdio transport."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ModuleNotFoundError:  # pragma: no cover - exercised in CI collection without MCP extras.
    ClientSession = Any  # type: ignore[assignment]
    StdioServerParameters = Any  # type: ignore[assignment]
    stdio_client = None  # type: ignore[assignment]


@dataclass
class StepResult:
    """Single validation step outcome."""

    name: str
    passed: bool
    detail: str
    payload: dict[str, Any] | None = None


class ValidationFailure(RuntimeError):
    """Raised when a required validation step fails."""

    def __init__(self, step: StepResult):
        self.step = step
        super().__init__(f"{step.name}: {step.detail}")


def _git_sha() -> str:
    """Return the current git SHA, or ``unknown`` outside a git checkout."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True)
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):  # pragma: no cover
        return "unknown"


def _extract_payload(tool_result: Any) -> dict[str, Any]:
    texts: list[str] = []
    for block in getattr(tool_result, "content", []) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            texts.append(text)
    joined = "\n".join(texts).strip()
    if not joined:
        return {}

    candidate = joined
    if "{" in joined:
        candidate = joined[joined.find("{") :]

    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
        return {"raw": parsed}
    except json.JSONDecodeError:
        return {"raw": joined}


def _artifact_dir(base: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    destination = base / f"policy_governance_validation_{timestamp}"
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _probe_api_health(base_url: str) -> StepResult:
    """Validate API availability before opening MCP transport."""
    health_url = f"{base_url.rstrip('/')}/api/health"
    request = Request(health_url, method="GET")
    try:
        with urlopen(request, timeout=5) as response:  # nosec B310
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        return StepResult(
            name="api_health",
            passed=False,
            detail=f"health endpoint returned HTTP {exc.code}",
            payload={"health_url": health_url},
        )
    except URLError as exc:
        return StepResult(
            name="api_health",
            passed=False,
            detail=f"cannot reach API health endpoint: {exc.reason}",
            payload={"health_url": health_url},
        )

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return StepResult(
            name="api_health",
            passed=False,
            detail="health endpoint did not return JSON payload",
            payload={"health_url": health_url},
        )

    status_value = parsed.get("status")
    if status_value != "healthy":
        return StepResult(
            name="api_health",
            passed=False,
            detail=f"health endpoint reported status={status_value!r}",
            payload={"health_url": health_url, "response": parsed},
        )

    return StepResult(
        name="api_health",
        passed=True,
        detail="API health endpoint is reachable",
        payload={"health_url": health_url},
    )


async def _call_tool(
    session: ClientSession,
    *,
    name: str,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    result = await session.call_tool(name, arguments=arguments)
    payload = _extract_payload(result)
    is_error = bool(getattr(result, "isError", False))
    return payload, is_error


def _build_stdio_params(base_url: str) -> StdioServerParameters:
    """Build MCP stdio server parameters for the validation session."""
    env = {
        **os.environ,
        "MCP_API_URL": base_url,
        "MCP_STDIO_TRUSTED": "true",
    }
    return StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "server.mcp"],
        env=env,
    )


async def _initialize_session(
    session: ClientSession,
    *,
    email: str,
    password: str,
    steps: list[StepResult],
) -> tuple[str, list[str]]:
    """Initialize MCP session, tool inventory, and authenticated state."""
    init = await session.initialize()
    protocol_version = getattr(init, "protocolVersion", "unknown")

    tools = await session.list_tools()
    inventory = sorted(tool.name for tool in tools.tools)

    login_payload, login_error = await _call_tool(
        session,
        name="mcp_login",
        arguments={"email": email, "password": password},
    )
    login_ok = not login_error and login_payload.get("status") == "authenticated"
    login_step = StepResult(
        name="mcp_login",
        passed=login_ok,
        detail="authenticated session" if login_ok else "login failed",
        payload=login_payload,
    )
    steps.append(login_step)
    if not login_ok:
        raise ValidationFailure(login_step)

    return protocol_version, inventory


async def _validate_guardrails(session: ClientSession, steps: list[StepResult]) -> None:
    """Validate read-only and mutating guardrail behaviors."""
    status_payload, status_error = await _call_tool(
        session,
        name="mcp_guardrails_status",
        arguments={},
    )
    status_ok = not status_error and bool(status_payload.get("success", False))
    status_step = StepResult(
        name="mcp_guardrails_status",
        passed=status_ok,
        detail="read-only guardrails status" if status_ok else "guardrails call failed",
        payload=status_payload,
    )
    steps.append(status_step)
    if not status_ok:
        raise ValidationFailure(status_step)

    mut_payload, mut_error = await _call_tool(
        session,
        name="apply_policy",
        arguments={
            "policy_json": json.dumps(
                {
                    "pre_rules": [{"type": "ip_deny", "cidr": "10.0.0.0/8"}],
                    "post_rules": [],
                }
            ),
        },
    )
    mut_ok = bool(mut_error) and mut_payload.get("error") in {
        "human_approval_required",
        "blocked_by_guardrails",
    }
    mut_step = StepResult(
        name="apply_policy_guardrail",
        passed=mut_ok,
        detail="mutating guardrail denial observed",
        payload=mut_payload,
    )
    steps.append(mut_step)
    if not mut_ok:
        raise ValidationFailure(mut_step)


def _build_runtime_context(iteration: int) -> dict[str, Any]:
    """Build the formal admissibility request payload for one iteration."""
    return {
        "principal": "agent:mcp-policy-validation",
        "action": "config:read",
        "resource": f"tenant/default/config/{iteration}",
        "runtime_context_json": json.dumps(
            {
                "authenticated": True,
                "direct_access": True,
                "direct_permit": True,
                "execution_phase": "confirm",
                "preview_confirmed": True,
            }
        ),
    }


async def _run_formal_iterations(
    session: ClientSession,
    *,
    count: int,
) -> int:
    """Run the formal admissibility/verification loop and return executions."""
    executed_count = 0
    for iteration in range(count):
        formal_payload, formal_error = await _call_tool(
            session,
            name="mcp_security_evaluate_admissibility",
            arguments=_build_runtime_context(iteration),
        )
        runtime_solver = formal_payload.get("runtime_solver", {})
        formal_ok = not formal_error and isinstance(runtime_solver, dict) and bool(runtime_solver)
        if not formal_ok:
            raise ValidationFailure(
                StepResult(
                    name="mcp_security_evaluate_admissibility",
                    passed=False,
                    detail=f"failed at iteration={iteration}",
                    payload={"iteration": iteration, "payload": formal_payload},
                )
            )

        decision_id = str(formal_payload.get("certificate", {}).get("decision_id", ""))
        verify_payload, verify_error = await _call_tool(
            session,
            name="mcp_security_verify_certificate",
            arguments={"decision_id": decision_id},
        )
        verify_ok = not verify_error and bool(verify_payload.get("success", False))
        if not verify_ok:
            raise ValidationFailure(
                StepResult(
                    name="mcp_security_verify_certificate",
                    passed=False,
                    detail=f"failed at iteration={iteration}",
                    payload={
                        "iteration": iteration,
                        "decision_id": decision_id,
                        "payload": verify_payload,
                    },
                )
            )
        executed_count += 1
    return executed_count


async def _validate_job_endpoints(
    session: ClientSession,
    *,
    steps: list[StepResult],
) -> None:
    """Validate MCP job-listing and missing-job envelope behavior."""
    list_jobs_payload, list_jobs_error = await _call_tool(
        session,
        name="mcp_list_jobs",
        arguments={"limit": 10, "offset": 0},
    )
    list_jobs_ok = not list_jobs_error and list_jobs_payload.get("mode") == "sync"
    list_jobs_step = StepResult(
        name="mcp_list_jobs",
        passed=list_jobs_ok,
        detail="job listing envelope validated",
        payload=list_jobs_payload,
    )
    steps.append(list_jobs_step)
    if not list_jobs_ok:
        raise ValidationFailure(list_jobs_step)

    unknown_job_payload, unknown_job_error = await _call_tool(
        session,
        name="mcp_check_job_status",
        arguments={"job_id": "job-not-found"},
    )
    unknown_job_ok = (
        not unknown_job_error
        and unknown_job_payload.get("success") is False
        and unknown_job_payload.get("error", {}).get("status_code") == 404
    )
    unknown_job_step = StepResult(
        name="mcp_check_job_status_unknown",
        passed=unknown_job_ok,
        detail="missing job returns deterministic 404 envelope",
        payload=unknown_job_payload,
    )
    steps.append(unknown_job_step)
    if not unknown_job_ok:
        raise ValidationFailure(unknown_job_step)


async def run_validation(
    *,
    email: str,
    password: str,
    profile: str,
    count: int,
    base_url: str,
) -> dict[str, Any]:
    """Run the full MCP policy-governance validation workflow."""
    steps: list[StepResult] = []
    if stdio_client is None:
        raise RuntimeError(
            "mcp package is required to run policy-governance validation. "
            "Install the server extras before executing this command."
        )

    health_step = _probe_api_health(base_url)
    steps.append(health_step)
    if not health_step.passed:
        raise ValidationFailure(health_step)

    params = _build_stdio_params(base_url)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            protocol_version, inventory = await _initialize_session(
                session,
                email=email,
                password=password,
                steps=steps,
            )
            await _validate_guardrails(session, steps)
            executed_count = await _run_formal_iterations(session, count=count)

            steps.append(
                StepResult(
                    name="mcp_security_evaluate_admissibility_loop",
                    passed=True,
                    detail=f"executed {executed_count} admissibility evaluations",
                    payload={"executed_count": executed_count},
                )
            )

            await _validate_job_endpoints(session, steps=steps)

            if executed_count != count:
                raise ValidationFailure(
                    StepResult(
                        name="count_contract",
                        passed=False,
                        detail=(
                            "requested_count and executed_count mismatch: "
                            f"{count} != {executed_count}"
                        ),
                        payload={
                            "requested_count": count,
                            "executed_count": executed_count,
                        },
                    )
                )

            return {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "git_sha": _git_sha(),
                "profile": profile,
                "requested_count": count,
                "executed_count": executed_count,
                "first_failure_trace_id": None,
                "mcp_protocol_version": protocol_version,
                "tool_inventory": inventory,
                "steps": [
                    {
                        "name": step.name,
                        "passed": step.passed,
                        "detail": step.detail,
                        "payload": step.payload,
                    }
                    for step in steps
                ],
                "summary": {
                    "total_steps": len(steps),
                    "passed": sum(1 for step in steps if step.passed),
                    "failed": sum(1 for step in steps if not step.passed),
                    "status": "pass" if all(step.passed for step in steps) else "fail",
                },
            }


def _write_artifacts(artifact_root: Path, report: dict[str, Any]) -> Path:
    destination = _artifact_dir(artifact_root)

    report_path = destination / "validation_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "MCP Policy Governance Validation",
        "",
        f"Timestamp (UTC): {report['generated_at']}",
        f"Git SHA: {report['git_sha']}",
        f"Profile: {report['profile']}",
        f"Requested Count: {report['requested_count']}",
        f"Executed Count: {report['executed_count']}",
        f"First Failure Trace Id: {report.get('first_failure_trace_id')}",
        f"MCP Protocol: {report['mcp_protocol_version']}",
        "",
        "Step Matrix:",
    ]
    for step in report["steps"]:
        status = "PASS" if step["passed"] else "FAIL"
        lines.append(f"- {status} {step['name']}: {step['detail']}")

    summary = report["summary"]
    lines.extend(
        [
            "",
            "Summary:",
            f"- total_steps={summary['total_steps']}",
            f"- passed={summary['passed']}",
            f"- failed={summary['failed']}",
            f"- status={summary['status']}",
        ]
    )

    lines.extend(
        [
            "",
            "Tool Inventory:",
        ]
    )
    for tool_name in report.get("tool_inventory", []):
        lines.append(f"- {tool_name}")

    (destination / "SUMMARY.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse CLI arguments for the validation command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--email", default=os.getenv("MCP_VALIDATOR_EMAIL", "admin@admin.com"))
    parser.add_argument("--password", default=os.getenv("MCP_VALIDATOR_PASSWORD", "password"))
    parser.add_argument("--profile", default="dev", choices=["dev", "staging", "prod-like"])
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument(
        "--artifact-dir",
        default="tests/artifacts/algorithm/policy_governance_validation",
        help="Directory where validation artifacts are written",
    )
    return parser.parse_args(argv)


def _extract_failure_trace_id(step: StepResult) -> str | None:
    """Best-effort extraction of failure trace/certificate identifier."""
    payload = step.payload if isinstance(step.payload, dict) else {}
    direct_decision_id = payload.get("decision_id")
    if isinstance(direct_decision_id, str) and direct_decision_id:
        return direct_decision_id

    nested_payload = payload.get("payload")
    if isinstance(nested_payload, dict):
        nested_decision_id = nested_payload.get("decision_id")
        if isinstance(nested_decision_id, str) and nested_decision_id:
            return nested_decision_id
        certificate = nested_payload.get("certificate")
        if isinstance(certificate, dict):
            cert_decision_id = certificate.get("decision_id")
            if isinstance(cert_decision_id, str) and cert_decision_id:
                return cert_decision_id
    return None


def main(argv: list[str]) -> int:
    """Run the CLI validation workflow and write artifacts."""
    args = parse_args(argv)
    if args.count < 1:
        print("FAILED: --count must be >= 1", file=sys.stderr)
        return 2

    started = time.time()
    try:
        report = asyncio.run(
            run_validation(
                email=args.email,
                password=args.password,
                profile=args.profile,
                count=args.count,
                base_url=args.base_url,
            )
        )
    except ValidationFailure as exc:
        first_failure_trace_id = _extract_failure_trace_id(exc.step)
        failure_report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_sha": _git_sha(),
            "profile": args.profile,
            "requested_count": args.count,
            "executed_count": 0,
            "first_failure_trace_id": first_failure_trace_id,
            "mcp_protocol_version": "unknown",
            "tool_inventory": [],
            "steps": [
                {
                    "name": exc.step.name,
                    "passed": False,
                    "detail": exc.step.detail,
                    "payload": exc.step.payload,
                }
            ],
            "summary": {
                "total_steps": 1,
                "passed": 0,
                "failed": 1,
                "status": "fail",
            },
        }
        artifact_dir = _write_artifacts(Path(args.artifact_dir), failure_report)
        print(f"FAILED: {exc}")
        print(f"Artifact: {artifact_dir}")
        return 1
    except (RuntimeError, ValueError, OSError) as exc:  # pragma: no cover
        print(f"FAILED: unexpected exception: {exc}", file=sys.stderr)
        return 1

    report["duration_seconds"] = round(time.time() - started, 3)
    artifact_dir = _write_artifacts(Path(args.artifact_dir), report)
    print(f"Validation status: {report['summary']['status']}")
    print(f"Artifact: {artifact_dir}")
    return 0 if report["summary"]["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
