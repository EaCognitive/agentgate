#!/usr/bin/env python3
"""AgentGate MCP E2E Production Readiness Verification.

Tests all 48 MCP tool functions and 6 MCP resources by calling
the underlying REST API endpoints that the MCP server proxies to.
Architecture: LLM -> MCP tools -> MCPApiClient -> REST API.

Usage:
    uv run python scripts/verify_mcp_e2e.py
    uv run python scripts/verify_mcp_e2e.py --base-url http://host:8000
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from scripts.verify_mcp_e2e_base import BASE_URL, PR, TIMEOUT, Agent
from scripts.verify_mcp_e2e_agents import (
    ApprovalAgent,
    AuditAgent,
    AuthAgent,
    CostAgent,
    DatasetAgent,
    HealthAgent,
    MCPAgent,
    PIIAgent,
    PolicyAgent,
    SettingsAgent,
    ThreatAgent,
    TraceAgent,
    UserAgent,
)

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s: %(message)s",
)


# -------------------------------------------------------------------
# Report
# -------------------------------------------------------------------


def print_report(phases: list[PR]) -> bool:
    """Print the production readiness summary table.

    Args:
        phases: Ordered list of phase reports.

    Returns:
        True when all checks pass (production ready).
    """
    now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC",
    )
    tt = sum(p.total for p in phases)
    tp = sum(p.passed for p in phases)
    tf = sum(p.failed for p in phases)
    ts = tt - tp - tf
    ov = "PASS" if tf == 0 else "FAIL"
    sep = "-" * 68
    print(f"\n{'=' * 68}")
    print("  AgentGate MCP E2E Production Readiness Report")
    print(f"  Date: {now}")
    print(f"{'=' * 68}\n")
    hdr = (
        f"{'Phase':>5} | {'Domain':<20} | "
        f"{'Tests':>5} | {'Pass':>4} | "
        f"{'Fail':>4} | {'Skip':>4} | Status"
    )
    print(hdr)
    print(sep)
    for p in phases:
        sk = p.total - p.passed - p.failed
        st = "PASS" if p.ok else "FAIL"
        print(
            f"{p.phase:>5} | {p.domain:<20} | "
            f"{p.total:>5} | {p.passed:>4} | "
            f"{p.failed:>4} | {sk:>4} | {st}"
        )
    print(sep)
    print(f"{'':>5}   {'TOTAL':<20} | {tt:>5} | {tp:>4} | {tf:>4} | {ts:>4} | {ov}")
    print()
    ready = tf == 0
    print(f"  Production Ready: {'YES' if ready else 'NO'}")
    print(f"{'=' * 68}\n")
    return ready


# -------------------------------------------------------------------
# Orchestrator
# -------------------------------------------------------------------

ALL_AGENTS: list[type[Agent]] = [
    HealthAgent,
    AuthAgent,
    UserAgent,
    ThreatAgent,
    PIIAgent,
    AuditAgent,
    CostAgent,
    TraceAgent,
    DatasetAgent,
    SettingsAgent,
    ApprovalAgent,
    PolicyAgent,
    MCPAgent,
]


async def run_verification(base_url: str) -> bool:
    """Execute the full E2E verification suite.

    Args:
        base_url: AgentGate API base URL.

    Returns:
        True if production ready (zero failures).
    """
    ctx: dict[str, Any] = {}
    phases: list[PR] = []
    start = time.monotonic()
    async with httpx.AsyncClient(
        base_url=base_url,
        timeout=TIMEOUT,
    ) as client:
        for cls in ALL_AGENTS:
            ag = cls(client, ctx)
            print(f"\n--- Phase {ag.phase}: {ag.domain} ---")
            phases.append(await ag.run())
    elapsed = time.monotonic() - start
    ready = print_report(phases)
    print(f"  Total time: {elapsed:.1f}s\n")
    return ready


def main() -> None:
    """Parse arguments and run verification."""
    parser = argparse.ArgumentParser(
        description=("AgentGate MCP E2E Production Verification"),
    )
    parser.add_argument(
        "--base-url",
        default=BASE_URL,
        help=f"API base URL (default: {BASE_URL})",
    )
    args = parser.parse_args()
    print(f"AgentGate MCP E2E Verification -> {args.base_url}\n")
    ready = asyncio.run(run_verification(args.base_url))
    sys.exit(0 if ready else 1)


if __name__ == "__main__":
    main()
