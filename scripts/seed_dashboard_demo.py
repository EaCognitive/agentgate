"""Seed the database with demo data for dashboard screenshots.

Creates:
- 36 traces across multiple tools with mixed statuses and staggered times
- 5 pending approvals
- 10 policies covering compliance, security, and operational governance
- 6 verification certificates

Usage:
    python3 scripts/seed_dashboard_demo.py

Environment:
    API_BASE          Backend URL (default http://localhost:8000)
    ADMIN_EMAIL       Login email  (default admin@admin.com)
    ADMIN_PASSWORD    Login password (default password)
"""

from __future__ import annotations

import asyncio
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from scripts.seed_demo_policies import (
    ACTIVATE_POLICIES,
    LOAD_POLICIES,
    LOCK_POLICIES,
    POLICY_DOCS,
)

API_BASE = os.getenv("API_BASE", "http://localhost:8000")
ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL",
    os.getenv("DEFAULT_ADMIN_EMAIL", "admin@admin.com"),
)
ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD",
    os.getenv("DEFAULT_ADMIN_PASSWORD", "password"),
)

AGENT_PROFILES = [
    {
        "agent_id": "trading-agent",
        "tools": ["db_query", "web_search", "email_send"],
        "resources": [
            "database/trades",
            "api/market-data",
            "s3/financial-reports",
        ],
        "prompts": [
            "Fetch latest portfolio positions",
            "Query trade settlement status for Q4",
            "Pull market data for AAPL, MSFT, GOOG",
        ],
    },
    {
        "agent_id": "clinical-data-agent",
        "tools": ["db_query", "file_read", "llm_query"],
        "resources": [
            "database/patients",
            "s3/medical-records",
            "api/lab-results",
        ],
        "prompts": [
            "Retrieve patient lab results for case #4521",
            "Summarize discharge notes from last 24h",
            "Query PHI records for compliance audit",
        ],
    },
    {
        "agent_id": "code-review-agent",
        "tools": ["code_interpreter", "llm_query", "slack_post"],
        "resources": [
            "github/pull-requests",
            "s3/build-artifacts",
            "api/ci-pipeline",
        ],
        "prompts": [
            "Review PR #892 for security vulnerabilities",
            "Run static analysis on auth module",
            "Post review summary to #engineering",
        ],
    },
    {
        "agent_id": "customer-support-agent",
        "tools": ["llm_query", "email_send", "db_query"],
        "resources": [
            "database/tickets",
            "api/knowledge-base",
            "email/support-inbox",
        ],
        "prompts": [
            "Draft response to ticket #TK-3301",
            "Look up customer account history",
            "Escalate billing dispute to finance team",
        ],
    },
    {
        "agent_id": "devops-deploy-agent",
        "tools": ["code_interpreter", "slack_post", "file_read"],
        "resources": [
            "k8s/production-cluster",
            "s3/deploy-configs",
            "api/monitoring",
        ],
        "prompts": [
            "Deploy v2.4.1 to staging environment",
            "Check pod health in production cluster",
            "Roll back deployment if error rate exceeds 5%",
        ],
    },
]

STATUSES = ["success", "failed", "blocked"]
STATUS_WEIGHTS = [0.60, 0.20, 0.20]

APPROVAL_SCENARIOS = [
    {
        "tool": "email_send",
        "agent_id": "customer-support-agent",
        "inputs": {
            "action": ("Send bulk notification to 847 customers"),
            "resource": "email/support-inbox",
        },
    },
    {
        "tool": "db_query",
        "agent_id": "clinical-data-agent",
        "inputs": {
            "action": ("Export 12,000 patient records for audit"),
            "resource": "database/patients",
        },
    },
    {
        "tool": "slack_post",
        "agent_id": "code-review-agent",
        "inputs": {
            "action": ("Post deployment report to #engineering"),
            "resource": "api/ci-pipeline",
        },
    },
    {
        "tool": "code_interpreter",
        "agent_id": "devops-deploy-agent",
        "inputs": {
            "action": ("Execute production rollback script"),
            "resource": "k8s/production-cluster",
        },
    },
    {
        "tool": "file_write",
        "agent_id": "trading-agent",
        "inputs": {
            "action": ("Write quarterly P&L report to S3"),
            "resource": "s3/financial-reports",
        },
    },
]

CERT_SCENARIOS = [
    {
        "principal": "trading-agent",
        "action": "read",
        "resource": "database/trades",
        "runtime_context": {"authenticated": True},
    },
    {
        "principal": "clinical-data-agent",
        "action": "read",
        "resource": "database/patients",
        "runtime_context": {"authenticated": True},
    },
    {
        "principal": "code-review-agent",
        "action": "read",
        "resource": "api/ci-pipeline",
        "runtime_context": {"authenticated": True},
    },
    {
        "principal": "trading-agent",
        "action": "delete",
        "resource": "database/trades",
        "runtime_context": {"authenticated": True},
    },
    {
        "principal": "unknown-agent",
        "action": "read",
        "resource": "database/patients",
        "runtime_context": {"authenticated": False},
    },
    {
        "principal": "devops-deploy-agent",
        "action": "execute",
        "resource": "k8s/production-cluster",
        "runtime_context": {"authenticated": True},
    },
]


async def post(
    client: httpx.AsyncClient,
    path: str,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> dict[str, Any] | None:
    """POST JSON to the API and return parsed response."""
    resp = await client.post(
        f"{API_BASE}{path}",
        json=payload,
        headers=headers,
    )
    if resp.status_code >= 400:
        print(f"  WARN {path} -> {resp.status_code}: {resp.text[:120]}")
        return None
    try:
        return resp.json()
    except (AttributeError, TypeError, ValueError):
        return None


async def seed_traces(
    client: httpx.AsyncClient,
    headers: dict[str, str],
) -> list[str]:
    """Create 36 demo traces with staggered timestamps."""
    now = datetime.now(timezone.utc)
    trace_ids: list[str] = []
    print("  Creating traces...")
    for _ in range(36):
        hours_ago = random.uniform(0.5, 23.5)
        started = now - timedelta(hours=hours_ago)
        status = random.choices(
            STATUSES,
            weights=STATUS_WEIGHTS,
        )[0]
        profile = random.choice(AGENT_PROFILES)
        tool = random.choice(profile["tools"])
        duration = random.uniform(12, 4500)
        tid = f"trace-demo-{uuid.uuid4().hex[:12]}"
        trace_ids.append(tid)

        payload: dict[str, Any] = {
            "trace_id": tid,
            "agent_id": profile["agent_id"],
            "tool": tool,
            "inputs": {
                "prompt": random.choice(profile["prompts"]),
                "resource": random.choice(profile["resources"]),
            },
            "status": status,
            "duration_ms": round(duration, 1),
            "cost": round(random.uniform(0.001, 0.12), 4),
            "started_at": started.isoformat(),
        }
        if status == "failed":
            payload["error"] = "Simulated failure for demo"
        if status == "blocked":
            payload["blocked_by"] = "policy_engine"

        await post(client, "/api/traces", payload, headers)

    print(f"    Created {len(trace_ids)} traces")
    return trace_ids


async def seed_approvals(
    client: httpx.AsyncClient,
    headers: dict[str, str],
    trace_ids: list[str],
) -> None:
    """Create 5 pending approval requests."""
    print("  Creating pending approvals...")
    for i, scenario in enumerate(APPROVAL_SCENARIOS):
        aid = f"approval-demo-{uuid.uuid4().hex[:10]}"
        await post(
            client,
            "/api/approvals",
            {
                "approval_id": aid,
                "tool": scenario["tool"],
                "inputs": scenario["inputs"],
                "trace_id": (trace_ids[i] if i < len(trace_ids) else None),
                "agent_id": scenario["agent_id"],
            },
            headers,
        )
    print("    Created 5 pending approvals")


async def seed_policies(
    client: httpx.AsyncClient,
    headers: dict[str, str],
) -> None:
    """Create, load, lock, and activate demo policies."""
    print("  Creating policies...")
    for doc in POLICY_DOCS:
        result = await post(
            client,
            "/api/policies",
            {"policy_json": doc},
            headers,
        )
        if result:
            pid = doc["policy_set_id"]
            print(f"    Created policy: {pid}")

    for pid in LOAD_POLICIES:
        resp = await client.post(
            f"{API_BASE}/api/policies/load/{pid}",
            headers=headers,
        )
        if resp.status_code < 300:
            print(f"    Loaded: {pid}")

    for pid in LOCK_POLICIES:
        resp = await client.patch(
            f"{API_BASE}/api/policies/{pid}",
            json={"locked": True},
            headers=headers,
        )
        if resp.status_code < 300:
            print(f"    Locked: {pid}")

    list_resp = await client.get(
        f"{API_BASE}/api/policies",
        headers=headers,
    )
    if list_resp.status_code == 200:
        pol_data = list_resp.json()
        db_policies = pol_data.get("db_policies", [])
        for pol in db_policies:
            pid = pol.get("policy_set_id")
            if pid in ACTIVATE_POLICIES:
                db_id = pol.get("db_id")
                if db_id:
                    await client.post(
                        (f"{API_BASE}/api/policies/{db_id}/activate"),
                        headers=headers,
                    )
                    print(f"    DB-activated: {pid} (id={db_id})")


async def seed_certificates(
    client: httpx.AsyncClient,
    headers: dict[str, str],
) -> None:
    """Create verification certificates via admissibility evaluation.

    Both admissible (200) and inadmissible (403) responses
    produce persisted certificates on the server.
    """
    print("  Creating certificates...")
    admitted = 0
    denied = 0
    for scenario in CERT_SCENARIOS:
        resp = await client.post(
            f"{API_BASE}/api/security/admissibility/evaluate",
            json=scenario,
            headers=headers,
        )
        if resp.status_code == 200:
            admitted += 1
        elif resp.status_code == 403:
            denied += 1
        else:
            print(f"    WARN cert -> {resp.status_code}: {resp.text[:120]}")
    print(f"    Created {admitted + denied} certificates ({admitted} admitted, {denied} denied)")


async def main() -> None:
    """Seed demo data into the running backend."""
    print("Seeding dashboard demo data...")
    print(f"  API: {API_BASE}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{API_BASE}/api/auth/login",
            json={
                "email": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD,
            },
        )
        if resp.status_code != 200:
            print(f"Login failed: {resp.status_code} {resp.text[:200]}")
            return
        token = resp.json()["access_token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        print("  Authenticated")

        trace_ids = await seed_traces(client, headers)
        await seed_approvals(client, headers, trace_ids)
        await seed_policies(client, headers)
        await seed_certificates(client, headers)

        print("\nDone. Refresh the dashboard to see the demo data.")


if __name__ == "__main__":
    asyncio.run(main())
