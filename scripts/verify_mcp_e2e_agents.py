"""AgentGate MCP E2E -- domain verification agents."""

from __future__ import annotations

import uuid
from importlib import import_module

import httpx

from scripts.verify_mcp_e2e_base import (
    BLOCK_IP,
    DENIED,
    HANDLED_ERRORS,
    RES_COUNT,
    TEST_EMAIL,
    TEST_NAME,
    TEST_PASSWORD,
    TOOL_COUNT,
    Agent,
)


def _create_mcp_server():
    """Return the MCP server factory."""
    return getattr(import_module("server.mcp.server"), "create_server")


def _preview_token_helpers():
    """Return preview-token helper functions."""
    confirm_module = import_module("server.mcp.confirm")
    return confirm_module.generate_preview_token, confirm_module.verify_preview_token


def _policy_engine_class():
    """Return the MCP policy engine class."""
    policy_engine_module = import_module("server.mcp.policy_engine")
    return getattr(policy_engine_module, "PolicyEngine")


# Phase 0
class HealthAgent(Agent):
    """Verify /api/health."""

    phase, domain = 0, "Health"

    async def _execute(self) -> None:
        """Check health endpoint."""
        try:
            resp = await self._c.get("/api/health")
        except HANDLED_ERRORS as exc:
            self._fl("health", f"connection: {exc}")
            return
        if resp.status_code != 200:
            self._fl("health", f"HTTP {resp.status_code}")
            return
        if resp.json().get("status") != "healthy":
            self._fl("health", "not healthy")
            return
        self._ok("health")


# Phase 1
class AuthAgent(Agent):
    """Verify auth endpoints."""

    phase, domain = 1, "Authentication"

    async def _execute(self) -> None:
        """Run authentication checks."""
        await self._register()
        if not await self._login():
            return
        await self._verify_me()
        await self._verify_check_mfa()
        await self._cg(
            "sessions",
            "/api/auth/sessions",
            lst=True,
        )

    async def _register(self) -> None:
        """Register the test user if missing."""
        try:
            resp = await self._c.post(
                "/api/auth/register",
                json={
                    "email": TEST_EMAIL,
                    "password": TEST_PASSWORD,
                    "name": TEST_NAME,
                },
            )
            if resp.status_code in (200, 201):
                self._ok("register")
            elif resp.status_code == 409:
                self._ok("register", "already registered")
            else:
                self._fl(
                    "register",
                    f"HTTP {resp.status_code}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("register", str(exc))

    async def _login(self) -> bool:
        """Authenticate test user and cache token context."""
        try:
            resp = await self._c.post(
                "/api/auth/login",
                json={
                    "email": TEST_EMAIL,
                    "password": TEST_PASSWORD,
                },
            )
            if resp.status_code != 200:
                self._fl(
                    "login",
                    f"HTTP {resp.status_code}",
                )
                return False
            body = resp.json()
            token = body.get("access_token", "")
            if not token:
                self._fl("login", "no access_token")
                return False
            self._ctx["access_token"] = token
            usr = body.get("user", {})
            self._ctx["user_id"] = usr.get("id")
            self._ctx["user_role"] = usr.get(
                "role",
                "viewer",
            )
            self._ok("login")
        except HANDLED_ERRORS as exc:
            self._fl("login", str(exc))
            return False
        return True

    async def _verify_me(self) -> None:
        """Validate /api/auth/me once token is available."""
        if self._ctx.get("access_token"):
            try:
                resp = await self._get("/api/auth/me")
                if resp.status_code == 200 and "email" in resp.json():
                    self._ok("me")
                else:
                    self._fl(
                        "me",
                        f"HTTP {resp.status_code}",
                    )
            except HANDLED_ERRORS as exc:
                self._fl("me", str(exc))
        else:
            self._sk("me", "no token")

    async def _verify_check_mfa(self) -> None:
        """Validate MFA status endpoint."""
        try:
            resp = await self._c.post(
                "/api/auth/check-mfa",
                json={"email": TEST_EMAIL},
            )
            if resp.status_code == 200 and "mfa_enabled" in resp.json():
                self._ok("check-mfa")
            else:
                self._fl(
                    "check-mfa",
                    f"HTTP {resp.status_code}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("check-mfa", str(exc))


# Phase 2
class UserAgent(Agent):
    """Verify user management."""

    phase, domain = 2, "User Management"

    async def _execute(self) -> None:
        """Run user management checks."""
        await self._cg(
            "list users",
            "/api/users",
            lst=True,
        )
        if self._ctx.get("user_role") != "admin":
            self._sk("create user", "not admin")
            self._sk("update user", "not admin")
            return
        em = "e2e_managed_user@agentgate.dev"
        try:
            resp = await self._post(
                "/api/users",
                body={
                    "email": em,
                    "password": TEST_PASSWORD,
                    "name": "E2E",
                    "role": "viewer",
                },
            )
            if resp.status_code in (200, 201):
                self._ok("create user")
                self._ctx["mgd_uid"] = resp.json().get(
                    "id",
                )
            elif resp.status_code == 409:
                self._ok("create user", "exists")
            else:
                self._fl(
                    "create user",
                    f"HTTP {resp.status_code}",
                )
                return
        except HANDLED_ERRORS as exc:
            self._fl("create user", str(exc))
            return
        uid = self._ctx.get("mgd_uid")
        if not uid:
            self._sk("update user", "no id")
            return
        try:
            resp = await self._pat(
                f"/api/users/{uid}",
                body={"name": "E2E Updated"},
            )
            if resp.status_code == 200:
                self._ok("update user")
            elif resp.status_code in DENIED:
                self._sk("update user", "permissions")
            else:
                self._fl(
                    "update user",
                    f"HTTP {resp.status_code}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("update user", str(exc))


# Phase 3
class ThreatAgent(Agent):
    """Verify security threats."""

    phase, domain = 3, "Security Threats"

    async def _sp(
        self,
        n: str,
        p: str,
        body: dict | None = None,
    ) -> httpx.Response | None:
        """Safe post with permission handling."""
        try:
            resp = await self._post(p, body=body)
        except HANDLED_ERRORS as exc:
            self._fl(n, str(exc))
            return None
        if resp.status_code in DENIED:
            self._sk(n, "permissions")
            return None
        return resp

    async def _execute(self) -> None:
        """Run security threat checks."""
        await self._cg(
            "list",
            "/api/security/threats",
            params={"limit": "5"},
            lst=True,
        )
        await self._cg(
            "stats",
            "/api/security/threats/stats",
            key="total_threats",
        )
        await self._cg(
            "timeline",
            "/api/security/threats/timeline",
            lst=True,
        )
        await self._cg(
            "blocked-ips",
            "/api/security/threats/blocked-ips",
            lst=True,
        )
        await self._cg(
            "detector-stats",
            "/api/security/threats/detector-stats",
            key="total_checks",
        )
        # Create -> ack -> resolve
        resp = await self._sp(
            "create threat",
            "/api/security/threats",
            body={
                "event_type": "mcp_e2e_test",
                "severity": "low",
                "description": "E2E test",
            },
        )
        if not resp:
            return
        if resp.status_code not in (200, 201):
            self._fl(
                "create threat",
                f"HTTP {resp.status_code}",
            )
            return
        tid = resp.json().get("id")
        self._ok("create threat")
        if tid:
            for act, lbl in [
                ("ack", "ack"),
                ("resolve", "resolve"),
            ]:
                r2 = await self._sp(
                    f"{lbl} threat",
                    f"/api/security/threats/{tid}/{act}",
                )
                if r2 and r2.status_code == 200:
                    self._ok(f"{lbl} threat")
                elif r2:
                    self._fl(
                        f"{lbl} threat",
                        f"HTTP {r2.status_code}",
                    )
        else:
            self._sk("ack threat", "no id")
            self._sk("resolve threat", "no id")
        # Block / unblock
        resp = await self._sp(
            "block IP",
            "/api/security/threats/block-ip",
            body={
                "ip": BLOCK_IP,
                "reason": "e2e",
                "duration_seconds": 60,
            },
        )
        if not resp:
            self._sk("unblock IP", "skipped")
            return
        if resp.status_code != 200:
            self._fl(
                "block IP",
                f"HTTP {resp.status_code}",
            )
            return
        self._ok("block IP")
        try:
            resp = await self._del(
                f"/api/security/threats/block-ip/{BLOCK_IP}",
            )
            if resp.status_code == 200:
                self._ok("unblock IP")
            else:
                self._fl(
                    "unblock IP",
                    f"HTTP {resp.status_code}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("unblock IP", str(exc))


# Phase 4
class PIIAgent(Agent):
    """Verify PII detect/redact."""

    phase, domain = 4, "PII Detection"

    async def _execute(self) -> None:
        """Run PII detection checks."""
        pii_session_id = f"verify-pii-{uuid.uuid4().hex[:10]}"
        try:
            create_resp = await self._post(
                "/api/pii/sessions",
                body={
                    "session_id": pii_session_id,
                    "user_id": TEST_EMAIL,
                    "agent_id": "verify-mcp-e2e",
                    "purpose": "PII verification flow",
                },
            )
            if create_resp.status_code != 200:
                self._fl(
                    "create pii session",
                    f"HTTP {create_resp.status_code}",
                )
                return
            self._ok("create pii session")
        except HANDLED_ERRORS as exc:
            self._fl("create pii session", str(exc))
            return

        t1 = "My name is John Smith and my SSN is 123-45-6789"
        try:
            r = await self._post(
                "/api/pii/detect",
                body={
                    "text": t1,
                    "score_threshold": 0.4,
                },
            )
            if r.status_code != 200:
                self._fl(
                    "detect",
                    f"HTTP {r.status_code}",
                )
            elif not r.json().get("detections"):
                self._fl("detect", "no detections")
            else:
                self._ok(
                    "detect",
                    f"{len(r.json()['detections'])} entities",
                )
        except HANDLED_ERRORS as exc:
            self._fl("detect", str(exc))
        t2 = "Call me at 555-123-4567 or email john@example.com"
        try:
            r = await self._post(
                "/api/pii/redact",
                body={
                    "session_id": pii_session_id,
                    "text": t2,
                    "score_threshold": 0.4,
                },
            )
            if r.status_code != 200:
                self._fl(
                    "redact",
                    f"HTTP {r.status_code}",
                )
            elif r.json().get("redacted_text", "") == t2:
                self._fl("redact", "text unchanged")
            else:
                self._ok("redact")
        except HANDLED_ERRORS as exc:
            self._fl("redact", str(exc))


# Phase 5
class AuditAgent(Agent):
    """Verify audit endpoints."""

    phase, domain = 5, "Audit"

    async def _execute(self) -> None:
        """Run audit checks."""
        await self._cg(
            "list",
            "/api/audit",
            params={"limit": "5"},
            lst=True,
        )
        await self._cg(
            "stats",
            "/api/audit/stats",
            key="total_entries",
        )
        await self._cg(
            "event-types",
            "/api/audit/event-types",
            key="event_types",
        )
        await self._cg(
            "actors",
            "/api/audit/actors",
            key="actors",
        )


# Phase 6
class CostAgent(Agent):
    """Verify cost tracking."""

    phase, domain = 6, "Cost Tracking"

    async def _execute(self) -> None:
        """Run cost tracking checks."""
        await self._cg(
            "summary",
            "/api/costs/summary",
            key="period_cost",
        )
        await self._cg(
            "breakdown",
            "/api/costs/breakdown",
            lst=True,
        )
        await self._cg(
            "timeline",
            "/api/costs/timeline",
            lst=True,
        )
        await self._cg(
            "by-agent",
            "/api/costs/by-agent",
            lst=True,
        )


# Phase 7
class TraceAgent(Agent):
    """Verify traces."""

    phase, domain = 7, "Traces"

    async def _execute(self) -> None:
        """Run trace checks."""
        await self._cg(
            "list",
            "/api/traces",
            params={"limit": "5"},
            lst=True,
        )
        await self._cg(
            "stats",
            "/api/traces/stats",
            key="total",
        )
        await self._cg(
            "timeline",
            "/api/traces/timeline",
            lst=True,
        )
        await self._cg(
            "tools",
            "/api/traces/tools",
            lst=True,
        )


# Phase 8
class DatasetAgent(Agent):
    """Verify dataset CRUD."""

    phase, domain = 8, "Datasets"

    async def _execute(self) -> None:
        """Run dataset checks."""
        await self._cg("list", "/api/datasets", lst=True)
        try:
            resp = await self._post(
                "/api/datasets",
                body={
                    "name": "e2e_verify_dataset",
                    "description": "E2E",
                },
            )
        except HANDLED_ERRORS as exc:
            self._fl("create", str(exc))
            return
        if resp.status_code in DENIED:
            self._sk("create", "permissions")
            return
        if resp.status_code not in (200, 201):
            self._fl(
                "create",
                f"HTTP {resp.status_code}",
            )
            return
        ds_id = resp.json().get("id")
        self._ok("create")
        if not ds_id:
            self._sk("list tests", "no id")
            self._sk("delete", "no id")
            return
        await self._cg(
            "list tests",
            f"/api/datasets/{ds_id}/tests",
            lst=True,
        )
        try:
            resp = await self._del(
                f"/api/datasets/{ds_id}",
            )
            if resp.status_code == 200:
                self._ok("delete")
            elif resp.status_code in DENIED:
                self._sk("delete", "permissions")
            else:
                self._fl(
                    "delete",
                    f"HTTP {resp.status_code}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("delete", str(exc))


# Phase 9
class SettingsAgent(Agent):
    """Verify settings."""

    phase, domain = 9, "Settings"

    async def _execute(self) -> None:
        """Run settings checks."""
        await self._cg("list", "/api/settings", lst=True)


# Phase 10
class ApprovalAgent(Agent):
    """Verify approvals."""

    phase, domain = 10, "Approvals"

    async def _execute(self) -> None:
        """Run approval checks."""
        await self._cg(
            "list",
            "/api/approvals",
            params={"limit": "5"},
            lst=True,
        )
        await self._cg(
            "pending",
            "/api/approvals/pending",
            lst=True,
        )
        await self._cg(
            "pending count",
            "/api/approvals/pending/count",
            key="count",
        )


# Phase 11
class PolicyAgent(Agent):
    """Verify policies."""

    phase, domain = 11, "Policies"

    async def _execute(self) -> None:
        """Run policy checks."""
        try:
            resp = await self._get("/api/policies")
        except HANDLED_ERRORS as exc:
            self._fl("list", str(exc))
            return
        if resp.status_code in DENIED:
            self._sk("list", "permissions")
            return
        if resp.status_code != 200:
            self._fl("list", f"HTTP {resp.status_code}")
            return
        body = resp.json()
        if "loaded_policies" not in body and "db_policies" not in body:
            self._fl("list", "missing policy keys")
            return
        self._ok("list")


# Phase 12
class MCPAgent(Agent):
    """Verify MCP internals: server, tools, resources, tokens, policy engine."""

    phase, domain = 12, "MCP Internals"

    async def _execute(self) -> None:
        """Run MCP internal checks."""
        self._server()
        await self._tools()
        await self._resources()
        self._tokens()
        self._policy()

    def _server(self) -> None:
        """Check MCP server creation."""
        try:
            srv = _create_mcp_server()()
            if srv is None:
                self._fl("server creation", "None")
                return
            self._ok("server creation")
        except HANDLED_ERRORS as exc:
            self._fl("server creation", str(exc))

    async def _tools(self) -> None:
        """Check MCP tool count."""
        try:
            tools = await _create_mcp_server()().list_tools()
            n = len(tools)
            if n == TOOL_COUNT:
                self._ok("tool count", str(n))
            else:
                self._fl(
                    "tool count",
                    f"expected {TOOL_COUNT}, got {n}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("tool count", str(exc))

    async def _resources(self) -> None:
        """Check MCP resource count."""
        try:
            resources = await _create_mcp_server()().list_resources()
            n = len(resources)
            if n == RES_COUNT:
                self._ok("resource count", str(n))
            else:
                self._fl(
                    "resource count",
                    f"expected {RES_COUNT}, got {n}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("resource count", str(exc))

    def _tokens(self) -> None:
        """Check token sign/verify."""
        try:
            generate_preview_token, verify_preview_token = _preview_token_helpers()
            act = "e2e_test_action"
            prm = {"ip": "10.0.0.1", "reason": "test"}
            tok = generate_preview_token(act, prm)
            ok, err = verify_preview_token(tok, act, prm)
            if ok:
                self._ok("token sign/verify")
            else:
                self._fl("token sign/verify", err)
        except HANDLED_ERRORS as exc:
            self._fl("token sign/verify", str(exc))

    def _policy(self) -> None:
        """Check policy engine simulation."""
        try:
            policy_engine_class = _policy_engine_class()
            eng = policy_engine_class()
            a1, _ = eng.evaluate_pre_detector(
                "10.0.0.1",
                "/api/test",
            )
            a2, _ = eng.evaluate_post_detector(
                [],
                "low",
                "sql_injection",
            )
            if a1 == "continue" and a2 == "continue":
                self._ok("policy simulate")
            else:
                self._fl(
                    "policy simulate",
                    f"pre={a1} post={a2}",
                )
        except HANDLED_ERRORS as exc:
            self._fl("policy simulate", str(exc))
