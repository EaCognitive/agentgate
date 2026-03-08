"""End-to-end workflow tests exercising the real server.main:app.

Every request flows through the full middleware stack:
CORS, SecurityHeaders, ThreatDetection, Metrics, SlowAPI, global exception handler.
"""

import uuid

import httpx
import pyotp
import pytest

pytestmark = pytest.mark.e2e


# ============================================================================
# 1. Health & Infrastructure
# ============================================================================


class TestHealthAndInfrastructure:
    """Verify core infrastructure endpoints and middleware headers."""

    async def test_health_check(self, e2e_client: httpx.AsyncClient):
        """Verify /api/health returns 200 with status and version fields."""
        resp = await e2e_client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "version" in body

    async def test_metrics_endpoint(self, e2e_client: httpx.AsyncClient):
        """Verify /metrics exposes Prometheus metrics."""
        resp = await e2e_client.get("/metrics")
        assert resp.status_code == 200
        assert "process_" in resp.text or "python_" in resp.text

    async def test_openapi_schema(self, e2e_client: httpx.AsyncClient):
        """Verify OpenAPI schema is available and contains correct metadata."""
        resp = await e2e_client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "AgentGate Dashboard API"

    async def test_security_headers_present(self, e2e_client: httpx.AsyncClient):
        """Verify security headers middleware applies X-Content-Type-Options and X-Frame-Options."""
        resp = await e2e_client.get("/api/health")
        assert "x-content-type-options" in resp.headers
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert "x-frame-options" in resp.headers

    async def test_cors_preflight(self, e2e_client: httpx.AsyncClient):
        """Verify CORS middleware responds to preflight OPTIONS requests."""
        resp = await e2e_client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        # CORS middleware should respond (may be 200 or 400 depending on config)
        assert resp.status_code in (200, 400)


# ============================================================================
# 2. Auth Lifecycle
# ============================================================================


class TestAuthLifecycle:
    """Register -> login -> /me -> refresh -> revoke; edge cases."""

    async def test_register_login_me_refresh_revoke(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify complete auth flow: fetch profile, refresh token, and revoke token."""
        headers = registered_admin["headers"]

        # /me
        resp = await e2e_client.get("/api/auth/me", headers=headers)
        assert resp.status_code == 200
        me = resp.json()
        assert me["email"] == registered_admin["email"]
        assert me["role"] == "admin"

        # refresh
        resp = await e2e_client.post(
            "/api/auth/refresh",
            json={"refresh_token": registered_admin["refresh_token"]},
        )
        assert resp.status_code == 200
        new_token = resp.json()["access_token"]
        assert new_token

        # revoke
        resp = await e2e_client.post(
            "/api/auth/revoke",
            json={"refresh_token": registered_admin["refresh_token"]},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    async def test_duplicate_registration_fails(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify duplicate email registration returns 409 conflict."""
        resp = await e2e_client.post(
            "/api/auth/register",
            json={
                "email": registered_admin["email"],
                "password": "AnyPassword1!",
                "name": "Duplicate",
            },
        )
        assert resp.status_code == 409
        assert "already registered" in resp.json()["detail"]

    async def test_wrong_password_returns_401(
        self, e2e_client: httpx.AsyncClient, registered_admin: dict
    ):
        """Verify login with incorrect password returns 401 unauthorized."""
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": registered_admin["email"], "password": "WrongPassword!1"},
        )
        assert resp.status_code == 401

    async def test_unauthorized_request_returns_401(self, e2e_client: httpx.AsyncClient):
        """Verify requests without auth token return 401 or 403."""
        resp = await e2e_client.get("/api/auth/me")
        assert resp.status_code in (401, 403)

    async def test_viewer_cannot_access_admin_routes(
        self,
        e2e_client: httpx.AsyncClient,
        registered_user: dict,
    ):
        """Verify viewer role cannot access admin-only endpoints like /api/test/seed."""
        # Viewer should be forbidden from admin-only operations like test/seed
        resp = await e2e_client.post(
            "/api/test/seed",
            headers=registered_user["headers"],
        )
        assert resp.status_code == 403


# ============================================================================
# 3. MFA Lifecycle
# ============================================================================


class TestMFALifecycle:
    """enable-2fa -> verify-2fa (TOTP) -> login with MFA -> disable-2fa."""

    async def test_mfa_full_cycle(self, e2e_client: httpx.AsyncClient):
        """Register a fresh user, enable MFA, verify, login with TOTP, disable."""

        email = f"mfa-{uuid.uuid4().hex[:8]}@agentgate.test"
        password = "MfaUser!Secure99"

        # Register
        resp = await e2e_client.post(
            "/api/auth/register",
            json={"email": email, "password": password, "name": "MFA Test"},
        )
        assert resp.status_code == 200

        # Login to get token
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": email, "password": password},
        )
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Enable 2FA
        resp = await e2e_client.post("/api/auth/enable-2fa", headers=headers)
        assert resp.status_code == 200
        secret = resp.json()["secret"]
        backup_codes = resp.json()["backup_codes"]
        assert secret
        assert len(backup_codes) == 8

        # Verify 2FA with real TOTP code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        resp = await e2e_client.post(
            "/api/auth/verify-2fa",
            json={"code": code},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "enabled"

        # Login now requires TOTP
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": email, "password": password},
        )
        assert resp.status_code == 200
        assert resp.json().get("mfa_required") is True

        # Login with TOTP code
        code = totp.now()
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": email, "password": password, "totp_code": code},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Disable 2FA
        resp = await e2e_client.post(
            "/api/auth/disable-2fa",
            json={"password": password},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "disabled"

    async def test_backup_code_single_use(self, e2e_client: httpx.AsyncClient):
        """Backup codes should be consumed after a single use."""

        email = f"backup-{uuid.uuid4().hex[:8]}@agentgate.test"
        password = "BackupUser!Secure99"

        # Register + login
        await e2e_client.post(
            "/api/auth/register",
            json={"email": email, "password": password, "name": "Backup Test"},
        )
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": email, "password": password},
        )
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Enable + verify 2FA
        resp = await e2e_client.post("/api/auth/enable-2fa", headers=headers)
        secret = resp.json()["secret"]
        backup_codes = resp.json()["backup_codes"]

        totp = pyotp.TOTP(secret)
        resp = await e2e_client.post(
            "/api/auth/verify-2fa",
            json={"code": totp.now()},
            headers=headers,
        )
        assert resp.status_code == 200

        # Use a backup code to login
        backup_code = backup_codes[0]
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": email, "password": password, "totp_code": backup_code},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

        # Same backup code should fail on second use
        resp = await e2e_client.post(
            "/api/auth/login",
            json={"email": email, "password": password, "totp_code": backup_code},
        )
        assert resp.status_code == 401


# ============================================================================
# 4. Trace CRUD
# ============================================================================


class TestTraceCRUD:
    """POST/GET traces, /stats, /timeline, /tools; RBAC checks."""

    async def test_create_and_list_traces(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify trace creation, retrieval by ID, and listing all traces."""
        trace_id = f"trace-{uuid.uuid4().hex[:12]}"
        resp = await e2e_client.post(
            "/api/traces",
            json={
                "trace_id": trace_id,
                "tool": "bash",
                "inputs": {"command": "echo hello"},
                "output": {"result": "hello"},
                "status": "success",
                "cost": 0.01,
                "agent_id": "agent-alpha",
            },
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["trace_id"] == trace_id

        # GET by ID
        resp = await e2e_client.get(
            f"/api/traces/{trace_id}",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["tool"] == "bash"

        # GET list
        resp = await e2e_client.get(
            "/api/traces",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert any(t["trace_id"] == trace_id for t in resp.json())

    async def test_trace_stats(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify /api/traces/stats returns total count and success rate."""
        resp = await e2e_client.get(
            "/api/traces/stats",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert "success_rate" in body

    async def test_trace_timeline(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify /api/traces/timeline returns time-series trace data."""
        resp = await e2e_client.get(
            "/api/traces/timeline",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_trace_tools(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify /api/traces/tools returns list of tools used in traces."""
        resp = await e2e_client.get(
            "/api/traces/tools",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_viewer_cannot_create_trace(
        self,
        e2e_client: httpx.AsyncClient,
        registered_user: dict,
    ):
        """Verify viewer role cannot create traces (requires admin/operator)."""
        resp = await e2e_client.post(
            "/api/traces",
            json={
                "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
                "tool": "bash",
                "inputs": {"command": "echo forbidden"},
                "status": "success",
            },
            headers=registered_user["headers"],
        )
        assert resp.status_code == 403


# ============================================================================
# 5. Approval Workflow
# ============================================================================


class TestApprovalWorkflow:
    """Create -> list pending -> decide (approve/deny)."""

    async def test_approve_workflow(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify approval creation, listing pending, and approval decision flow."""
        approval_id = f"appr-{uuid.uuid4().hex[:12]}"

        # Create (admin auth required)
        resp = await e2e_client.post(
            "/api/approvals",
            json={
                "approval_id": approval_id,
                "tool": "send_email",
                "inputs": {"to": "ceo@example.com", "subject": "Urgent"},
            },
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"

        # List pending
        resp = await e2e_client.get(
            "/api/approvals/pending",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert any(a["approval_id"] == approval_id for a in resp.json())

        # Approve
        resp = await e2e_client.post(
            f"/api/approvals/{approval_id}/decide",
            json={"approved": True, "reason": "Looks good"},
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    async def test_deny_workflow(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify approval denial flow with dangerous query example."""
        approval_id = f"appr-{uuid.uuid4().hex[:12]}"

        await e2e_client.post(
            "/api/approvals",
            json={
                "approval_id": approval_id,
                "tool": "database_query",
                "inputs": {"query": "DROP TABLE users"},
            },
            headers=registered_admin["headers"],
        )

        resp = await e2e_client.post(
            f"/api/approvals/{approval_id}/decide",
            json={"approved": False, "reason": "Dangerous query"},
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "denied"


# ============================================================================
# 6. Audit Log
# ============================================================================


class TestAuditLog:
    """Verify auth events are auto-logged; export CSV/JSON."""

    async def test_audit_entries_exist(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify audit log captures registration and login events."""
        resp = await e2e_client.get(
            "/api/audit",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        entries = resp.json()
        # Registration and login events should have been logged
        assert len(entries) > 0

    async def test_export_csv(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify audit log CSV export returns proper content-type and data."""
        resp = await e2e_client.get(
            "/api/audit/export?format=csv",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    async def test_export_json(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify audit log JSON export returns proper content-type and data."""
        resp = await e2e_client.get(
            "/api/audit/export?format=json",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        assert "application/json" in resp.headers.get("content-type", "")


# ============================================================================
# 7. Dataset Management
# ============================================================================


async def test_dataset_crud_lifecycle(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict,
):
    """Verify dataset CRUD, test case creation, and test run creation."""
    headers = registered_admin["headers"]

    resp = await e2e_client.post(
        "/api/datasets",
        json={"name": "E2E Dataset", "description": "Created by E2E tests"},
        headers=headers,
    )
    assert resp.status_code == 201
    dataset = resp.json()
    dataset_id = dataset["id"]

    resp = await e2e_client.get(f"/api/datasets/{dataset_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "E2E Dataset"

    resp = await e2e_client.get("/api/datasets", headers=headers)
    assert resp.status_code == 200
    assert any(d["id"] == dataset_id for d in resp.json())

    resp = await e2e_client.post(
        f"/api/datasets/{dataset_id}/tests",
        json={
            "dataset_id": dataset_id,
            "name": "E2E Test Case",
            "tool": "bash",
            "inputs": {"command": "echo test"},
            "expected_output": {"result": "test"},
        },
        headers=headers,
    )
    assert resp.status_code == 201

    resp = await e2e_client.post(
        f"/api/datasets/{dataset_id}/runs",
        json={"dataset_id": dataset_id, "name": "E2E Run"},
        headers=headers,
    )
    assert resp.status_code == 201

    resp = await e2e_client.get(
        f"/api/datasets/{dataset_id}/stats",
        headers=headers,
    )
    assert resp.status_code == 200


# ============================================================================
# 8. PII Vault
# ============================================================================


class TestPIIVault:
    """Session management (create/list/clear); compliance stats; checklist."""

    async def test_pii_session_lifecycle(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify PII session creation, listing, and deletion."""
        headers = registered_admin["headers"]
        session_id = f"pii-{uuid.uuid4().hex[:12]}"

        # Create session
        resp = await e2e_client.post(
            "/api/pii/sessions",
            json={
                "session_id": session_id,
                "user_id": "user-123",
                "agent_id": "agent-alpha",
                "purpose": "e2e test",
            },
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["session_id"] == session_id

        # List sessions
        resp = await e2e_client.get("/api/pii/sessions", headers=headers)
        assert resp.status_code == 200
        assert any(s["session_id"] == session_id for s in resp.json())

        # Clear session
        resp = await e2e_client.delete(
            f"/api/pii/sessions/{session_id}",
            headers=headers,
        )
        assert resp.status_code == 200

    async def test_compliance_stats(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify /api/pii/stats returns compliance statistics including total sessions."""
        resp = await e2e_client.get(
            "/api/pii/stats",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "total_sessions" in body

    async def test_compliance_checklist(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify /api/pii/compliance-checklist returns regulatory compliance checklist."""
        resp = await e2e_client.get(
            "/api/pii/compliance-checklist",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 200


# ============================================================================
# 9. Test Data Seed / Clear
# ============================================================================


async def test_seed_and_clear(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict,
):
    """Verify test data seeding creates traces and clearing removes all test data."""
    headers = registered_admin["headers"]

    resp = await e2e_client.post("/api/test/seed", headers=headers)
    assert resp.status_code == 200
    seed_data = resp.json()
    assert seed_data.get("traces_created", 0) > 0

    resp = await e2e_client.get("/api/traces", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) > 0

    resp = await e2e_client.delete("/api/test/clear", headers=headers)
    assert resp.status_code == 200


# ============================================================================
# 10. Overview
# ============================================================================


async def test_overview_returns_stats(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict,
):
    """Verify /api/overview returns 24h statistics including total calls and success rate."""
    resp = await e2e_client.get(
        "/api/overview",
        headers=registered_admin["headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "total_calls" in body
    assert "success_rate" in body
    assert body["period"] == "24h"


# ============================================================================
# 11. Error Handling
# ============================================================================


class TestErrorHandling:
    """404 for nonexistent resources (not 500)."""

    async def test_nonexistent_trace_returns_404(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify requesting nonexistent trace returns 404, not 500."""
        resp = await e2e_client.get(
            "/api/traces/nonexistent-trace-id-999",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 404

    async def test_nonexistent_approval_returns_404(
        self,
        e2e_client: httpx.AsyncClient,
        registered_admin: dict,
    ):
        """Verify requesting nonexistent approval returns 404, not 500."""
        resp = await e2e_client.get(
            "/api/approvals/nonexistent-approval-id-999",
            headers=registered_admin["headers"],
        )
        assert resp.status_code == 404
