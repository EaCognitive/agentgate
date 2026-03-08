"""End-to-end SDK journey tests for formal runtime kernel and scoped PII middleware."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from ea_agentgate.agent import Agent
from ea_agentgate.api_client import ApiError, DashboardClient
from ea_agentgate.middleware.pii_vault import PIIVault
from server.main import app

pytestmark = pytest.mark.e2e


class _InProcessDashboardClient(DashboardClient):
    """DashboardClient transport adapter that targets an in-process FastAPI app."""

    def __init__(self, *, test_client: TestClient, token: str):
        super().__init__(base_url="http://testserver")
        self._test_client = test_client
        self.token = token
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        request_headers = {"Content-Type": "application/json"}
        if self.token:
            request_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            request_headers.update(headers)

        response = self._test_client.request(
            method,
            path,
            json=body,
            params=params,
            headers=request_headers,
        )
        self.calls.append(
            {
                "method": method,
                "path": path,
                "body": body or {},
                "params": params or {},
                "headers": headers or {},
                "status_code": response.status_code,
            }
        )

        if response.status_code >= 400:
            detail: Any = None
            message = response.text
            try:
                detail = response.json()
                if isinstance(detail, dict):
                    message = str(detail.get("detail", detail.get("message", response.text)))
            except ValueError:
                detail = None
            raise ApiError(response.status_code, message, detail)

        if not response.content:
            return {}
        return response.json()


def _register_and_login_user(
    test_client: TestClient,
    *,
    email: str,
    password: str,
    name: str,
) -> dict[str, Any]:
    """Register and login a user, then return token, identity, and auth headers."""
    register_response = test_client.post(
        "/api/auth/register",
        json={"email": email, "password": password, "name": name},
    )
    assert register_response.status_code == 200, register_response.text

    login_response = test_client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_response.status_code == 200, login_response.text
    access_token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    profile_response = test_client.get("/api/auth/me", headers=headers)
    assert profile_response.status_code == 200, profile_response.text
    profile = profile_response.json()

    return {
        "id": profile["id"],
        "email": profile["email"],
        "token": access_token,
        "headers": headers,
    }


@pytest.mark.asyncio
async def test_sdk_formal_path_uses_runtime_z3_kernel(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SDK formal helper must reach runtime solver metadata in enforce mode."""
    _ = e2e_client
    monkeypatch.setenv("AGENTGATE_Z3_MODE", "enforce")

    with TestClient(app) as test_client:
        sdk_client = _InProcessDashboardClient(
            test_client=test_client,
            token=registered_admin["access_token"],
        )
        evaluation = sdk_client.formal_evaluate_admissibility(
            principal="agent:sdk-e2e",
            action="config:read",
            resource="tenant/default/config",
            runtime_context={
                "authenticated": True,
                "direct_access": True,
                "direct_permit": True,
                "execution_phase": "confirm",
                "preview_confirmed": True,
            },
            chain_id="e2e-sdk-z3",
        )

        assert evaluation["success"] is True
        certificate = evaluation["certificate"]
        runtime_solver = certificate["proof_payload"]["runtime_solver"]
        assert runtime_solver["solver_mode"] == "enforce"
        assert runtime_solver["solver_backend"] == "z3"
        assert runtime_solver["z3_check_result"] == "consistent"

        verification = sdk_client.formal_verify_certificate(certificate["decision_id"])
        assert verification["valid"] is True

        evidence = sdk_client.formal_verify_evidence_chain("e2e-sdk-z3")
        assert evidence["valid"] is True
        assert evidence["checked_entries"] >= 1

        runtime_status = sdk_client.formal_runtime_status()
        assert runtime_status["configured_mode"] == "enforce"
        assert runtime_status["z3_available"] is True


@pytest.mark.asyncio
async def test_agent_formal_middleware_remote_provider_uses_runtime_kernel(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent formal middleware should use canonical remote kernel path in enforce mode."""
    _ = e2e_client
    monkeypatch.setenv("AGENTGATE_Z3_MODE", "enforce")
    monkeypatch.setenv("AGENTGATE_FORCE_REMOTE_VERIFICATION", "true")

    with TestClient(app) as test_client:
        sdk_client = _InProcessDashboardClient(
            test_client=test_client,
            token=registered_admin["access_token"],
        )
        agent = Agent(
            formal_verification=True,
            principal="agent:proof-middleware-e2e",
            verification_mode="enforce",
            verification_provider="remote",
            formal_api_client=sdk_client,
            agent_id="agent-proof-middleware-e2e",
            session_id="session-proof-middleware-e2e",
            user_id=registered_admin["email"],
        )

        @agent.tool
        def echo(text: str) -> str:
            return f"echo:{text}"

        result = agent.call("echo", text="z3 runtime check")
        assert result == "echo:z3 runtime check"

        called_paths = [call["path"] for call in sdk_client.calls]
        assert "/api/security/admissibility/evaluate" in called_paths

        certificate = agent.last_certificate
        assert isinstance(certificate, dict)
        runtime_solver = certificate["proof_payload"]["runtime_solver"]
        assert runtime_solver["solver_mode"] == "enforce"
        assert runtime_solver["solver_backend"] == "z3"
        assert runtime_solver["z3_check_result"] == "consistent"


@pytest.mark.asyncio
async def test_pii_middleware_round_trip_restores_authorized_output(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict[str, Any],
) -> None:
    """PII middleware should redact inbound text and restore outbound text via server API."""
    _ = e2e_client

    with TestClient(app) as test_client:
        sdk_client = _InProcessDashboardClient(
            test_client=test_client,
            token=registered_admin["access_token"],
        )
        session_id = f"pii-e2e-{uuid.uuid4().hex[:10]}"
        sdk_client.post(
            "/api/pii/sessions",
            body={
                "session_id": session_id,
                "user_id": registered_admin["email"],
                "agent_id": "agent-pii-e2e",
                "purpose": "e2e middleware validation",
            },
        )

        pii_vault = PIIVault(
            use_server_api=True,
            api_client=sdk_client,
            pii_session_id=session_id,
            fail_closed=True,
        )
        agent = Agent(
            middleware=[pii_vault],
            agent_id="agent-pii-e2e",
            session_id=session_id,
            user_id=registered_admin["email"],
        )

        @agent.tool
        def echo(text: str) -> str:
            return f"echo:{text}"

        result = agent.call("echo", text="ssn 123-45-6789")
        assert result == "echo:ssn 123-45-6789"

        called_paths = [call["path"] for call in sdk_client.calls]
        assert "/api/pii/redact" in called_paths
        assert "/api/pii/restore" in called_paths


@pytest.mark.asyncio
async def test_pii_restore_permission_denial_fails_closed(
    e2e_client: httpx.AsyncClient,
    registered_admin: dict[str, Any],
) -> None:
    """Server-scoped restore must fail closed when caller lacks PII_RETRIEVE permission."""
    _ = e2e_client

    with TestClient(app) as test_client:
        admin_sdk_client = _InProcessDashboardClient(
            test_client=test_client,
            token=registered_admin["access_token"],
        )

        viewer_email = f"viewer-{uuid.uuid4().hex[:8]}@agentgate.test"
        viewer_user = _register_and_login_user(
            test_client,
            email=viewer_email,
            password="ViewerE2E!Secure99",
            name="PII Viewer",
        )

        admin_sdk_client.post(
            "/api/pii/permissions",
            body={
                "user_id": viewer_user["id"],
                "permission": "pii:store",
                "reason": "e2e scoped redact permission",
            },
        )

        viewer_sdk_client = _InProcessDashboardClient(
            test_client=test_client,
            token=viewer_user["token"],
        )
        session_id = f"pii-viewer-{uuid.uuid4().hex[:10]}"
        viewer_sdk_client.post(
            "/api/pii/sessions",
            body={
                "session_id": session_id,
                "user_id": viewer_user["email"],
                "agent_id": "agent-viewer-e2e",
                "purpose": "e2e deny restore path",
            },
        )

        pii_vault = PIIVault(
            use_server_api=True,
            api_client=viewer_sdk_client,
            pii_session_id=session_id,
            fail_closed=True,
        )
        agent = Agent(
            middleware=[pii_vault],
            agent_id="agent-viewer-e2e",
            session_id=session_id,
            user_id=viewer_user["email"],
        )

        @agent.tool
        def echo(text: str) -> str:
            return text

        with pytest.raises(RuntimeError, match="status=403"):
            agent.call("echo", text="ssn 987-65-4321")

        called_paths = [call["path"] for call in viewer_sdk_client.calls]
        assert "/api/pii/redact" in called_paths
        assert "/api/pii/restore" in called_paths
