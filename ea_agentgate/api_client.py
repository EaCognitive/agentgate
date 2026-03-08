"""HTTP client for the AgentGate server API.

Provides a session-managed client that communicates with the AgentGate
backend, enabling both the CLI and programmatic access to all dashboard
features through a single, shared API layer.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, TypedDict, cast

SESSION_DIR = Path.home() / ".ea-agentgate"
SESSION_FILE = SESSION_DIR / "session.json"
LEGACY_SESSION_FILE = Path.home() / ".agentgate" / "session.json"


class ApiError(Exception):
    """Raised when the AgentGate API returns an error."""

    def __init__(self, status: int, message: str, detail: Any = None):
        self.status = status
        self.message = message
        self.detail = detail
        super().__init__(f"HTTP {status}: {message}")


class RuntimeSolverPayload(TypedDict, total=False):
    """Runtime solver metadata extracted from formal decision proofs."""

    solver_mode: str
    solver_backend: str
    z3_check_result: str
    drift_detected: bool
    failure_reason: str | None


class FormalCertificatePayload(TypedDict, total=False):
    """Serialized decision certificate payload."""

    decision_id: str
    result: str
    proof_type: str
    theorem_hash: str
    alpha_hash: str
    gamma_hash: str
    proof_payload: dict[str, Any]
    signature: str


class FormalEvaluateResponse(TypedDict, total=False):
    """Canonical response payload for formal admissibility checks."""

    success: bool
    certificate: FormalCertificatePayload
    runtime_solver: RuntimeSolverPayload


class FormalVerifyCertificateResponse(TypedDict, total=False):
    """Canonical response payload for certificate verification."""

    success: bool
    valid: bool
    verification_run: dict[str, Any]


class FormalVerifyEvidenceResponse(TypedDict, total=False):
    """Canonical response payload for evidence chain verification."""

    success: bool
    chain_id: str
    valid: bool
    checked_entries: int
    failure_reason: str | None
    failed_hop_index: int | None


class DashboardClient:
    """HTTP client for the AgentGate server API.

    Manages authentication tokens and provides typed convenience
    methods for every HTTP verb. Session tokens are persisted to
    ``~/.ea-agentgate/session.json`` so that subsequent CLI invocations
    do not require re-authentication.

    Args:
        base_url: Server base URL. Falls back to ``$AGENTGATE_URL``
                  or ``http://localhost:8000``.
    """

    def __init__(self, base_url: str | None = None):
        self.base_url = (
            base_url or os.environ.get("AGENTGATE_URL") or "http://localhost:8000"
        ).rstrip("/")
        self._validate_base_url()
        self.token: str | None = None
        self.email: str = ""
        self._load_session()

    # ------------------------------------------------------------------
    # Session persistence
    # ------------------------------------------------------------------

    def _load_session(self) -> None:
        """Load a previously saved session token from disk."""
        for session_file in (SESSION_FILE, LEGACY_SESSION_FILE):
            if not session_file.exists():
                continue
            try:
                data = json.loads(session_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("url") != self.base_url:
                continue
            self.token = data.get("token")
            self.email = data.get("email", "")
            if session_file == LEGACY_SESSION_FILE and not SESSION_FILE.exists():
                self._save_session()
            return

    def _save_session(self) -> None:
        """Persist the current session token to disk."""
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        SESSION_FILE.write_text(
            json.dumps(
                {
                    "url": self.base_url,
                    "token": self.token,
                    "email": self.email,
                }
            )
        )

    def _clear_session(self) -> None:
        """Remove the persisted session."""
        for session_file in (SESSION_FILE, LEGACY_SESSION_FILE):
            if session_file.exists():
                session_file.unlink()
        self.token = None
        self.email = ""

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> dict[str, Any]:
        """Authenticate and store the access token."""
        resp = self.request(
            "POST",
            "/api/auth/login",
            body={"email": email, "password": password},
        )
        if not isinstance(resp, dict):
            raise ApiError(500, "Invalid login response payload", resp)
        self.token = resp.get("access_token", "")
        self.email = email
        self._save_session()
        return resp

    def logout(self) -> None:
        """Clear the stored session."""
        self._clear_session()

    def require_auth(self) -> None:
        """Raise if no token is available."""
        if not self.token:
            raise ApiError(
                401,
                "Not authenticated. Run: ea-agentgate login",
            )

    # ------------------------------------------------------------------
    # HTTP transport
    # ------------------------------------------------------------------

    def _validate_base_url(self) -> None:
        """Allow only HTTP(S) API endpoints for outbound requests."""
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(
                "DashboardClient base_url must use http or https scheme",
            )
        if not parsed.netloc:
            raise ValueError("DashboardClient base_url must include a host")

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Execute an HTTP request against the server."""
        url = f"{self.base_url}{path}"
        if params:
            filtered = {k: str(v) for k, v in params.items() if v is not None}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)

        request_headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            request_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            request_headers.update(headers)

        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url,
            data=data,
            headers=request_headers,
            method=method,
        )

        try:
            # base_url is validated to http/https in _validate_base_url.
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
                raw = resp.read().decode()
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raw_body = exc.read().decode()
            try:
                detail = json.loads(raw_body)
                msg = detail.get("detail", detail.get("message", raw_body))
            except json.JSONDecodeError:
                msg = raw_body
                detail = None
            raise ApiError(exc.code, str(msg), detail) from exc
        except urllib.error.URLError as exc:
            raise ApiError(
                0,
                f"Cannot connect to {self.base_url}: {exc.reason}",
            ) from exc

    # ------------------------------------------------------------------
    # Convenience verbs (all require auth except raw request())
    # ------------------------------------------------------------------

    def get(
        self,
        path: str,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Authenticated GET request."""
        self.require_auth()
        return self.request("GET", path, params=params, headers=headers)

    def post(
        self,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Authenticated POST request."""
        self.require_auth()
        return self.request("POST", path, body=body, headers=headers)

    def put(
        self,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Authenticated PUT request."""
        self.require_auth()
        return self.request("PUT", path, body=body, headers=headers)

    def patch(
        self,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Authenticated PATCH request."""
        self.require_auth()
        return self.request("PATCH", path, body=body, headers=headers)

    def delete(
        self,
        path: str,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Authenticated DELETE request."""
        self.require_auth()
        return self.request("DELETE", path, params=params, headers=headers)

    # ------------------------------------------------------------------
    # Formal security convenience API
    # ------------------------------------------------------------------

    def formal_evaluate_admissibility(
        self,
        *,
        principal: str,
        action: str,
        resource: str,
        runtime_context: dict | None = None,
        delegation_ref: str | None = None,
        tenant_id: str | None = None,
        chain_id: str = "sdk-formal-evaluation",
    ) -> FormalEvaluateResponse:
        """Evaluate formal admissibility through the canonical security endpoint."""
        response = self.post(
            "/api/security/admissibility/evaluate",
            body={
                "principal": principal,
                "action": action,
                "resource": resource,
                "runtime_context": runtime_context or {},
                "delegation_ref": delegation_ref,
                "tenant_id": tenant_id,
                "chain_id": chain_id,
            },
        )
        if not isinstance(response, dict):
            raise ApiError(500, "Invalid formal evaluate response payload", response)
        return cast(FormalEvaluateResponse, response)

    def formal_verify_certificate(self, decision_id: str) -> FormalVerifyCertificateResponse:
        """Verify a formal decision certificate by ID."""
        response = self.post(
            "/api/security/certificate/verify",
            body={"decision_id": decision_id},
        )
        if not isinstance(response, dict):
            raise ApiError(500, "Invalid certificate verify response payload", response)
        return cast(FormalVerifyCertificateResponse, response)

    def formal_verify_evidence_chain(
        self, chain_id: str = "global"
    ) -> FormalVerifyEvidenceResponse:
        """Verify integrity of an immutable evidence chain."""
        chain_path = urllib.parse.quote(chain_id, safe="")
        response = self.get(f"/api/security/evidence/chain/{chain_path}")
        if not isinstance(response, dict):
            raise ApiError(500, "Invalid evidence verify response payload", response)
        return cast(FormalVerifyEvidenceResponse, response)

    def formal_runtime_status(self) -> dict[str, Any]:
        """Fetch runtime solver diagnostics for formal enforcement readiness."""
        response = self.get("/api/security/admissibility/runtime-status")
        if not isinstance(response, dict):
            raise ApiError(500, "Invalid runtime status response payload", response)
        return response
