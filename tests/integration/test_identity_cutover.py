"""Integration test for hybrid-to-descope identity cutover behavior."""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections.abc import Iterator

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select
from sqlmodel.pool import StaticPool

from server.main import app
from server.models import User, get_session
from server.routers.auth_utils import create_access_token


def _is_truthy(value: str | None) -> bool:
    """Return True when a string expresses an enabled flag."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _base64url_uint(value: int) -> str:
    """Encode an integer as base64url without padding."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _generate_rsa_material(kid: str) -> tuple[str, dict[str, object]]:
    """Generate a private key PEM and corresponding JWKS document."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _base64url_uint(public_numbers.n),
                "e": _base64url_uint(public_numbers.e),
            }
        ]
    }
    return private_pem, jwks


class _JWKSHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler serving a static JWKS document."""

    jwks_bytes: bytes = b'{"keys":[]}'

    def do_get(self) -> None:
        """Serve the static JWKS payload for test token validation."""
        if self.path != "/jwks":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(self.jwks_bytes)

    do_GET = do_get

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """Suppress HTTP server request logs in test output."""
        _ = (code, size)


@contextmanager
def _jwks_server(jwks: dict[str, object]) -> Iterator[str]:
    """Start a local JWKS server and yield the JWKS endpoint URL."""
    handler_cls = type("DynamicJWKSHandler", (_JWKSHandler,), {})
    handler_cls.jwks_bytes = json.dumps(jwks).encode("utf-8")
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/jwks"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _issue_local_provider_token(email: str, tenant_id: str) -> str:
    """Issue a local provider token for hybrid mode exchange."""
    return create_access_token(
        {
            "sub": email,
            "email": email,
            "name": "Cutover User",
            "role": "developer",
            "roles": ["developer"],
            "tenant_id": tenant_id,
            "session_assurance": "A1",
            "principal_risk": "R1",
        }
    )


def _issue_descope_provider_token(
    *,
    private_key_pem: str,
    kid: str,
    email: str,
    issuer: str,
    audience: str,
    tenant_id: str,
) -> str:
    """Issue an RS256 token validated through JWKS for descope mode."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "descope|cutover-user",
        "email": email,
        "name": "Cutover User",
        "roles": ["developer"],
        "tenant_id": tenant_id,
        "amr": ["mfa"],
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    return jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"kid": kid})


def _build_test_client(database_url: str | None = None) -> tuple[TestClient, Session]:
    """Create a test client backed by an isolated database."""
    if database_url:
        resolved_url = database_url
        if resolved_url.startswith("postgresql://") and "+psycopg" not in resolved_url:
            resolved_url = resolved_url.replace("postgresql://", "postgresql+psycopg://", 1)
        engine = create_engine(resolved_url)
    else:
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def get_session_override() -> Session:
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    return client, session


def _resolve_cutover_database_url(
    *,
    backend: str,
    explicit_postgres_url: str,
    postgres_test_db: str | None,
    require_postgres: bool,
) -> str | None:
    """Resolve the test database URL for the requested cutover backend."""
    if backend != "postgres":
        return None
    if explicit_postgres_url:
        return explicit_postgres_url
    if postgres_test_db:
        return postgres_test_db
    if require_postgres:
        pytest.fail("PostgreSQL backend was required but no database URL was available.")
    pytest.skip("PostgreSQL test container is unavailable for cutover simulation.")
    raise AssertionError("unreachable")


def _assert_provider_mode(
    client: TestClient,
    *,
    expected_mode: str,
    local_password_auth_allowed: bool,
) -> None:
    """Assert provider mode and local-password policy from the public provider endpoint."""
    providers = client.get("/api/auth/providers")
    assert providers.status_code == 200
    provider_body = providers.json()
    assert provider_body["mode"] == expected_mode
    assert provider_body["local_password_auth_allowed"] is local_password_auth_allowed


def _assert_local_hybrid_exchange(
    client: TestClient,
    *,
    email: str,
    tenant_id: str,
) -> None:
    """Exchange a local-provider token and verify the hybrid response."""
    hybrid_token = _issue_local_provider_token(email=email, tenant_id=tenant_id)
    hybrid_exchange = client.post(
        "/api/auth/exchange",
        json={"provider_token": hybrid_token, "provider_hint": "local"},
    )
    assert hybrid_exchange.status_code == 200
    hybrid_body = hybrid_exchange.json()
    assert hybrid_body["auth_provider"] == "local"
    assert hybrid_body["tenant_id"] == tenant_id


def _assert_local_login_disabled(client: TestClient, *, email: str) -> None:
    """Assert local-password login is disabled after the descope cutover."""
    local_login = client.post(
        "/api/auth/login",
        json={"email": email, "password": "ignored"},
    )
    assert local_login.status_code == 403
    assert "Local password login is disabled" in local_login.json()["detail"]


def _assert_descope_auth_context(
    client: TestClient,
    *,
    access_token: str,
    tenant_id: str,
) -> None:
    """Assert live auth context reflects the Descope-backed identity."""
    context_response = client.get(
        "/api/auth/context",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert context_response.status_code == 200
    auth_context = context_response.json()
    assert auth_context["provider"] == "descope"
    assert auth_context["provider_subject"] == "descope|cutover-user"
    assert auth_context["tenant_id"] == tenant_id


def _assert_persisted_descope_identity(
    session: Session,
    *,
    email: str,
    tenant_id: str,
) -> None:
    """Assert the user record was updated to the Descope identity provider state."""
    user = session.exec(select(User).where(User.email == email)).first()
    assert user is not None
    assert user.identity_provider == "descope"
    assert user.provider_subject == "descope|cutover-user"
    assert user.tenant_id == tenant_id


def _run_descope_cutover(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    *,
    email: str,
    descope_tenant: str,
) -> str:
    """Switch the app to descope mode and return a verified access token."""
    kid = "descope-cutover-key"
    issuer = "https://descope.example.test"
    audience = "agentgate-cutover-tests"
    private_key_pem, jwks = _generate_rsa_material(kid=kid)
    with _jwks_server(jwks) as jwks_url:
        monkeypatch.setenv("IDENTITY_PROVIDER_MODE", "descope")
        monkeypatch.setenv("ALLOW_LOCAL_PASSWORD_AUTH", "false")
        monkeypatch.setenv("DESCOPE_JWKS_URL", jwks_url)
        monkeypatch.setenv("DESCOPE_ISSUER", issuer)
        monkeypatch.setenv("DESCOPE_AUDIENCE", audience)

        _assert_provider_mode(
            client,
            expected_mode="descope",
            local_password_auth_allowed=False,
        )
        _assert_local_login_disabled(client, email=email)
        descope_token = _issue_descope_provider_token(
            private_key_pem=private_key_pem,
            kid=kid,
            email=email,
            issuer=issuer,
            audience=audience,
            tenant_id=descope_tenant,
        )
        descope_exchange = client.post(
            "/api/auth/exchange",
            json={"provider_token": descope_token, "provider_hint": "descope"},
        )
        assert descope_exchange.status_code == 200
        descope_body = descope_exchange.json()
        assert descope_body["auth_provider"] == "descope"
        assert descope_body["tenant_id"] == descope_tenant
        assert descope_body["session_assurance"] == "A2"
        _assert_descope_auth_context(
            client,
            access_token=descope_body["access_token"],
            tenant_id=descope_tenant,
        )
        return str(descope_body["access_token"])


def test_hybrid_to_descope_cutover_simulation(
    monkeypatch: pytest.MonkeyPatch,
    postgres_test_db: str | None,
) -> None:
    """Validate staged cutover behavior from hybrid_migration to descope."""
    backend = os.getenv("CUTOVER_TEST_BACKEND", "sqlite").strip().lower()
    require_postgres = _is_truthy(os.getenv("CUTOVER_TEST_REQUIRE_POSTGRES"))
    explicit_postgres_url = os.getenv("CUTOVER_TEST_DATABASE_URL", "").strip()
    db_url = _resolve_cutover_database_url(
        backend=backend,
        explicit_postgres_url=explicit_postgres_url,
        postgres_test_db=postgres_test_db,
        require_postgres=require_postgres,
    )

    client, session = _build_test_client(database_url=db_url)
    email = f"cutover-{secrets.token_hex(4)}@example.com"
    hybrid_tenant = "tenant-hybrid"
    descope_tenant = "tenant-descope"

    try:
        monkeypatch.setenv("AGENTGATE_ENV", "test")
        monkeypatch.setenv("TESTING", "true")
        monkeypatch.setenv("IDENTITY_PROVIDER_MODE", "hybrid_migration")
        monkeypatch.setenv("ALLOW_LOCAL_PASSWORD_AUTH", "true")
        monkeypatch.delenv("DESCOPE_JWKS_URL", raising=False)
        monkeypatch.delenv("DESCOPE_ISSUER", raising=False)
        monkeypatch.delenv("DESCOPE_AUDIENCE", raising=False)

        _assert_provider_mode(
            client,
            expected_mode="hybrid_migration",
            local_password_auth_allowed=True,
        )
        _assert_local_hybrid_exchange(client, email=email, tenant_id=hybrid_tenant)
        _run_descope_cutover(
            client,
            monkeypatch,
            email=email,
            descope_tenant=descope_tenant,
        )
        _assert_persisted_descope_identity(
            session,
            email=email,
            tenant_id=descope_tenant,
        )
    finally:
        app.dependency_overrides.clear()
        session.close()
        client.close()
