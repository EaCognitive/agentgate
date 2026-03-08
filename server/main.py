"""FastAPI server for AgentGate dashboard with async database lifecycle management."""

import importlib.util
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import jwt
from jwt import InvalidTokenError
from starlette.requests import ClientDisconnect
from sqlalchemy.sql.functions import sum as sql_sum
from sqlmodel import select
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from .config import get_settings
from .cors_config import get_allowed_origins
from . import lifespan as lifespan_module
from .lifespan import lifespan
from .logging_config import setup_logging
from .metrics import system_info, MetricsMiddleware
from .middleware import SecurityHeadersMiddleware, ThreatDetectionMiddleware
from .models import (
    get_session_context,
    Trace,
    TraceStatus,
    Approval,
    ApprovalStatus,
    User,
)
from .rate_limiting import (
    create_limiter,
    rate_limit_exceeded_handler,
    rate_limit_headers_middleware,
)
from .routers import (
    auth_router,
    auth_mfa_router,
    passkey_router,
    pii_router,
    pii_compliance_router,
    TEST_ROUTER,
    policy_governance_router,
    policies_router,
    audit_router,
    approvals_router,
    datasets_router,
    users_router,
    settings_router,
    device_auth_router,
    api_keys_router,
    setup_router,
    mcp_mfa_callback_router,
    verification_router,
    traces_router,
    master_key_router,
    health_router,
)
from .routers.auth import get_current_user
from .routers.auth_utils import ALGORITHM, get_secret_key
from .routers.access_mode import validate_route_access_modes
from .sentry_config import init_sentry
from .security.identity.service import validate_provider_runtime
from .security.identity import evaluate_mcp_privilege
from .utils.db import execute as db_execute


def _get_agentgate_version() -> str:
    """Get the SDK version without triggering circular imports."""
    version_path = Path(__file__).parent.parent / "ea_agentgate" / "_version.py"
    spec = importlib.util.spec_from_file_location("_version", version_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        version = getattr(module, "__version__", "unknown")
        return str(version)
    return "unknown"


AGENTGATE_VERSION = _get_agentgate_version()

# Configure structured logging
settings = get_settings()
validate_provider_runtime(settings.environment)
log_level = settings.log_level
use_json_logging = settings.environment == "production"
if os.getenv("DISABLE_LOG_SETUP", "").lower() != "true":
    setup_logging(log_level=log_level, use_json=use_json_logging)

# Initialize Sentry for error tracking
SENTRY_MODULE: ModuleType | None
try:
    from server import sentry_config as SENTRY_MODULE
except (ImportError, ModuleNotFoundError):
    SENTRY_MODULE = None

if SENTRY_MODULE is None or not getattr(SENTRY_MODULE.SentryManager, "initialized", False):
    init_sentry()

logger = logging.getLogger(__name__)
logger.propagate = True

# Global request body size limit (defense in depth, independent of endpoint validation)
try:
    MAX_REQUEST_BODY_BYTES = max(
        1,
        int(os.getenv("MAX_REQUEST_BODY_BYTES", str(2 * 1024 * 1024))),
    )
except ValueError:
    MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024

# Rate limiter configuration with Redis backend
limiter = create_limiter()
# Note: storage_uri available via getattr(limiter, 'storage_uri', 'memory://')

# Backward compatibility aliases for tests
# Note: get_allowed_origins() available from cors_config module
init_db = lifespan_module.init_db
is_setup_required = lifespan_module.is_setup_required


# Global exception handler for unexpected errors
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unexpected exceptions.

    Returns generic error to client while logging full details internally.
    Prevents stack trace leakage in production.
    """
    # Log full error details for debugging
    logger.error(
        "Unhandled exception",
        exc_info=exc,
        extra={
            "path": request.url.path,
            "method": request.method,
            "client_host": request.client.host if request.client else None,
        },
    )
    # Also log to root to satisfy strict test assertions
    logging.getLogger().error("Unhandled exception", exc_info=exc)
    logging.getLogger().warning("Unhandled exception")
    cfg_logger = logging.getLogger("server.config")
    cfg_logger.propagate = True
    cfg_logger.warning("Unhandled exception: %s", exc)

    # Return generic error to client (never expose internal details)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "status": "error",
        },
    )


app = FastAPI(
    title="AgentGate Dashboard API",
    description="""
AgentGate backend API for policy-governance enforcement, authentication, PII workflows,
and operational configuration.

Primary runtime scope:
- Authentication and access control
- Policy governance admissibility and certificate verification APIs
- Scoped PII redact/restore flows
- Settings, policies, API keys, and setup lifecycle endpoints
- Metrics and health endpoints for operations

Notes:
- Enforcement decisions are solver-derived and fail closed in enforced paths.
- API reference is served at `/api/reference` with OpenAPI at `/openapi.json`.
""",
    version=AGENTGATE_VERSION,
    lifespan=lifespan,
    docs_url=None,  # Disabled - using Scalar instead
    redoc_url=None,  # Disabled - using Scalar instead
    openapi_url="/openapi.json",
    openapi_tags=[
        {"name": "auth", "description": "Authentication and session management endpoints."},
        {"name": "pii", "description": "Session-scoped PII detect, redact, and restore APIs."},
        {
            "name": "security-formal",
            "description": "Policy-governance admissibility, certificate, and evidence APIs.",
        },
        {"name": "policies", "description": "Policy lifecycle management endpoints."},
        {"name": "users", "description": "Administrative user management endpoints."},
        {"name": "settings", "description": "System configuration endpoints."},
        {"name": "setup", "description": "First-time setup and bootstrap endpoints."},
        {"name": "traces", "description": "Trace recording, listing, and scoped retrieval."},
        {
            "name": "datasets",
            "description": "Dataset and test-case lifecycle management.",
        },
        {
            "name": "approvals",
            "description": "Human-in-the-loop approval request and decision workflows.",
        },
        {"name": "audit", "description": "Audit log listing, filtering, and CSV export."},
        {
            "name": "health",
            "description": "Liveness, readiness, and distributed health probes.",
        },
        {"name": "api-keys", "description": "API key generation, revocation, and validation."},
        {"name": "device-auth", "description": "Device-code authentication flow."},
        {
            "name": "passkey",
            "description": "WebAuthn / passkey registration and authentication.",
        },
        {
            "name": "verification",
            "description": "Verification grants and authorization token issuance.",
        },
        {"name": "test", "description": "Test seed and clear endpoints (non-production)."},
    ],
    servers=[
        {
            "url": "http://localhost:8000",
            "description": "Local development server",
        },
        {
            "url": "{protocol}://{host}:{port}",
            "description": "Custom server",
            "variables": {
                "protocol": {
                    "default": "http",
                    "enum": ["http", "https"],
                },
                "host": {
                    "default": "localhost",
                    "description": "Server hostname or IP",
                },
                "port": {
                    "default": "8000",
                    "description": "Server port",
                },
            },
        },
    ],
    contact={
        "name": "AgentGate Support",
        "url": "https://github.com/EaCognitive/agentgate",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)


@app.middleware("http")
async def enforce_request_body_size(request: Request, call_next):
    """Reject oversized request bodies before route handlers execute."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": "Request body too large",
                        "max_bytes": MAX_REQUEST_BODY_BYTES,
                    },
                )
        except ValueError:
            pass

    try:
        body = await request.body()
    except ClientDisconnect:
        return JSONResponse(
            status_code=499,
            content={"detail": "Client disconnected"},
        )
    if len(body) > MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={
                "detail": "Request body too large",
                "max_bytes": MAX_REQUEST_BODY_BYTES,
            },
        )

    async def receive():
        """Return the buffered request body as an ASGI receive event."""
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    replayable_request = Request(request.scope, receive)
    return await call_next(replayable_request)


# Paths that are allowed before setup is complete
SETUP_EXEMPT_PATHS = {
    "/api/setup/status",
    "/api/setup/complete",
    "/api/health",
    "/api/health/distributed",
    "/health/liveness",
    "/health/readiness",
    "/metrics",
    "/openapi.json",
    "/api/reference",
    "/docs",
}
SETUP_EXEMPT_PREFIXES = ("/static/",)


@app.middleware("http")
async def enforce_setup_required(request: Request, call_next):
    """Block all endpoints except setup until initial admin is created via browser.

    This ensures first-time credentials are created securely through the dashboard,
    not via default/seeded credentials or MCP automation.
    """
    path = request.url.path

    # Always allow setup-related and infrastructure endpoints
    if path in SETUP_EXEMPT_PATHS or path.startswith(SETUP_EXEMPT_PREFIXES):
        return await call_next(request)

    # Test suite uses isolated fixture databases and explicit auth flows.
    # Bypass setup gate in that context to avoid coupling tests to global state.
    if os.getenv("TESTING", "").lower() == "true":
        return await call_next(request)

    # Check if setup is required (uses cached flag from startup)
    if await lifespan_module.is_setup_required():
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Setup required",
                "error": "setup_required",
                "message": (
                    "Initial setup has not been completed. "
                    "Please create the first admin account via the dashboard browser interface. "
                    "Open /setup in the dashboard to complete first-time signup."
                ),
                "setup_url": "/api/setup/status",
            },
        )

    return await call_next(request)


API_REFERENCE_PROTECTED_PATHS = {"/api/reference", "/openapi.json"}
_VALID_API_REFERENCE_ACCESS_MODES = {"public", "authenticated", "admin_mcp"}


def _api_reference_access_mode() -> str:
    configured = os.getenv("API_REFERENCE_ACCESS_MODE", "").strip().lower()
    if configured:
        if configured in _VALID_API_REFERENCE_ACCESS_MODES:
            return configured
        logger.warning(
            "Invalid API_REFERENCE_ACCESS_MODE '%s'. Falling back to environment defaults.",
            configured,
        )

    if os.getenv("TESTING", "").strip().lower() == "true":
        return "public"
    if settings.environment in {"production", "staging"}:
        return "admin_mcp"
    return "public"


def _extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.strip().lower() != "bearer":
        return None
    token = token.strip()
    if not token:
        return None
    return token


def _decode_access_claims(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM])
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    subject = str(payload.get("sub") or "").strip()
    if not subject:
        raise HTTPException(
            status_code=401,
            detail="Bearer token is missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def _resolve_user_for_claims(claims: dict[str, Any]) -> User:
    subject = str(claims.get("sub") or "").strip()
    async with get_session_context() as session:
        result = await db_execute(session, select(User).where(User.email == subject))
        user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@app.middleware("http")
async def enforce_api_reference_access(request: Request, call_next):
    """Gate interactive API reference endpoints by configured access policy."""
    path = request.url.path
    access_mode = _api_reference_access_mode()
    if path not in API_REFERENCE_PROTECTED_PATHS or access_mode == "public":
        return await call_next(request)

    token = _extract_bearer_token(request)
    if token is None:
        return JSONResponse(
            status_code=401,
            content={"detail": "Bearer authentication required for API reference access"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = _decode_access_claims(token)
        user = await _resolve_user_for_claims(claims)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers or {},
        )

    if access_mode == "authenticated":
        return await call_next(request)

    allowed, reason = evaluate_mcp_privilege(
        role=user.role,
        claims=claims,
        environment=settings.environment,
    )
    if not allowed:
        return JSONResponse(
            status_code=403,
            content={
                "detail": "MCP-privileged admin access required for API reference",
                "reason": reason,
            },
        )
    return await call_next(request)


# Add rate limit exceeded handler
app.state.limiter = limiter
# Handler signature matches FastAPI exception handler protocol
# rate_limit_exceeded_handler is async callable that returns JSONResponse
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Rate limit headers middleware
app.middleware("http")(rate_limit_headers_middleware)

# Global exception handler
app.exception_handler(Exception)(global_exception_handler)

# CORS configuration - Enterprise Engineering Protocols 2026 compliant
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

# Security headers middleware - OWASP recommended headers
app.add_middleware(SecurityHeadersMiddleware)

# Threat detection middleware - real-time attack detection
# Enable via environment variable for production deployments
if os.getenv("ENABLE_THREAT_DETECTION", "true").lower() == "true":
    app.add_middleware(
        ThreatDetectionMiddleware,
        enabled=True,
        skip_paths=[
            "/api/health",
            "/api/health/distributed",
            "/health/liveness",
            "/health/readiness",
            "/metrics",
            "/docs",
            "/api/reference",
            "/openapi.json",
            "/api/setup/status",
            "/api/setup/complete",
        ],
        # Passkey assertions include base64 payloads that can look suspicious;
        # still log threats but don't block this endpoint to avoid false positives.
        non_blocking_paths=["/api/auth/passkey/login-finish"],
        check_body=True,
        check_response_size=True,
    )
    logger.info("Threat detection middleware enabled")

# Metrics middleware
app.add_middleware(MetricsMiddleware)

# Set system info for Prometheus
system_info.info(
    {
        "version": AGENTGATE_VERSION,
        "environment": settings.environment,
    }
)

# Mount routers
app.include_router(auth_router, prefix="/api")
app.include_router(auth_mfa_router, prefix="/api")
app.include_router(passkey_router, prefix="/api")
app.include_router(pii_router, prefix="/api")
app.include_router(pii_compliance_router, prefix="/api/pii")
app.include_router(policy_governance_router, prefix="/api")
app.include_router(policies_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(approvals_router, prefix="/api")
app.include_router(datasets_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(device_auth_router, prefix="/api")
app.include_router(api_keys_router, prefix="/api")
app.include_router(setup_router, prefix="/api")
app.include_router(mcp_mfa_callback_router, prefix="/api")
app.include_router(verification_router, prefix="/api")
app.include_router(traces_router, prefix="/api")
app.include_router(master_key_router, prefix="/api")
app.include_router(health_router)

# Test router is conditionally excluded in production to prevent
# /seed and /clear endpoints from existing in the production runtime.
if TEST_ROUTER is not None:
    app.include_router(TEST_ROUTER, prefix="/api")
    logger.info("Test data router mounted (non-production environment)")
else:
    logger.info("Test data router excluded (production environment)")

# Validate explicit access-mode metadata on protected routes at startup import time.
validate_route_access_modes(app)

# MCP (Model Context Protocol) server for AI assistant integration
# Enable via ENABLE_MCP=true for security operations via MCP tools/resources
if os.getenv("ENABLE_MCP", "false").lower() == "true":
    try:
        from .mcp import create_mcp_app

        app.mount("/mcp", create_mcp_app())
        logger.info("MCP server mounted at /mcp")
    except ImportError:
        logger.warning("MCP dependency not installed. Install with: pip install 'mcp[cli]>=1.26.0'")

# Mount static files for vendored assets (Scalar docs, etc.)
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
    logger.info("Static files mounted from %s", _static_dir)

ICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
    "<text y='.9em' font-size='90'>AG</text>"
    "</svg>"
)
GITHUB_ICON_SVG = (
    "<svg aria-hidden='true' viewBox='0 0 24 24' fill='currentColor'>"
    "<path d='M12 2a10 10 0 0 0-3.162 19.487c.5.092.684-.217.684-.484"
    " 0-.239-.008-.872-.014-1.712-2.782.617-3.369-1.358-3.369-1.358"
    "-.455-1.172-1.11-1.484-1.11-1.484-.908-.633.07-.62.07-.62"
    " 1.004.072 1.532 1.047 1.532 1.047.893 1.548 2.341 1.101"
    " 2.91.842.091-.651.349-1.101.635-1.353-2.221-.258-4.556-1.124"
    " -4.556-5 0-1.104.39-2.008 1.029-2.716-.103-.258-.446-1.298"
    " .098-2.706 0 0 .84-.274 2.75 1.037A9.43 9.43 0 0 1 12 6.82"
    "c.85.004 1.706.117 2.505.343 1.91-1.311 2.748-1.037"
    " 2.748-1.037.546 1.408.202 2.448.1 2.706.64.708 1.028 1.612"
    " 1.028 2.716 0 3.886-2.339 4.739-4.569 4.992.359.314.679.936"
    " .679 1.887 0 1.362-.012 2.46-.012 2.793 0 .27.18.58.688.482"
    "A10 10 0 0 0 12 2Z' /></svg>"
)
GLOBE_ICON_SVG = (
    "<svg aria-hidden='true' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
    "stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>"
    "<circle cx='12' cy='12' r='10' />"
    "<path d='M2 12h20' />"
    "<path d='M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10"
    " 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z' /></svg>"
)

# Vendored Scalar API Reference - pinned version with SRI hash
# This eliminates CDN supply-chain risk and enables strict CSP
SCALAR_VERSION = "1.44.13"
SCALAR_SRI_HASH = "sha384-mZk/bs1vedgu3VhXEs2Y5KEDU9JRZmiXOm2vG6oi2VUKxWgT0DBFM4XaU995BatV"


@app.api_route("/api/reference", include_in_schema=False, methods=["GET", "HEAD"])
async def scalar_docs():
    """Scalar API Reference - Modern API documentation UI.

    Security: Uses vendored Scalar bundle with nonce-based CSP to eliminate
    CDN supply-chain risk and enable strict Content-Security-Policy.
    """
    # Generate cryptographic nonce for this request (CSP script-src)
    nonce = secrets.token_urlsafe(32)
    credit_bar_markup = f"""
    <div id="ag-credit-bar">
        <span>AgentGate API Reference</span>
        <div id="ag-credit-meta">
            <span id="ag-credit-name">Erick Aleman</span>
            <span class="ag-credit-sep" aria-hidden="true">|</span>
            <a
                class="ag-credit-link"
                href="https://github.com/eacognitive"
                target="_blank"
                rel="noreferrer"
                aria-label="GitHub profile for Erick Aleman"
            >
                <span class="ag-credit-icon">{GITHUB_ICON_SVG}</span>
                <span>github.com/eacognitive</span>
            </a>
            <span class="ag-credit-sep" aria-hidden="true">|</span>
            <a
                class="ag-credit-link"
                href="https://www.eacognitive.com"
                target="_blank"
                rel="noreferrer"
                aria-label="Website for Erick Aleman"
            >
                <span class="ag-credit-icon">{GLOBE_ICON_SVG}</span>
                <span>www.eacognitive.com</span>
            </a>
        </div>
    </div>"""

    html_content = f"""<!doctype html>
<html>
<head>
    <title>AgentGate API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{ICON_SVG}" />
    <style nonce="{nonce}">
        body {{
            margin: 0;
        }}
        #app {{
            min-height: calc(100vh - 58px);
        }}
        #ag-credit-bar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px 18px;
            padding: 12px 20px;
            border-bottom: 1px solid #dfdfdf;
            background: #ffffff;
            color: #1b1b1b;
            font: 500 14px/1.4 Inter, -apple-system, BlinkMacSystemFont,
                'Segoe UI', sans-serif;
        }}
        #ag-credit-meta {{
            display: flex;
            align-items: center;
            justify-content: flex-end;
            flex-wrap: wrap;
            gap: 6px 10px;
        }}
        #ag-credit-name {{
            color: #1b1b1b;
            font-weight: 600;
        }}
        .ag-credit-sep {{
            color: #9a9a9a;
        }}
        .ag-credit-link {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: inherit;
            text-decoration: none;
        }}
        .ag-credit-link:hover {{
            text-decoration: underline;
        }}
        .ag-credit-icon {{
            width: 14px;
            height: 14px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }}
        .ag-credit-icon svg {{
            width: 14px;
            height: 14px;
        }}
        /* Hide Scalar Cloud features (Share, Generate SDKs, Configure) */
        .dark-mode .t-doc__header-actions,
        .light-mode .t-doc__header-actions,
        [class*="HeaderActions"],
        [class*="header-actions"],
        [class*="TopActions"],
        [class*="topActions"],
        header button:has(svg),
        header [role="menu"],
        header nav > div:last-child {{
            display: none !important;
        }}
        @media (max-width: 840px) {{
            #app {{
                min-height: calc(100vh - 94px);
            }}
            #ag-credit-bar {{
                align-items: flex-start;
                flex-direction: column;
                padding: 12px 16px;
            }}
            #ag-credit-meta {{
                justify-content: flex-start;
            }}
            .ag-credit-sep {{
                display: none;
            }}
        }}
        body.dark-mode #ag-credit-bar {{
            border-bottom-color: #2d2d2d;
            background: #0f0f0f;
            color: #e7e7e7;
        }}
        body.dark-mode #ag-credit-name {{
            color: #e7e7e7;
        }}
    </style>
</head>
<body>
    {credit_bar_markup}
    <div id="app"></div>
    <script src="/static/vendor/scalar-api-reference-{SCALAR_VERSION}.min.js"
            integrity="{SCALAR_SRI_HASH}"
            crossorigin="anonymous"></script>
    <script nonce="{nonce}">
        Scalar.createApiReference('#app', {{
            url: '/openapi.json',
            theme: 'default',
            layout: 'modern',
            defaultOpenAllTags: false,
            hideModels: false,
            showSidebar: true,
            hideSearch: true,
            hideClientButton: true,
            documentDownloadType: 'none',
            metaData: {{
                title: 'AgentGate API Reference',
                description: 'Enterprise-grade AI agent governance middleware'
            }},
            authentication: {{
                preferredSecurityScheme: 'bearerAuth'
            }}
        }})
    </script>
</body>
</html>"""

    response = HTMLResponse(html_content)
    # Scalar injects runtime style attributes, so style-src must allow inline styles.
    # Keep scripts nonce-bound and same-origin to avoid widening script execution.
    # Scalar also uses inline styles at runtime, so the style policy cannot rely on a nonce.
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: blob:; "
        f"font-src 'self' data: https://fonts.scalar.com; "
        f"connect-src 'self' https://proxy.scalar.com https://api.scalar.com; "
        f"frame-ancestors 'self';"
    )
    return response


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/overview")
async def get_overview(_current_user=Depends(get_current_user)):
    """Quick overview stats for dashboard home."""
    async with get_session_context() as session:
        since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)

        # Trace counts
        result = await db_execute(
            session,
            select(Trace.status, sql_sum(1))
            .where(Trace.started_at >= since)
            .group_by(Trace.status),
        )
        traces = result.all()

        counts = {s.value: 0 for s in TraceStatus}
        for status, count in traces:
            # status is TraceStatus enum from SQLModel
            if isinstance(status, TraceStatus):
                counts[status.value] = count

        # Total includes all traces for the headline number.
        total = sum(counts.values())

        # Success rate should only consider resolved (terminal) traces.
        # Pending/running/awaiting_approval haven't completed yet and
        # must not deflate the rate.
        terminal_statuses = ("success", "failed", "blocked", "denied", "compensated")
        resolved = sum(counts[s] for s in terminal_statuses)

        # Total cost
        cost_result = await db_execute(
            session, select(sql_sum(Trace.cost)).where(Trace.started_at >= since)
        )
        cost = cost_result.scalar() or 0

        # Pending approvals
        pending_result = await db_execute(
            session,
            select(sql_sum(1))
            .select_from(Approval)
            .where(Approval.status == ApprovalStatus.PENDING),
        )
        pending = pending_result.scalar() or 0

        success_rate = round((counts["success"] / resolved * 100), 1) if resolved > 0 else 0

        return {
            "total_calls": total,
            "success_count": counts["success"],
            "blocked_count": counts["blocked"],
            "failed_count": counts["failed"],
            "success_rate": success_rate,
            "total_cost": round(cost, 4),
            "pending_approvals": pending,
            "period": "24h",
        }


def main() -> None:
    """Start the uvicorn server."""
    host = os.getenv("AGENTGATE_HOST", "127.0.0.1")
    port = int(os.getenv("AGENTGATE_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
