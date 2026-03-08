"""Security headers middleware."""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers to all responses.

    Implements OWASP recommended security headers:
    - Content-Security-Policy: Prevents XSS and injection attacks
    - Strict-Transport-Security: Enforces HTTPS
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME sniffing
    - X-XSS-Protection: Legacy XSS protection
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Feature permissions

    Usage:
        from server.middleware import SecurityHeadersMiddleware

        app.add_middleware(SecurityHeadersMiddleware)
    """

    def __init__(self, app, enable_hsts: bool | None = None):
        """
        Initialize security headers middleware.

        Args:
            app: FastAPI application
            enable_hsts: Enable HSTS header (auto-detects from env if None)
        """
        super().__init__(app)
        # Only enable HSTS in production with HTTPS
        self.enable_hsts = (
            enable_hsts if enable_hsts is not None else os.getenv("AGENTGATE_ENV") == "production"
        )

    def _set_content_security_policy(self, response: Response, request: Request) -> None:
        """Set appropriate Content-Security-Policy header based on path.

        Note: /docs and /api/reference set their own nonce-based CSP directly
        in the route handler
        to avoid CDN dependencies and enable strict CSP with vendored assets.
        """
        # Skip docs routes that define nonce-based CSP in route handlers.
        if request.url.path in {"/docs", "/api/reference"}:
            return

        # OpenAPI JSON doesn't need scripts, use strict CSP
        if request.url.path == "/openapi.json":
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none';"
            )
        else:
            # Default strict CSP for API endpoints
            # No unsafe-inline or unsafe-eval needed for JSON APIs
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )

    def _set_security_headers(self, response: Response) -> None:
        """Set all OWASP security headers."""
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        if "server" in response.headers:
            del response.headers["server"]

    def is_hsts_enabled(self) -> bool:
        """Check if HSTS is enabled for this middleware.

        Returns:
            True if HSTS header is enabled, False otherwise
        """
        return self.enable_hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        """Add security headers to response."""
        response: Response = await call_next(request)
        self._set_content_security_policy(response, request)
        self._set_security_headers(response)
        return response
