"""
FastAPI middleware for real-time threat detection.

Integrates the threat detection engine into the request pipeline with:
- Minimal latency impact (<10ms overhead)
- Non-blocking detection for most checks
- Automatic IP blocking enforcement
- Request/response analysis
- Metrics export
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast
from collections.abc import Callable, Awaitable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from server.policy_governance.kernel.threat_detector import (
    ThreatDetector,
    ThreatSeverity,
)
from server.models import SecurityThreat, get_session_context
from server.utils.db import commit as db_commit

logger = logging.getLogger(__name__)


def _extract_trusted_ip_from_xff(forwarded_for: str) -> str | None:
    """Extract the trusted client IP from an X-Forwarded-For chain.

    With our Nginx config, ``$proxy_add_x_forwarded_for`` appends the trusted
    source IP to any existing list. That means the right-most non-empty value
    is the proxy-observed client address and should be used server-side.
    """
    candidates = [part.strip() for part in forwarded_for.split(",") if part.strip()]
    if not candidates:
        return None
    return candidates[-1]


@dataclass
class ThreatDetectionConfig:
    """Configuration for threat detection middleware."""

    threat_detector: ThreatDetector | None = None
    enabled: bool = True
    skip_paths: list[str] | None = None
    non_blocking_paths: list[str] | None = None
    check_body: bool = True
    check_response_size: bool = True
    max_body_size: int = 1024 * 1024  # 1MB


class ThreatDetectionMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for threat detection.

    Performs real-time threat analysis on incoming requests with
    minimal performance impact through:
    - Early IP block checks
    - Selective body parsing
    - Background alert processing
    - Response size monitoring
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        app: ASGIApp,
        *,
        threat_detector: ThreatDetector | None = None,
        enabled: bool = True,
        skip_paths: list[str] | None = None,
        non_blocking_paths: list[str] | None = None,
        check_body: bool = True,
        check_response_size: bool = True,
        max_body_size: int = 1024 * 1024,
    ):
        """
        Initialize threat detection middleware.

        Args:
            app: FastAPI application.
            threat_detector: ThreatDetector instance.
            enabled: Enable/disable middleware.
            skip_paths: Paths to skip threat detection.
            non_blocking_paths: Paths where threats are logged but not blocked.
            check_body: Whether to parse and check request body.
            check_response_size: Whether to check response size for data exfiltration.
            max_body_size: Maximum body size to parse.
        """
        super().__init__(app)
        self._detector = threat_detector or ThreatDetector()
        self._enabled = enabled
        self._skip_paths = set(
            skip_paths or ["/api/health", "/metrics", "/docs", "/redoc", "/openapi.json"]
        )
        self._non_blocking_paths = set(non_blocking_paths or [])
        self._check_body = check_body
        self._check_response_size = check_response_size
        self._max_body_size = max_body_size

    def should_skip_path(self, path: str) -> bool:
        """Check if path should skip threat detection.

        Args:
            path: Request path to check

        Returns:
            True if threat detection should be skipped for this path
        """
        return path in self._skip_paths or path.startswith("/static/")

    def _should_skip(self, path: str) -> bool:
        """Check if path should skip threat detection."""
        return self.should_skip_path(path)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, handling proxies."""
        # Trust X-Real-IP set by our reverse proxy first.
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return cast(str, real_ip.strip())  # type: ignore[no-any-return]

        # Fallback to X-Forwarded-For chain. Use trusted right-most IP.
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            trusted_ip = _extract_trusted_ip_from_xff(forwarded_for)
            if trusted_ip:
                return cast(str, trusted_ip)  # type: ignore[no-any-return]

        # Fall back to direct connection
        if request.client:
            return cast(str, request.client.host)  # type: ignore[no-any-return]

        return "unknown"

    def _get_headers_dict(self, request: Request) -> dict[str, str]:
        """Convert request headers to dictionary."""
        return {key.lower(): value for key, value in request.headers.items()}

    async def _parse_body(self, request: Request) -> dict[str, Any] | None:
        """Safely parse request body if JSON.

        Enforces ``_max_body_size`` on the *actual* body length, not
        the client-supplied Content-Length header which can be spoofed
        or omitted entirely.
        """
        content_type = request.headers.get("content-type", "")

        if "application/json" not in content_type:
            return None

        try:
            # Pre-flight check: reject obviously oversized bodies early
            # via the header (untrusted, but avoids reading when the
            # client is honest).
            content_length = int(request.headers.get("content-length", 0))
            if content_length > self._max_body_size:
                return None

            body = await request.body()

            # Authoritative size check on the actual payload
            if len(body) > self._max_body_size:
                return None

            if body:
                return dict(json.loads(body))

        except (json.JSONDecodeError, ValueError):
            pass

        return None

    async def _record_threats(self, threats: list[Any]) -> None:
        """Persist detected threats for dashboard visibility."""
        if not threats:
            return
        try:
            async with get_session_context() as session:
                for threat in threats:
                    description = (
                        threat.details.get("description")
                        if getattr(threat, "details", None)
                        else None
                    )
                    if not description:
                        description = f"Detected {threat.event_type.value} from {threat.ip_address}"

                    metadata = {
                        "details": threat.details,
                        "pattern_matches": threat.pattern_matches,
                        "action_taken": threat.action_taken,
                        "blocked": threat.blocked,
                        "user_agent": threat.user_agent,
                    }

                    record = SecurityThreat(
                        event_id=threat.event_id,
                        event_type=threat.event_type.value,
                        severity=threat.severity.value,
                        source_ip=threat.ip_address,
                        target=threat.endpoint,
                        description=description,
                        detected_at=datetime.fromtimestamp(
                            threat.timestamp, tz=timezone.utc
                        ).replace(tzinfo=None),
                        user_id=threat.user_id,
                        user_email=threat.user_email,
                        metadata_json=metadata,
                    )
                    session.add(record)
                await db_commit(session)
        # pylint: disable-next=broad-exception-caught
        except Exception as exc:  # pragma: no cover - best-effort logging
            logger.error("Failed to persist threat events: %s", exc, exc_info=True)

    def _extract_user_info(self, request: Request) -> tuple[int | None, str | None]:
        """Extract user ID and email from authenticated request."""
        user_id: int | None = None
        user_email: str | None = None

        if hasattr(request.state, "user"):
            user = request.state.user
            user_id = getattr(user, "id", None)
            user_email = getattr(user, "email", None)

        return user_id, user_email

    async def _check_request_threat(
        self,
        request: Request,
        client_ip: str,
        user_id: int | None,
        user_email: str | None,
    ) -> JSONResponse | None:
        """Analyze request for threats. Returns JSONResponse if blocked, None otherwise."""
        try:
            headers = self._get_headers_dict(request)
            body: dict[str, Any] | None = None

            if self._check_body and request.method in ("POST", "PUT", "PATCH"):
                body = await self._parse_body(request)

            # Run threat detection
            result = self._detector.check_request(
                ip=client_ip,
                endpoint=(
                    f"{request.url.path}?{request.url.query}"
                    if request.url.query
                    else str(request.url.path)
                ),
                method=request.method,
                headers=headers,
                body=body,
                user_id=user_id,
                user_email=user_email,
            )

            if result.threats:
                await self._record_threats(result.threats)

            # Block if critical threats detected
            is_block_exempt = request.url.path in self._non_blocking_paths

            if result.should_block and not is_block_exempt:
                logger.warning(
                    "Request blocked due to threat detection: %s from %s",
                    result.block_reason,
                    client_ip,
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Request blocked",
                        "detail": "The request contains potentially malicious content",
                    },
                )
            if result.should_block and is_block_exempt:
                logger.warning(
                    "Threat detected but not blocking exempt path %s: %s from %s",
                    request.url.path,
                    result.block_reason,
                    client_ip,
                )

        # pylint: disable-next=broad-exception-caught
        except Exception as e:
            # Log but don't block on detection errors
            logger.error("Threat detection error: %s", e, exc_info=True)

        return None

    async def _check_data_exfiltration(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        user_email: str | None,
    ) -> None:
        """Check for data exfiltration in response."""
        if not self._check_response_size or not hasattr(request.state, "user"):
            return

        try:
            response_size = int(response.headers.get("content-length", 0))
            user = request.state.user

            exfil_event = self._detector.check_data_exfiltration(
                user=user,
                endpoint=str(request.url.path),
                response_size=response_size,
                ip=client_ip,
            )

            if exfil_event and exfil_event.severity in (
                ThreatSeverity.HIGH,
                ThreatSeverity.CRITICAL,
            ):
                # Log but don't block (response already sent)
                logger.warning(
                    "Data exfiltration detected: %s for user %s",
                    exfil_event.details,
                    user_email,
                )

        # pylint: disable-next=broad-exception-caught
        except Exception as e:
            logger.error("Post-response analysis error: %s", e)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process request with threat detection."""
        # Skip if disabled or path excluded
        if not self._enabled or self._should_skip(request.url.path):
            return await call_next(request)

        start_time = time.time()
        client_ip = self._get_client_ip(request)

        # Early check: Is IP blocked?
        if self._detector.is_blocked(client_ip):
            logger.warning("Blocked IP attempted access: %s", client_ip)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access denied",
                    "detail": "Your IP address has been blocked due to suspicious activity",
                },
            )

        # Get user info if authenticated
        user_id, user_email = self._extract_user_info(request)

        # Check for threats in request
        block_response = await self._check_request_threat(request, client_ip, user_id, user_email)
        if block_response is not None:
            return block_response

        # Process request
        response = await call_next(request)

        # Post-response analysis
        await self._check_data_exfiltration(request, response, client_ip, user_email)

        # Record processing time
        processing_time = (time.time() - start_time) * 1000
        if processing_time > 10:
            logger.debug(
                "Threat detection took %.2fms for %s",
                processing_time,
                request.url.path,
            )

        return response


class ThreatDetectionASGIMiddleware:
    """
    Pure ASGI middleware for threat detection.

    Lower-level implementation for maximum performance.
    Use this instead of ThreatDetectionMiddleware for
    high-throughput deployments.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        threat_detector: ThreatDetector | None = None,
        enabled: bool = True,
        skip_paths: set[str] | None = None,
    ):
        """
        Initialize ASGI middleware.

        Args:
            app: ASGI application.
            threat_detector: Threat detector instance.
            enabled: Enable/disable middleware.
            skip_paths: Paths to skip.
        """
        self._app = app
        self._detector = threat_detector or ThreatDetector()
        self._enabled = enabled
        self._skip_paths = skip_paths or {"/api/health", "/metrics"}

    def get_client_ip_from_scope(self, scope: Scope) -> str:
        """Extract client IP from ASGI scope.

        Args:
            scope: ASGI scope dictionary

        Returns:
            Client IP address as string
        """
        headers = dict(scope.get("headers", []))

        real_ip = headers.get(b"x-real-ip")
        if real_ip:
            return cast(str, real_ip.decode(errors="ignore").strip())

        forwarded = headers.get(b"x-forwarded-for")
        if forwarded:
            trusted_ip = _extract_trusted_ip_from_xff(forwarded.decode(errors="ignore"))
            if trusted_ip:
                return cast(str, trusted_ip)

        client = scope.get("client")
        if client:
            return cast(str, client[0])

        return "unknown"

    def _get_client_ip(self, scope: Scope) -> str:
        """Extract client IP from scope."""
        return self.get_client_ip_from_scope(scope)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle ASGI request."""
        if scope["type"] != "http" or not self._enabled:
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self._skip_paths:
            await self._app(scope, receive, send)
            return

        client_ip = self._get_client_ip(scope)

        # Check IP block
        if self._detector.is_blocked(client_ip):
            response = JSONResponse(
                status_code=403,
                content={"error": "Access denied"},
            )
            await response(scope, receive, send)
            return

        # Process request
        await self._app(scope, receive, send)


def create_threat_detection_middleware(
    detector: ThreatDetector | None = None,
    **kwargs: Any,
) -> type[ThreatDetectionMiddleware]:
    """
    Factory function for creating threat detection middleware.

    Args:
        detector: Optional threat detector instance.
        **kwargs: Additional middleware configuration.

    Returns:
        Configured middleware instance.

    Example:
        from fastapi import FastAPI
        from server.middleware.threat_detection import create_threat_detection_middleware

        app = FastAPI()
        middleware = create_threat_detection_middleware(
            skip_paths=["/api/health", "/docs"],
            check_body=True,
        )
        # Note: Don't pass app to factory, it's passed when adding middleware
    """
    # This returns a class that will be instantiated by FastAPI
    # with the app parameter when adding middleware

    class ConfiguredMiddleware(ThreatDetectionMiddleware):
        """Configured threat detection middleware with preset options."""

        def __init__(self, app: ASGIApp):
            super().__init__(app, threat_detector=detector, **kwargs)

    return ConfiguredMiddleware  # type: ignore[return-value]


class _SharedDetectorSingleton:
    """Singleton for managing shared threat detector instance across middleware."""

    _instance = None

    def __init__(self) -> None:
        """Initialize singleton instance attributes."""
        if not hasattr(self, "_detector"):
            self._detector: ThreatDetector | None = None

    def __new__(cls):
        """Create singleton instance on first access."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_detector(self) -> ThreatDetector:
        """Get or create the shared detector instance.

        Returns:
            Shared ThreatDetector instance
        """
        if self._detector is None:
            self._detector = ThreatDetector()
        return self._detector

    def set_detector(self, detector: ThreatDetector) -> None:
        """Set the shared detector instance.

        Args:
            detector: ThreatDetector instance to set
        """
        self._detector = detector

    def reset_detector(self) -> None:
        """Reset the shared detector instance to None."""
        self._detector = None


def get_shared_detector() -> ThreatDetector:
    """
    Get or create shared threat detector instance.

    Returns:
        Shared ThreatDetector instance.
    """
    return _SharedDetectorSingleton().get_detector()


def set_shared_detector(detector: ThreatDetector) -> None:
    """
    Set the shared threat detector instance.

    Args:
        detector: ThreatDetector instance to share.
    """
    _SharedDetectorSingleton().set_detector(detector)


__all__ = [
    "ThreatDetectionMiddleware",
    "ThreatDetectionASGIMiddleware",
    "create_threat_detection_middleware",
    "get_shared_detector",
    "set_shared_detector",
]
