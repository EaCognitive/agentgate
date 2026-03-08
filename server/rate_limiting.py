"""Rate limiting configuration and middleware for FastAPI."""

import logging


from fastapi import Request
from fastapi.responses import JSONResponse, Response
from limits.errors import ConfigurationError
from slowapi import Limiter
from slowapi.util import get_ipaddr
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

from .config import get_settings

logger = logging.getLogger(__name__)


def create_limiter() -> Limiter:
    """Create and configure rate limiter with Redis or memory backend.

    Returns:
        Limiter: Configured rate limiter instance.

    Raises:
        RuntimeError: If production environment requires Redis but it's not configured.
    """
    settings = get_settings()
    storage_uri = settings.redis_url or "memory://"

    if settings.environment == "production" and storage_uri == "memory://":
        raise RuntimeError(
            "Production environment requires REDIS_URL for rate limiting. "
            "Set REDIS_URL to a valid Redis connection string. "
            "Per-process memory:// storage is unsafe in clustered deployments."
        )

    try:
        limiter_instance = Limiter(
            key_func=get_ipaddr,  # Use IP address for rate limiting
            storage_uri=storage_uri,
            strategy="moving-window",  # Better than fixed-window
            default_limits=["100/minute"],
            in_memory_fallback=["100/minute"],
            in_memory_fallback_enabled=True,
        )
        # Store storage_uri for test verification (dynamic attribute)
        setattr(limiter_instance, "storage_uri", storage_uri)
        return limiter_instance
    except ConfigurationError as exc:
        if settings.environment == "production":
            raise RuntimeError("Rate limiter configuration failed in production") from exc
        logger.warning("Limiter backend unavailable; falling back to in-memory storage")
        limiter_instance = Limiter(
            key_func=get_ipaddr,
            storage_uri="memory://",
            strategy="moving-window",
            default_limits=["100/minute"],
            in_memory_fallback=["100/minute"],
            in_memory_fallback_enabled=True,
        )
        # Store storage_uri for test verification (dynamic attribute)
        setattr(limiter_instance, "storage_uri", "memory://")
        return limiter_instance


async def rate_limit_exceeded_handler(request: Request, exc: Exception) -> Response:
    """Return a structured response for rate limit violations.

    Args:
        request: The incoming request that exceeded the rate limit.
        exc: The exception raised (typically RateLimitExceeded).

    Returns:
        JSONResponse with 429 status and rate limit headers.
    """
    # Extract detail from RateLimitExceeded or use default
    detail = getattr(exc, "detail", None) or "Rate limit exceeded"
    if not isinstance(detail, str):
        detail = str(detail)

    headers: dict[str, str] = {}
    limit_info = getattr(request.state, "view_rate_limit", None)
    try:
        if isinstance(limit_info, tuple) and len(limit_info) >= 3:
            headers["X-RateLimit-Limit"] = str(limit_info[0])
            headers["X-RateLimit-Remaining"] = str(limit_info[1])
            headers["X-RateLimit-Reset"] = str(limit_info[2])
        elif limit_info:
            headers["X-RateLimit-Limit"] = str(getattr(limit_info, "limit", ""))
            headers["X-RateLimit-Remaining"] = str(getattr(limit_info, "remaining", ""))
            headers["X-RateLimit-Reset"] = str(getattr(limit_info, "reset_time", ""))
    except (AttributeError, TypeError, ValueError):  # pragma: no cover - defensive only
        headers = {}

    return JSONResponse(
        status_code=HTTP_429_TOO_MANY_REQUESTS,
        content={"error": "rate_limit_exceeded", "detail": detail},
        headers=headers,
    )


async def rate_limit_headers_middleware(request: Request, call_next):
    """Add rate limit information headers to responses.

    Args:
        request: The incoming request.
        call_next: The next middleware or endpoint handler.

    Returns:
        Response with rate limit headers added if available.
    """
    response = await call_next(request)

    # Add rate limit headers if available
    if hasattr(request.state, "view_rate_limit"):
        limit_info = request.state.view_rate_limit
        # Handle both tuple and object formats from slowapi
        try:
            if isinstance(limit_info, tuple):
                # Tuple format: (limit, remaining, reset_time)
                if len(limit_info) >= 3:
                    response.headers["X-RateLimit-Limit"] = str(limit_info[0])
                    response.headers["X-RateLimit-Remaining"] = str(limit_info[1])
                    response.headers["X-RateLimit-Reset"] = str(limit_info[2])
            else:
                # Object format with attributes
                response.headers["X-RateLimit-Limit"] = str(limit_info.limit)
                response.headers["X-RateLimit-Remaining"] = str(limit_info.remaining)
                response.headers["X-RateLimit-Reset"] = str(limit_info.reset_time)
        except (AttributeError, IndexError, TypeError):
            # If we can't extract rate limit info, just skip adding headers
            pass

    return response
