"""CORS configuration for FastAPI following Enterprise Engineering Protocols 2026."""

import logging
import os

from .config import get_settings

logger = logging.getLogger(__name__)


def _development_origins() -> list[str]:
    """Return the standard local dashboard origins."""
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def _normalize_origins(raw_origins: str | list[str] | None) -> list[str]:
    """Normalize origins from env or settings into a clean list."""
    if isinstance(raw_origins, str):
        return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
    if isinstance(raw_origins, list):
        return [origin.strip() for origin in raw_origins if origin.strip()]
    return []


def get_allowed_origins() -> list[str]:
    """Get allowed CORS origins from environment or use development defaults.

    Returns:
        List of allowed CORS origin URLs.

    Notes:
        - Production requires explicit ALLOWED_ORIGINS environment variable
        - Development defaults to localhost:3000 if not set
        - Origins are comma-separated in ALLOWED_ORIGINS env var
    """
    env_override = os.environ.get("ALLOWED_ORIGINS")
    if env_override is not None:
        return _normalize_origins(env_override)

    env_value = os.getenv("AGENTGATE_ENV", "").strip().lower()
    if env_value == "production":
        return []
    if env_value == "development":
        return _development_origins()

    get_settings.cache_clear()
    current_settings = get_settings()
    normalized_origins = _normalize_origins(current_settings.model_dump().get("allowed_origins"))
    if normalized_origins:
        return normalized_origins
    if current_settings.environment == "development":
        return _development_origins()
    logger.warning("ALLOWED_ORIGINS not set in production - using restrictive defaults")
    return []
