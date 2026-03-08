"""Runtime Sentry initialization helpers."""

import logging
import os
from importlib import import_module
from typing import Any, Literal, cast

logger = logging.getLogger(__name__)

_SENTRY_SDK: Any | None = None
_FASTAPI_INTEGRATION: type[Any] | None = None
_STARLETTE_INTEGRATION: type[Any] | None = None
_SQLALCHEMY_INTEGRATION: type[Any] | None = None
_LOGGING_INTEGRATION: type[Any] | None = None

try:
    _SENTRY_SDK = import_module("sentry_sdk")
    _FASTAPI_INTEGRATION = getattr(
        import_module("sentry_sdk.integrations.fastapi"),
        "FastApiIntegration",
    )
    _STARLETTE_INTEGRATION = getattr(
        import_module("sentry_sdk.integrations.starlette"),
        "StarletteIntegration",
    )
    _SQLALCHEMY_INTEGRATION = getattr(
        import_module("sentry_sdk.integrations.sqlalchemy"),
        "SqlalchemyIntegration",
    )
    _LOGGING_INTEGRATION = getattr(
        import_module("sentry_sdk.integrations.logging"),
        "LoggingIntegration",
    )
except ImportError:
    _SENTRY_SDK = None

SentryLevel = Literal["fatal", "critical", "error", "warning", "info", "debug"]


class SentryManager:
    """Manages Sentry initialization and state."""

    initialized = False

    @classmethod
    def init(cls):
        """Initialize Sentry for error tracking.

        Only initializes in production if SENTRY_DSN is set.
        """
        sentry_dsn = os.getenv("SENTRY_DSN")

        if not sentry_dsn:
            logger.info("SENTRY_DSN not set - Sentry error tracking disabled")
            return

        if (
            _SENTRY_SDK is None
            or _FASTAPI_INTEGRATION is None
            or _STARLETTE_INTEGRATION is None
            or _SQLALCHEMY_INTEGRATION is None
            or _LOGGING_INTEGRATION is None
        ):
            logger.warning("sentry-sdk not installed - error tracking disabled")
            return

        try:
            # Configure logging integration
            sentry_logging = _LOGGING_INTEGRATION(
                level=logging.INFO,  # Capture info and above as breadcrumbs
                event_level=logging.ERROR,  # Send errors as events
            )

            _SENTRY_SDK.init(
                dsn=sentry_dsn,
                environment=os.getenv("AGENTGATE_ENV", "development"),
                release=f"ea-agentgate@{os.getenv('VERSION', '0.4.0')}",
                integrations=[
                    _FASTAPI_INTEGRATION(),
                    _STARLETTE_INTEGRATION(),
                    _SQLALCHEMY_INTEGRATION(),
                    sentry_logging,
                ],
                # Performance monitoring
                traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1")),
                # Error sampling
                sample_rate=1.0,  # Send all errors
                # PII filtering
                send_default_pii=False,  # Don't send PII by default
                # Max breadcrumbs
                max_breadcrumbs=50,
                # Attach stacktrace to messages
                attach_stacktrace=True,
                # Custom tags
                before_send=cast(Any, filter_sensitive_data),
            )

            logger.info("Sentry initialized for environment: %s", os.getenv("AGENTGATE_ENV"))
            cls.initialized = True

        except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
            logger.error("Failed to initialize Sentry: %s", exc)

    @classmethod
    def is_initialized(cls) -> bool:
        """Check if Sentry is initialized.

        Returns:
            True if Sentry is initialized and ready, False otherwise
        """
        return cls.initialized


# Backwards compatibility for the rest of the app
def init_sentry():
    """Wrapper for SentryManager.init."""
    SentryManager.init()


def filter_sensitive_data(event: dict[str, Any], hint: Any = None) -> dict[str, Any]:
    """Filter sensitive data before sending to Sentry."""
    _ = hint  # Unused
    # Remove sensitive headers
    if "request" in event and "headers" in event["request"]:
        headers = event["request"]["headers"]
        sensitive_headers = ["authorization", "cookie", "x-api-key"]
        for header in sensitive_headers:
            if header in headers:
                headers[header] = "[Filtered]"

    # Remove sensitive query params
    if "request" in event and "query_string" in event["request"]:
        query_string = event["request"]["query_string"]
        if query_string and ("password" in query_string.lower() or "token" in query_string.lower()):
            event["request"]["query_string"] = "[Filtered]"

    # Remove sensitive POST data
    if "request" in event and "data" in event["request"]:
        data = event["request"]["data"]
        if isinstance(data, dict):
            sensitive_keys = ["password", "secret", "token", "api_key", "credit_card"]
            for key in sensitive_keys:
                if key in data:
                    data[key] = "[Filtered]"

    return event


def capture_exception(error: Exception, context: dict | None = None):
    """Capture an exception with optional context.

    Args:
        error: The exception to capture
        context: Additional context to attach to the event
    """
    if _SENTRY_SDK is None:
        return

    try:
        with _SENTRY_SDK.push_scope() as scope:
            if context:
                for key, value in context.items():
                    scope.set_context(key, value)

            _SENTRY_SDK.capture_exception(error)
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        logger.error("Failed to capture exception in Sentry: %s", exc)


def capture_message(
    message: str,
    level: str = "info",
    context: dict | None = None,
) -> None:
    """Capture a message with optional context.

    Args:
        message: The message to capture
        level: Severity level (debug, info, warning, error, fatal)
        context: Additional context to attach to the message
    """
    if _SENTRY_SDK is None:
        return

    try:
        level_map: dict[str, SentryLevel] = {
            "fatal": "fatal",
            "critical": "critical",
            "error": "error",
            "warning": "warning",
            "info": "info",
            "debug": "debug",
        }
        sentry_level = level_map.get(level.lower(), "info")

        with _SENTRY_SDK.push_scope() as scope:
            if context:
                for key, value in context.items():
                    scope.set_context(key, value)

            _SENTRY_SDK.capture_message(message, level=sentry_level)
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        logger.error("Failed to capture message in Sentry: %s", exc)
