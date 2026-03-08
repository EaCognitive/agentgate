"""Read-only MCP resources backed by the AgentGate REST API.

Each resource proxies through the authenticated API client so that
requests pass through the full middleware stack (RBAC, rate limiting,
audit logging, threat detection). The only exception is alerts/summary
which reads runtime state directly from the in-process detector.
"""

from __future__ import annotations

import json
import logging

from server.middleware.threat_detection import get_shared_detector

from .api_client import MCPApiClientError, get_api_client
from .auth_session import auth_error_payload, require_mcp_auth

logger = logging.getLogger(__name__)


def _get_detector_alert_manager() -> object:
    """Return the shared detector alert manager."""
    detector = get_shared_detector()
    return getattr(detector, "_alert_manager", None)


def _count_configured_channels(manager: object) -> int:
    """Return the number of configured alert channels."""
    channels = getattr(manager, "_channels", [])
    return len(channels) if isinstance(channels, list) else 0


async def get_recent_threats_resource() -> str:
    """Retrieve the most recent security threats via the REST API.

    Returns:
        JSON string containing a list of threat records.
    """
    try:
        await require_mcp_auth()
        client = get_api_client()
        result = await client.get(
            "/api/security/threats",
            params={"limit": 50},
        )
        return json.dumps(result, indent=2, default=str)
    except MCPApiClientError as exc:
        logger.error("Failed to retrieve recent threats: %s", exc)
        return json.dumps(auth_error_payload(exc, "get_recent_threats"), indent=2)


async def get_threat_stats() -> str:
    """Retrieve threat statistics via the REST API.

    Returns:
        JSON string containing severity counts and trend data.
    """
    try:
        await require_mcp_auth()
        client = get_api_client()
        result = await client.get("/api/security/threats/stats")
        return json.dumps(result, indent=2, default=str)
    except MCPApiClientError as exc:
        logger.error("Failed to retrieve threat stats: %s", exc)
        return json.dumps(auth_error_payload(exc, "get_threat_stats"), indent=2)


async def get_threat_timeline() -> str:
    """Retrieve hourly threat timeline via the REST API.

    Returns:
        JSON string containing hourly bucketed threat counts.
    """
    try:
        await require_mcp_auth()
        client = get_api_client()
        result = await client.get(
            "/api/security/threats/timeline",
        )
        return json.dumps(result, indent=2, default=str)
    except MCPApiClientError as exc:
        logger.error(
            "Failed to retrieve threat timeline: %s",
            exc,
        )
        return json.dumps(
            auth_error_payload(exc, "get_threat_timeline"),
            indent=2,
        )


async def get_blocked_ips() -> str:
    """Retrieve currently blocked IP addresses via the REST API.

    Returns:
        JSON string containing blocked IP details.
    """
    try:
        await require_mcp_auth()
        client = get_api_client()
        result = await client.get(
            "/api/security/threats/blocked-ips",
        )
        return json.dumps(result, indent=2, default=str)
    except MCPApiClientError as exc:
        logger.error("Failed to retrieve blocked IPs: %s", exc)
        return json.dumps(auth_error_payload(exc, "get_blocked_ips"), indent=2)


async def get_detector_stats() -> str:
    """Retrieve threat detector engine statistics via the REST API.

    Returns:
        JSON string containing detection check counts.
    """
    try:
        await require_mcp_auth()
        client = get_api_client()
        result = await client.get(
            "/api/security/threats/detector-stats",
        )
        return json.dumps(result, indent=2, default=str)
    except MCPApiClientError as exc:
        logger.error(
            "Failed to retrieve detector stats: %s",
            exc,
        )
        return json.dumps(
            auth_error_payload(exc, "get_detector_stats"),
            indent=2,
        )


async def get_alerts_summary() -> str:
    """Retrieve alert manager statistics from in-process state.

    This resource reads directly from the runtime detector because
    alert manager stats are ephemeral in-process counters with no
    corresponding REST endpoint.

    Returns:
        JSON string containing alert delivery metrics.
    """
    try:
        await require_mcp_auth()
        manager = _get_detector_alert_manager()
        if manager is None:
            raise RuntimeError("Alert manager is not available")
        raw = manager.stats

        total_sent = raw.get(
            "total_sent",
            raw.get("alerts_sent", 0),
        )
        total_suppressed = raw.get(
            "total_suppressed",
            raw.get("alerts_suppressed", 0),
        )
        total_deduplicated = raw.get(
            "total_deduplicated",
            raw.get("alerts_deduplicated", 0),
        )
        channels_configured = raw.get(
            "channels_configured",
            _count_configured_channels(manager),
        )

        return json.dumps(
            {
                "total_sent": total_sent,
                "total_suppressed": total_suppressed,
                "total_deduplicated": total_deduplicated,
                "channels_configured": channels_configured,
            },
            indent=2,
        )

    except MCPApiClientError as exc:
        logger.error(
            "Failed to authenticate for alerts summary: %s",
            exc,
        )
        return json.dumps(
            auth_error_payload(exc, "get_alerts_summary"),
            indent=2,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.error(
            "Failed to retrieve alerts summary: %s",
            exc,
        )
        return json.dumps(
            {
                "error": "Failed to retrieve alerts summary",
                "details": str(exc),
            }
        )
