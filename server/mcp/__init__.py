"""
MCP (Model Context Protocol) server for AgentGate security operations.

Exposes threat detection, IP blocking, governance, and AI-enhanced
security tools as MCP resources and tools for AI assistants.
"""

from __future__ import annotations

from importlib import import_module
import logging
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP
    from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


def create_mcp_server() -> "FastMCP":
    """Create and configure the MCP server instance.

    Returns:
        Configured FastMCP server with all resources and tools.
    """
    server_module = import_module("server.mcp.server")
    return server_module.create_server()


def create_mcp_app() -> "ASGIApp":
    """Create an ASGI-mountable MCP application.

    Returns:
        ASGI application suitable for mounting on FastAPI.
    """
    server = create_mcp_server()
    return cast("ASGIApp", server.sse_app())


__all__ = [
    "create_mcp_server",
    "create_mcp_app",
]
