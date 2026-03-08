"""Standalone MCP server entry point.

Usage:
    python -m server.mcp          # stdio transport (Claude Desktop)
    python -m server.mcp --sse    # SSE transport (production)
"""

from __future__ import annotations

import argparse
from importlib import import_module
import logging
import os
import sys


def _configure_mcp_logging() -> None:
    """Set MCP logger verbosity from MCP_LOG_LEVEL (default: WARNING)."""
    level_name = os.getenv("MCP_LOG_LEVEL", "WARNING").upper()
    level = getattr(logging, level_name, logging.WARNING)
    for logger_name in ("mcp", "mcp.server", "server.mcp"):
        logging.getLogger(logger_name).setLevel(level)


def main() -> None:
    """Run the MCP server in standalone mode."""
    _configure_mcp_logging()

    parser = argparse.ArgumentParser(description="AgentGate Security MCP Server")
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Use SSE transport instead of stdio",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Use streamable HTTP transport instead of stdio",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8100,
        help="Port for SSE transport (default: 8100)",
    )
    args = parser.parse_args()

    try:
        create_server = getattr(import_module("server.mcp.server"), "create_server")
    except ModuleNotFoundError as exc:
        if exc.name == "mcp":
            print(
                "Missing dependency 'mcp'. Install server extras first:\n"
                "  uv sync --extra server\n"
                "or run with:\n"
                "  uv run --extra server python -m server.mcp",
                file=sys.stderr,
            )
            raise SystemExit(2) from exc
        raise
    uvicorn = import_module("uvicorn")

    server = create_server()

    if args.http:
        uvicorn.run(
            server.streamable_http_app(),
            host="127.0.0.1",
            port=args.port,
        )
    elif args.sse:
        uvicorn.run(
            server.sse_app(),
            host="127.0.0.1",
            port=args.port,
        )
    else:
        server.run(transport="stdio")


if __name__ == "__main__":
    main()
