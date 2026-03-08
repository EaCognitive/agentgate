"""AgentGate CLI -- full-featured command-line interface.

Every operation available in the web dashboard is also accessible here,
talking to the same backend API.  This ensures a single source of truth
and makes the platform fully automatable and AI-agent friendly.

Usage::

    ea-agentgate login
    ea-agentgate overview
    ea-agentgate pii detect "My SSN is 123-45-6789"
    ea-agentgate audit list --type login --limit 10
    ea-agentgate threats stats
    ea-agentgate users list --json
    ea-agentgate serve --port 8000
"""

import argparse
import importlib
import os
import sys

from ea_agentgate import __version__

from ..api_client import ApiError, DashboardClient
from .formatters import print_error

# Command module registrations (lazy-loaded on first parse)
_CMD_MODULES = [
    "ea_agentgate.cli.cmd_auth",
    "ea_agentgate.cli.cmd_overview",
    "ea_agentgate.cli.cmd_pii",
    "ea_agentgate.cli.cmd_audit",
    "ea_agentgate.cli.cmd_threats",
    "ea_agentgate.cli.cmd_users",
    "ea_agentgate.cli.cmd_costs",
    "ea_agentgate.cli.cmd_datasets",
    "ea_agentgate.cli.cmd_approvals",
    "ea_agentgate.cli.cmd_traces",
    "ea_agentgate.cli.cmd_settings",
    "ea_agentgate.cli.cmd_formal",
]


def _build_parser() -> argparse.ArgumentParser:
    """Build the complete argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="ea-agentgate",
        description=(
            "AgentGate CLI -- enterprise security gateway for AI agents.\n"
            "Full feature parity with the web dashboard."
        ),
        epilog=(
            "Every command supports --json for machine-readable output.\n"
            "Set AGENTGATE_URL to point to a remote server "
            "(default: http://localhost:8000)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # Shared parent parser for common flags
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json",
        action="store_true",
        dest="json",
        help="Output as JSON (machine-readable)",
    )
    common.add_argument(
        "--url",
        help="AgentGate server URL (default: $AGENTGATE_URL or localhost:8000)",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        description="Run 'ea-agentgate <command> --help' for details.",
    )

    # Built-in: serve
    serve_p = subparsers.add_parser(
        "serve",
        parents=[common],
        help="Start the AgentGate server",
    )
    serve_p.add_argument("--host", default=os.getenv("AGENTGATE_HOST", "127.0.0.1"))
    serve_p.add_argument("--port", type=int, default=8000)
    serve_p.add_argument("--reload", action="store_true")
    serve_p.add_argument("--workers", type=int, default=None)
    serve_p.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug"],
    )
    serve_p.set_defaults(func=_cmd_serve)

    # Register all command modules
    for module_path in _CMD_MODULES:
        mod = importlib.import_module(module_path)
        mod.register(subparsers, common)

    return parser


# ------------------------------------------------------------------
# Built-in command handlers
# ------------------------------------------------------------------


def _cmd_serve(args: argparse.Namespace, _client: DashboardClient) -> None:
    """Start the AgentGate server (uvicorn)."""
    try:
        uvicorn_module = importlib.import_module("uvicorn")
        server_mod = importlib.import_module("server.main")
        app = getattr(server_mod, "app")
    except (ImportError, AttributeError):
        print_error(
            "Could not import server module. Ensure the server package is installed.",
        )
        sys.exit(1)

    config: dict = {
        "app": app,
        "host": args.host,
        "port": args.port,
        "log_level": args.log_level.lower(),
    }
    if args.reload:
        config["reload"] = True
    if args.workers and args.workers > 1:
        config["workers"] = args.workers

    print(f"Starting AgentGate on {args.host}:{args.port}")
    print(f"Docs:  http://{args.host}:{args.port}/docs")
    getattr(uvicorn_module, "run")(**config)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    """Main CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)

    # Build client (only for commands that need it; serve ignores it)
    url = getattr(args, "url", None)
    client = DashboardClient(base_url=url) if url else DashboardClient()

    try:
        args.func(args, client)
    except ApiError as exc:
        print_error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
