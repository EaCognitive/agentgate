"""Trace monitoring CLI commands."""

from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_json, print_ok, print_table
from .table_helpers import render_payload_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register trace subcommands."""
    traces = subparsers.add_parser(
        "traces",
        help="Tool execution trace monitoring",
    )
    sub = traces.add_subparsers(dest="traces_action")

    # list (default)
    p = sub.add_parser("list", parents=[parent], help="List traces")
    p.add_argument(
        "--status",
        choices=["pending", "running", "success", "failed", "blocked"],
    )
    p.add_argument("--tool", help="Filter by tool name")
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--page", type=int, default=1)
    p.set_defaults(func=cmd_list)

    # timeline
    p = sub.add_parser(
        "timeline",
        parents=[parent],
        help="Trace timeline",
    )
    p.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours (default 24)",
    )
    p.set_defaults(func=cmd_timeline)

    traces.add_argument("--json", action="store_true", dest="json", default=False)
    traces.add_argument("--url", default=None)
    traces.set_defaults(func=cmd_list_default)


def cmd_list_default(args: Namespace, client: DashboardClient) -> None:
    """Default: list recent traces."""
    args.status = None
    args.tool = None
    args.limit = 20
    args.page = 1
    cmd_list(args, client)


def cmd_list(args: Namespace, client: DashboardClient) -> None:
    """List tool execution traces."""
    params: dict = {
        "page": args.page,
        "limit": args.limit,
    }
    if getattr(args, "status", None):
        params["status"] = args.status
    if getattr(args, "tool", None):
        params["tool"] = args.tool

    data = client.get("/api/traces", params=params)
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data.get("items", []) if isinstance(data, dict) else data
    if not items:
        print_ok("No traces found.")
        return

    rows = []
    for trace in items:
        rows.append(
            [
                str(trace.get("id", "-")),
                trace.get("tool", "-"),
                trace.get("status", "-"),
                f"${trace.get('cost', 0):.4f}",
                f"{trace.get('duration_ms', 0)}ms",
                trace.get("started_at", "-")[:19],
            ]
        )
    print_table(
        ["ID", "TOOL", "STATUS", "COST", "DURATION", "STARTED"],
        rows,
    )
    total = data.get("total", len(items)) if isinstance(data, dict) else len(items)
    print(f"\n  {total} total traces (page {args.page})")


def cmd_timeline(args: Namespace, client: DashboardClient) -> None:
    """Show trace timeline."""
    data = client.get(
        "/api/traces/timeline",
        params={"hours": args.hours},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    render_payload_table(
        data,
        items_key="timeline",
        empty_message="No timeline data.",
        headers=["TIME", "TOTAL", "SUCCESS", "FAILED", "BLOCKED"],
        row_builder=lambda item: [
            item.get("timestamp", "-")[:16],
            str(item.get("total_calls", 0)),
            str(item.get("success_count", 0)),
            str(item.get("failed_count", 0)),
            str(item.get("blocked_count", 0)),
        ],
    )
