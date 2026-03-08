"""Audit log CLI commands."""

from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_json, print_ok, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register audit subcommands."""
    audit = subparsers.add_parser(
        "audit",
        help="View and export audit log entries",
    )
    sub = audit.add_subparsers(dest="audit_action")

    # list (default)
    p = sub.add_parser(
        "list",
        parents=[parent],
        help="List audit log entries",
    )
    p.add_argument("--type", dest="event_type", help="Filter by event type")
    p.add_argument("--actor", help="Filter by actor email")
    p.add_argument("--result", choices=["success", "failure"])
    p.add_argument("--limit", type=int, default=20)
    p.add_argument("--page", type=int, default=1)
    p.set_defaults(func=cmd_list)

    # export
    p = sub.add_parser(
        "export",
        parents=[parent],
        help="Export audit log",
    )
    p.add_argument(
        "format",
        choices=["csv", "json"],
        help="Export format",
    )
    p.set_defaults(func=cmd_export)

    audit.add_argument("--json", action="store_true", dest="json", default=False)
    audit.add_argument("--url", default=None)
    audit.set_defaults(func=cmd_list_default, _parser=audit)


def cmd_list_default(args: Namespace, client: DashboardClient) -> None:
    """Default audit action: list entries."""
    args.event_type = None
    args.actor = None
    args.result = None
    args.limit = 20
    args.page = 1
    cmd_list(args, client)


def cmd_list(args: Namespace, client: DashboardClient) -> None:
    """List audit log entries with optional filters."""
    params: dict = {
        "page": args.page,
        "page_size": args.limit,
        "limit": args.limit,
    }
    if getattr(args, "event_type", None):
        params["event_type"] = args.event_type
    if getattr(args, "actor", None):
        params["actor"] = args.actor
    if getattr(args, "result", None):
        params["result"] = args.result

    data = client.get("/api/audit", params=params)
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data.get("items", []) if isinstance(data, dict) else data
    total = data.get("total", len(items)) if isinstance(data, dict) else len(items)

    if not items:
        print_ok("No audit entries found.")
        return

    rows = []
    for entry in items:
        rows.append(
            [
                entry.get("timestamp", "-")[:19],
                entry.get("event_type", "-"),
                entry.get("actor", "-"),
                entry.get("tool", "-") or "-",
                entry.get("result", "-"),
            ]
        )
    print_table(
        ["TIMESTAMP", "EVENT TYPE", "ACTOR", "TOOL", "RESULT"],
        rows,
    )
    print(f"\n  {total} total entries (page {args.page})")


def cmd_export(args: Namespace, client: DashboardClient) -> None:
    """Export audit log as CSV or JSON."""
    data = client.get(
        "/api/audit/export",
        params={"format": args.format},
    )
    if isinstance(data, str):
        print(data)
    else:
        print_json(data)
