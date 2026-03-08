"""Security threat CLI commands."""

import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_error, print_json, print_kv, print_ok, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register threat subcommands."""
    threats = subparsers.add_parser(
        "threats",
        help="Security threat monitoring and response",
    )
    sub = threats.add_subparsers(dest="threats_action")

    # list
    p = sub.add_parser("list", parents=[parent], help="List threats")
    p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
    )
    p.add_argument(
        "--status",
        choices=["pending", "acknowledged", "resolved", "dismissed"],
    )
    p.set_defaults(func=cmd_list)

    # stats
    p = sub.add_parser(
        "stats",
        parents=[parent],
        help="Threat statistics",
    )
    p.set_defaults(func=cmd_stats)

    # ack
    p = sub.add_parser(
        "ack",
        parents=[parent],
        help="Acknowledge a threat",
    )
    p.add_argument("id", help="Threat ID")
    p.set_defaults(func=cmd_ack)

    # resolve
    p = sub.add_parser(
        "resolve",
        parents=[parent],
        help="Resolve a threat",
    )
    p.add_argument("id", help="Threat ID")
    p.set_defaults(func=cmd_resolve)

    # dismiss
    p = sub.add_parser(
        "dismiss",
        parents=[parent],
        help="Dismiss a threat",
    )
    p.add_argument("id", help="Threat ID")
    p.set_defaults(func=cmd_dismiss)

    threats.add_argument("--json", action="store_true", dest="json", default=False)
    threats.add_argument("--url", default=None)
    threats.set_defaults(func=cmd_list_default)


def cmd_list_default(args: Namespace, client: DashboardClient) -> None:
    """Default: list all threats."""
    args.severity = None
    args.status = None
    cmd_list(args, client)


def cmd_list(args: Namespace, client: DashboardClient) -> None:
    """List threat events with optional filters."""
    params: dict = {}
    if getattr(args, "severity", None):
        params["severity"] = args.severity
    if getattr(args, "status", None):
        params["status"] = args.status

    data = client.get("/api/security/threats", params=params)
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data if isinstance(data, list) else data.get("items", [])
    if not items:
        print_ok("No threats found.")
        return

    rows = []
    for threat in items:
        rows.append(
            [
                str(threat.get("id", "-")),
                threat.get("detected_at", threat.get("timestamp", "-"))[:19],
                threat.get("severity", "-"),
                threat.get("attack_type", threat.get("event_type", threat.get("type", "-"))),
                threat.get("status", "-"),
                threat.get("source_ip", "-"),
            ]
        )
    print_table(
        ["ID", "DETECTED", "SEVERITY", "TYPE", "STATUS", "SOURCE IP"],
        rows,
    )


def cmd_stats(args: Namespace, client: DashboardClient) -> None:
    """Show threat statistics."""
    data = client.get("/api/security/threats/stats")
    if getattr(args, "json", False):
        print_json(data)
        return

    print("  Threat Statistics")
    print()
    print_kv(
        [
            ("Total", data.get("total", 0)),
            ("Critical", data.get("critical", 0)),
            ("High", data.get("high", 0)),
            ("Medium", data.get("medium", 0)),
            ("Low", data.get("low", 0)),
            ("Resolved", data.get("resolved", 0)),
            ("Pending", data.get("pending", 0)),
        ]
    )


def _action(
    args: Namespace,
    client: DashboardClient,
    action: str,
    label: str,
) -> None:
    """Perform a threat action (ack/resolve/dismiss)."""
    if not args.id:
        print_error("Threat ID is required.")
        sys.exit(1)
    data = client.post(f"/api/security/threats/{args.id}/{action}")
    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok(f"Threat {args.id} {label}.")


def cmd_ack(args: Namespace, client: DashboardClient) -> None:
    """Acknowledge a threat."""
    _action(args, client, "ack", "acknowledged")


def cmd_resolve(args: Namespace, client: DashboardClient) -> None:
    """Resolve a threat."""
    _action(args, client, "resolve", "resolved")


def cmd_dismiss(args: Namespace, client: DashboardClient) -> None:
    """Dismiss a threat."""
    _action(args, client, "dismiss", "dismissed")
