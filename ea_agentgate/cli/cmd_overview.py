"""Overview / dashboard stats CLI command."""

from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_json, print_kv


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register the overview command."""
    p = subparsers.add_parser(
        "overview",
        parents=[parent],
        help="Show dashboard overview stats (last 24h)",
    )
    p.set_defaults(func=cmd_overview)


def cmd_overview(args: Namespace, client: DashboardClient) -> None:
    """Fetch and display overview statistics."""
    data = client.get("/api/overview")

    if getattr(args, "json", False):
        print_json(data)
        return

    print("  AgentGate Overview (last 24h)")
    print()
    print_kv(
        [
            ("Total Calls", data.get("total_calls", 0)),
            ("Success Rate", f"{data.get('success_rate', 0)}%"),
            ("Blocked", data.get("blocked_count", 0)),
            ("Failed", data.get("failed_count", 0)),
            ("Total Cost", f"${data.get('total_cost', 0):.4f}"),
            ("Pending Approvals", data.get("pending_approvals", 0)),
        ]
    )
