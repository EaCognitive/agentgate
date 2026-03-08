"""Cost analytics CLI commands."""

from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_json, print_kv
from .table_helpers import render_payload_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register cost analytics subcommands."""
    costs = subparsers.add_parser(
        "costs",
        help="Cost tracking and analytics",
    )
    sub = costs.add_subparsers(dest="costs_action")

    # summary (default)
    p = sub.add_parser(
        "summary",
        parents=[parent],
        help="Cost summary",
    )
    p.set_defaults(func=cmd_summary)

    # breakdown
    p = sub.add_parser(
        "breakdown",
        parents=[parent],
        help="Cost breakdown by tool",
    )
    p.set_defaults(func=cmd_breakdown)

    # agents
    p = sub.add_parser(
        "agents",
        parents=[parent],
        help="Cost breakdown by agent",
    )
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_agents)

    # timeline
    p = sub.add_parser(
        "timeline",
        parents=[parent],
        help="Cost over time",
    )
    p.add_argument("--hours", type=int, default=168, help="Hours (default 168 = 7d)")
    p.set_defaults(func=cmd_timeline)

    costs.add_argument("--json", action="store_true", dest="json", default=False)
    costs.add_argument("--url", default=None)
    costs.set_defaults(func=cmd_summary_default)


def cmd_summary_default(args: Namespace, client: DashboardClient) -> None:
    """Default: show summary."""
    cmd_summary(args, client)


def cmd_summary(args: Namespace, client: DashboardClient) -> None:
    """Show cost summary."""
    data = client.get("/api/costs/summary")
    if getattr(args, "json", False):
        print_json(data)
        return

    print("  Cost Summary")
    print()
    print_kv(
        [
            ("Total Cost", f"${data.get('total_cost', 0):.4f}"),
            ("Total Calls", data.get("total_calls", 0)),
            ("Avg / Call", f"${data.get('average_cost_per_call', 0):.4f}"),
            ("Period", f"{data.get('period_start', '?')} - {data.get('period_end', '?')}"),
        ]
    )


def cmd_breakdown(args: Namespace, client: DashboardClient) -> None:
    """Show cost breakdown by tool."""
    data = client.get("/api/costs/breakdown")
    if getattr(args, "json", False):
        print_json(data)
        return

    render_payload_table(
        data,
        items_key="breakdown",
        empty_message="No cost data available.",
        headers=["TOOL", "TOTAL", "AVG", "CALLS", "SUCCESS", "FAILED"],
        row_builder=lambda item: [
            item.get("tool", "-"),
            f"${item.get('total_cost', 0):.4f}",
            f"${item.get('average_cost', 0):.4f}",
            str(item.get("call_count", 0)),
            str(item.get("success_count", 0)),
            str(item.get("failed_count", 0)),
        ],
    )


def cmd_agents(args: Namespace, client: DashboardClient) -> None:
    """Show cost breakdown by agent."""
    data = client.get(
        "/api/costs/by-agent",
        params={"limit": args.limit},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    render_payload_table(
        data,
        items_key="agents",
        empty_message="No agent cost data.",
        headers=["AGENT", "TOTAL COST", "CALLS"],
        row_builder=lambda item: [
            item.get("agent_id", "-"),
            f"${item.get('total_cost', 0):.4f}",
            str(item.get("total_calls", 0)),
        ],
    )


def cmd_timeline(args: Namespace, client: DashboardClient) -> None:
    """Show cost over time."""
    data = client.get(
        "/api/costs/timeline",
        params={"hours": args.hours},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    render_payload_table(
        data,
        items_key="timeline",
        empty_message="No timeline data.",
        headers=["TIME", "COST", "CALLS"],
        row_builder=lambda item: [
            item.get("timestamp", "-")[:16],
            f"${item.get('total_cost', 0):.4f}",
            str(item.get("total_calls", 0)),
        ],
    )
