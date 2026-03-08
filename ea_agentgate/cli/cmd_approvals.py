"""Approval workflow CLI commands."""

import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_error, print_json, print_ok, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register approval subcommands."""
    approvals = subparsers.add_parser(
        "approvals",
        help="Approval workflows (human-in-the-loop)",
    )
    sub = approvals.add_subparsers(dest="approvals_action")

    # pending (default)
    p = sub.add_parser(
        "pending",
        parents=[parent],
        help="List pending approvals",
    )
    p.set_defaults(func=cmd_pending)

    # history
    p = sub.add_parser(
        "history",
        parents=[parent],
        help="Approval history",
    )
    p.add_argument("--status", choices=["approved", "denied", "expired"])
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    # approve
    p = sub.add_parser(
        "approve",
        parents=[parent],
        help="Approve a request",
    )
    p.add_argument("id", help="Approval ID")
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_approve)

    # deny
    p = sub.add_parser(
        "deny",
        parents=[parent],
        help="Deny a request",
    )
    p.add_argument("id", help="Approval ID")
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_deny)

    approvals.add_argument("--json", action="store_true", dest="json", default=False)
    approvals.add_argument("--url", default=None)
    approvals.set_defaults(func=cmd_pending_default)


def cmd_pending_default(args: Namespace, client: DashboardClient) -> None:
    """Default: list pending approvals."""
    cmd_pending(args, client)


def cmd_pending(args: Namespace, client: DashboardClient) -> None:
    """List pending approval requests."""
    data = client.get("/api/approvals/pending")
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data if isinstance(data, list) else data.get("items", [])
    if not items:
        print_ok("No pending approvals.")
        return

    rows = []
    for item in items:
        rows.append(
            [
                str(item.get("id", item.get("approval_id", "-"))),
                item.get("tool", "-"),
                item.get("created_at", "-")[:19],
                item.get("inputs", {}).get("agent_id", "-")
                if isinstance(item.get("inputs"), dict)
                else "-",
            ]
        )
    print_table(["ID", "TOOL", "REQUESTED", "AGENT"], rows)


def cmd_history(args: Namespace, client: DashboardClient) -> None:
    """List approval history."""
    params: dict = {"page_size": args.limit}
    if getattr(args, "status", None):
        params["status"] = args.status

    data = client.get("/api/approvals", params=params)
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data.get("items", []) if isinstance(data, dict) else data
    if not items:
        print_ok("No approval history.")
        return

    rows = []
    for item in items:
        rows.append(
            [
                str(item.get("id", item.get("approval_id", "-"))),
                item.get("tool", "-"),
                item.get("status", "-"),
                item.get("decided_by", "-") or "-",
                (item.get("decided_at") or "-")[:19],
            ]
        )
    print_table(
        ["ID", "TOOL", "STATUS", "DECIDED BY", "DECIDED AT"],
        rows,
    )


def _decide(
    args: Namespace,
    client: DashboardClient,
    approved: bool,
    label: str,
) -> None:
    """Submit approval decision."""
    if not args.id:
        print_error("Approval ID is required.")
        sys.exit(1)

    body: dict = {"approved": approved}
    if getattr(args, "reason", ""):
        body["reason"] = args.reason

    data = client.post(f"/api/approvals/{args.id}/decide", body=body)
    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok(f"Approval {args.id} {label}.")


def cmd_approve(args: Namespace, client: DashboardClient) -> None:
    """Approve a pending request."""
    _decide(args, client, True, "approved")


def cmd_deny(args: Namespace, client: DashboardClient) -> None:
    """Deny a pending request."""
    _decide(args, client, False, "denied")
