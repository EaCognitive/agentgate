"""User management CLI commands."""

import getpass
import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_error, print_json, print_ok, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register user management subcommands."""
    users = subparsers.add_parser(
        "users",
        help="User administration",
    )
    sub = users.add_subparsers(dest="users_action")

    # list
    p = sub.add_parser("list", parents=[parent], help="List all users")
    p.set_defaults(func=cmd_list)

    # create
    p = sub.add_parser("create", parents=[parent], help="Create a user")
    p.add_argument("--email", required=True)
    p.add_argument("--name", required=True)
    p.add_argument(
        "--role",
        default="viewer",
        choices=["admin", "operator", "auditor", "developer", "viewer"],
    )
    p.add_argument("--password", help="User password (prompted if omitted)")
    p.set_defaults(func=cmd_create)

    # update
    p = sub.add_parser("update", parents=[parent], help="Update a user")
    p.add_argument("id", help="User ID")
    p.add_argument(
        "--role",
        choices=[
            "admin",
            "operator",
            "auditor",
            "developer",
            "viewer",
        ],
    )
    p.add_argument(
        "--active",
        dest="is_active",
        action="store_true",
        default=None,
    )
    p.add_argument(
        "--inactive",
        dest="is_active",
        action="store_false",
    )
    p.set_defaults(func=cmd_update)

    # Add common flags to top-level parser for bare `ea-agentgate users`
    users.add_argument("--json", action="store_true", dest="json", default=False)
    users.add_argument("--url", default=None)
    # Default: list
    users.set_defaults(func=cmd_list_default)


def cmd_list_default(args: Namespace, client: DashboardClient) -> None:
    """Default: list users."""
    cmd_list(args, client)


def cmd_list(args: Namespace, client: DashboardClient) -> None:
    """List all users."""
    data = client.get("/api/users")
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data if isinstance(data, list) else data.get("items", data.get("users", []))
    if not items:
        print_ok("No users found.")
        return

    rows = []
    for user in items:
        active = "active" if user.get("is_active", True) else "inactive"
        rows.append(
            [
                str(user.get("id", "-")),
                user.get("email", "-"),
                user.get("name", "-"),
                user.get("role", "-"),
                active,
            ]
        )
    print_table(["ID", "EMAIL", "NAME", "ROLE", "STATUS"], rows)


def cmd_create(args: Namespace, client: DashboardClient) -> None:
    """Create a new user."""
    password = args.password or getpass.getpass("Password: ")
    if not password:
        print_error("Password is required.")
        sys.exit(1)

    data = client.post(
        "/api/users",
        body={
            "email": args.email,
            "name": args.name,
            "role": args.role,
            "password": password,
        },
    )
    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok(f"User {args.email} created (role: {args.role}).")


def cmd_update(args: Namespace, client: DashboardClient) -> None:
    """Update user role or status."""
    body: dict = {}
    if args.role:
        body["role"] = args.role
    if args.is_active is not None:
        body["is_active"] = args.is_active

    if not body:
        print_error("Specify --role or --active/--inactive.")
        sys.exit(1)

    data = client.patch(f"/api/users/{args.id}", body=body)
    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok(f"User {args.id} updated.")
