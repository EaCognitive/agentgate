"""Authentication CLI commands."""

import getpass
import sys
from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_error, print_json, print_ok


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register login / logout / whoami commands."""
    login_p = subparsers.add_parser(
        "login",
        parents=[parent],
        help="Authenticate with the AgentGate server",
    )
    login_p.add_argument("--email", "-e", help="Account email")
    login_p.add_argument("--password", "-p", help="Account password")
    login_p.set_defaults(func=cmd_login)

    logout_p = subparsers.add_parser(
        "logout",
        parents=[parent],
        help="Clear stored credentials",
    )
    logout_p.set_defaults(func=cmd_logout)

    whoami_p = subparsers.add_parser(
        "whoami",
        parents=[parent],
        help="Show current authenticated user",
    )
    whoami_p.set_defaults(func=cmd_whoami)


def cmd_login(args: Namespace, client: DashboardClient) -> None:
    """Authenticate and store session token."""
    email = args.email or input("Email: ")
    password = args.password or getpass.getpass("Password: ")

    if not email or not password:
        print_error("Email and password are required.")
        sys.exit(1)

    resp = client.login(email, password)
    if getattr(args, "json", False):
        print_json({"status": "ok", "email": email})
    else:
        role = resp.get("role", resp.get("user", {}).get("role", ""))
        print_ok(f"Logged in as {email}" + (f" ({role})" if role else ""))


def cmd_logout(args: Namespace, client: DashboardClient) -> None:
    """Clear session token."""
    client.logout()
    if getattr(args, "json", False):
        print_json({"status": "ok"})
    else:
        print_ok("Logged out.")


def cmd_whoami(args: Namespace, client: DashboardClient) -> None:
    """Display current session info."""
    if not client.token:
        print_error("Not authenticated. Run: ea-agentgate login")
        sys.exit(1)

    if getattr(args, "json", False):
        print_json({"url": client.base_url, "email": client.email})
    else:
        print_ok(f"Server:  {client.base_url}")
        print_ok(f"Email:   {client.email}")
