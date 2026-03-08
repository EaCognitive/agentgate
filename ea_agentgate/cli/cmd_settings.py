"""System settings CLI commands."""

from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_json, print_kv, print_ok


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register settings subcommands."""
    settings = subparsers.add_parser(
        "settings",
        help="System configuration",
    )
    sub = settings.add_subparsers(dest="settings_action")

    # get (default)
    p = sub.add_parser(
        "get",
        parents=[parent],
        help="Show current settings",
    )
    p.set_defaults(func=cmd_get)

    # update
    p = sub.add_parser(
        "update",
        parents=[parent],
        help="Update a setting",
    )
    p.add_argument("--key", required=True, help="Setting key")
    p.add_argument("--value", required=True, help="Setting value")
    p.set_defaults(func=cmd_update)

    settings.add_argument("--json", action="store_true", dest="json", default=False)
    settings.add_argument("--url", default=None)
    settings.set_defaults(func=cmd_get_default)


def cmd_get_default(args: Namespace, client: DashboardClient) -> None:
    """Default: show settings."""
    cmd_get(args, client)


def cmd_get(args: Namespace, client: DashboardClient) -> None:
    """Show current system settings."""
    data = client.get("/api/settings")
    if getattr(args, "json", False):
        print_json(data)
        return

    settings = data if isinstance(data, dict) else {}
    if not settings:
        print_ok("No settings configured.")
        return
    # Filter out internal/meta keys
    settings.pop("id", None)
    settings.pop("created_at", None)
    settings.pop("updated_at", None)

    print("  System Settings")
    print()
    pairs = list(sorted(settings.items()))
    print_kv(pairs)


def cmd_update(args: Namespace, client: DashboardClient) -> None:
    """Update a system setting."""
    # Fetch current settings, merge, then PUT
    current = client.get("/api/settings")
    if not isinstance(current, dict):
        current = {}

    # Try to parse numeric/boolean values
    value: object = args.value
    if args.value.lower() in ("true", "false"):
        value = args.value.lower() == "true"
    else:
        try:
            value = int(args.value)
        except ValueError:
            try:
                value = float(args.value)
            except ValueError:
                pass

    current[args.key] = value
    data = client.put("/api/settings", body=current)

    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok(f"Setting '{args.key}' updated to '{args.value}'.")
