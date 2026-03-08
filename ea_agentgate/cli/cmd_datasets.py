"""Dataset and test management CLI commands."""

import sys
import time
from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_error, print_json, print_ok, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register dataset subcommands."""
    ds = subparsers.add_parser(
        "datasets",
        help="Dataset and test case management",
    )
    sub = ds.add_subparsers(dest="datasets_action")

    # list
    p = sub.add_parser("list", parents=[parent], help="List datasets")
    p.set_defaults(func=cmd_list)

    # create
    p = sub.add_parser("create", parents=[parent], help="Create dataset")
    p.add_argument("--name", required=True)
    p.add_argument("--description", default="")
    p.set_defaults(func=cmd_create)

    # delete
    p = sub.add_parser("delete", parents=[parent], help="Delete dataset")
    p.add_argument("id", help="Dataset ID")
    p.set_defaults(func=cmd_delete)

    # tests
    p = sub.add_parser(
        "tests",
        parents=[parent],
        help="List test cases",
    )
    p.add_argument("id", help="Dataset ID")
    p.set_defaults(func=cmd_tests)

    # run
    p = sub.add_parser(
        "run",
        parents=[parent],
        help="Run all tests in dataset",
    )
    p.add_argument("id", help="Dataset ID")
    p.add_argument(
        "--wait",
        action="store_true",
        help="Wait for run to complete",
    )
    p.set_defaults(func=cmd_run)

    # export
    p = sub.add_parser(
        "export",
        parents=[parent],
        help="Export dataset as pytest file",
    )
    p.add_argument("id", help="Dataset ID")
    p.set_defaults(func=cmd_export)

    ds.add_argument("--json", action="store_true", dest="json", default=False)
    ds.add_argument("--url", default=None)
    ds.set_defaults(func=cmd_list_default)


def cmd_list_default(args: Namespace, client: DashboardClient) -> None:
    """Default: list datasets."""
    cmd_list(args, client)


def cmd_list(args: Namespace, client: DashboardClient) -> None:
    """List all datasets."""
    data = client.get("/api/datasets")
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data if isinstance(data, list) else data.get("items", [])
    if not items:
        print_ok("No datasets found.")
        return

    rows = []
    for ds in items:
        rate = ds.get("last_run_pass_rate")
        rate_str = f"{rate:.0f}%" if rate is not None else "-"
        rows.append(
            [
                str(ds.get("id", "-")),
                ds.get("name", "-"),
                str(ds.get("test_count", 0)),
                rate_str,
                (ds.get("last_run_at") or "-")[:19],
            ]
        )
    print_table(["ID", "NAME", "TESTS", "PASS RATE", "LAST RUN"], rows)


def cmd_create(args: Namespace, client: DashboardClient) -> None:
    """Create a new dataset."""
    data = client.post(
        "/api/datasets",
        body={
            "name": args.name,
            "description": args.description,
        },
    )
    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok(f"Dataset '{args.name}' created (id: {data.get('id', '?')}).")


def cmd_delete(args: Namespace, client: DashboardClient) -> None:
    """Delete a dataset."""
    client.delete(f"/api/datasets/{args.id}")
    if getattr(args, "json", False):
        print_json({"status": "deleted", "id": args.id})
    else:
        print_ok(f"Dataset {args.id} deleted.")


def cmd_tests(args: Namespace, client: DashboardClient) -> None:
    """List test cases for a dataset."""
    data = client.get(f"/api/datasets/{args.id}/tests")
    if getattr(args, "json", False):
        print_json(data)
        return

    items = data if isinstance(data, list) else data.get("items", [])
    if not items:
        print_ok(f"No test cases in dataset {args.id}.")
        return

    rows = []
    for tc in items:
        rows.append(
            [
                str(tc.get("id", "-")),
                tc.get("name", "-"),
                tc.get("tool", "-"),
                tc.get("status", "-"),
            ]
        )
    print_table(["ID", "NAME", "TOOL", "STATUS"], rows)


def cmd_run(args: Namespace, client: DashboardClient) -> None:
    """Run all tests in a dataset."""
    data = client.post(f"/api/datasets/{args.id}/runs")
    run_id = data.get("id", data.get("run_id"))

    if not getattr(args, "wait", False):
        if getattr(args, "json", False):
            print_json(data)
        else:
            print_ok(f"Test run started (run_id: {run_id}).")
        return

    # Poll until complete
    print_ok(f"Test run {run_id} started. Waiting...")
    for _ in range(120):
        time.sleep(2)
        status_data = client.get(
            f"/api/datasets/{args.id}/runs/{run_id}",
        )
        status = status_data.get("status", "")
        if status in ("completed", "failed", "cancelled"):
            if getattr(args, "json", False):
                print_json(status_data)
            else:
                passed = status_data.get("passed_tests", 0)
                failed = status_data.get("failed_tests", 0)
                total = status_data.get("total_tests", 0)
                print_ok(
                    f"Run complete: {passed}/{total} passed, {failed} failed ({status})",
                )
            return

    print_error("Timed out waiting for test run to complete.")
    sys.exit(1)


def cmd_export(args: Namespace, client: DashboardClient) -> None:
    """Export dataset as pytest file."""
    data = client.post(f"/api/datasets/{args.id}/export/pytest")
    if isinstance(data, str):
        print(data)
    elif isinstance(data, dict) and "code" in data:
        print(data["code"])
    else:
        print_json(data)
