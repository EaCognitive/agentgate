"""PII detection, redaction, and vault CLI commands."""

from argparse import ArgumentParser, Namespace, _SubParsersAction

from ..api_client import DashboardClient
from .formatters import print_json, print_kv, print_ok, print_table


def register(subparsers: _SubParsersAction, parent: ArgumentParser) -> None:
    """Register pii subcommands."""
    pii = subparsers.add_parser(
        "pii",
        help="PII detection, redaction, and vault operations",
    )
    sub = pii.add_subparsers(dest="pii_action")

    # detect
    p = sub.add_parser("detect", parents=[parent], help="Detect PII in text")
    p.add_argument("text", help="Text to analyse for PII entities")
    p.set_defaults(func=cmd_detect)

    # redact
    p = sub.add_parser("redact", parents=[parent], help="Redact PII from text")
    p.add_argument("text", help="Text to redact")
    p.add_argument(
        "--session-id",
        required=True,
        help="PII session ID. Create a session first via 'ops pii sessions' API workflow.",
    )
    p.set_defaults(func=cmd_redact)

    # restore
    p = sub.add_parser("restore", parents=[parent], help="Restore tokenized PII text")
    p.add_argument("text", help="Redacted text that includes <TYPE_N> tokens")
    p.add_argument(
        "--session-id",
        required=True,
        help="PII session ID used when the text was redacted",
    )
    p.set_defaults(func=cmd_restore)

    # stats
    p = sub.add_parser(
        "stats",
        parents=[parent],
        help="PII vault statistics",
    )
    p.set_defaults(func=cmd_stats)

    # compliance
    p = sub.add_parser(
        "compliance",
        parents=[parent],
        help="HIPAA / SOC 2 compliance status",
    )
    p.set_defaults(func=cmd_compliance)

    # audit
    p = sub.add_parser(
        "audit",
        parents=[parent],
        help="PII vault audit log",
    )
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_audit)

    # sessions
    p = sub.add_parser(
        "sessions",
        parents=[parent],
        help="PII handling sessions",
    )
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_sessions)

    # rotate-keys
    p = sub.add_parser(
        "rotate-keys",
        parents=[parent],
        help="Rotate PII vault encryption keys",
    )
    p.set_defaults(func=cmd_rotate_keys)

    pii.add_argument("--json", action="store_true", dest="json", default=False)
    pii.add_argument("--url", default=None)
    pii.set_defaults(func=_pii_help, _parser=pii)


def _pii_help(args: Namespace, _client: DashboardClient) -> None:
    """Show PII subcommand help."""
    parser = getattr(args, "_parser", None)
    if parser is not None:
        parser.print_help()


def cmd_detect(args: Namespace, client: DashboardClient) -> None:
    """Detect PII entities in text."""
    data = client.post("/api/pii/detect", body={"text": args.text})
    if getattr(args, "json", False):
        print_json(data)
        return

    entities = data.get("detections") or data.get("entities") or data.get("results") or []
    if not entities:
        print_ok("No PII detected.")
        return

    print(f"  Detected {len(entities)} PII entities:")
    print()
    rows = []
    for ent in entities:
        rows.append(
            [
                ent.get("type", ent.get("entity_type", "-")),
                f"[{ent.get('start', '?')}:{ent.get('end', '?')}]",
                str(round(ent.get("score", 0), 2)),
                ent.get("value", ""),
            ]
        )
    print_table(["TYPE", "SPAN", "SCORE", "VALUE"], rows)


def cmd_redact(args: Namespace, client: DashboardClient) -> None:
    """Redact PII from text."""
    data = client.post(
        "/api/pii/redact",
        body={"text": args.text, "session_id": args.session_id},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    print_ok("Redacted text:")
    print(f"  {data.get('redacted_text', data.get('text', '-'))}")
    count = data.get("entities_found", data.get("pii_count", 0))
    if count:
        print(f"  ({count} entities redacted)")


def cmd_restore(args: Namespace, client: DashboardClient) -> None:
    """Restore tokenized PII placeholders in text."""
    data = client.post(
        "/api/pii/restore",
        body={"text": args.text, "session_id": args.session_id},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    print_ok("Restored text:")
    print(f"  {data.get('restored_text', data.get('text', '-'))}")


def cmd_stats(args: Namespace, client: DashboardClient) -> None:
    """Show PII vault statistics."""
    data = client.get("/api/pii/stats")
    if getattr(args, "json", False):
        print_json(data)
        return

    print("  PII Vault Statistics")
    print()
    print_kv(
        [
            ("Total Stored", data.get("total_stored", 0)),
            ("Active Sessions", data.get("active_sessions", 0)),
            ("Integrity Failures", data.get("integrity_failures", 0)),
            ("Key Age (days)", data.get("key_age_days", "-")),
        ]
    )


def cmd_compliance(args: Namespace, client: DashboardClient) -> None:
    """Show HIPAA and SOC 2 compliance status."""
    data = client.get("/api/pii/compliance")
    if getattr(args, "json", False):
        print_json(data)
        return

    hipaa = data.get("hipaa", {})
    soc2 = data.get("soc2", {})

    print("  Compliance Status")
    print()
    print("  HIPAA:")
    for check in hipaa.get("checks", []):
        status = "PASS" if check.get("passed") else "FAIL"
        print(f"    [{status}] {check.get('name', '-')}")

    print()
    print("  SOC 2:")
    for check in soc2.get("checks", []):
        status = "PASS" if check.get("passed") else "FAIL"
        print(f"    [{status}] {check.get('name', '-')}")


def cmd_audit(args: Namespace, client: DashboardClient) -> None:
    """Show PII vault audit log."""
    data = client.get(
        "/api/pii/audit",
        params={"limit": args.limit},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    entries = data if isinstance(data, list) else data.get("items", [])
    if not entries:
        print_ok("No PII audit entries.")
        return

    rows = []
    for entry in entries:
        rows.append(
            [
                entry.get("timestamp", "-")[:19],
                entry.get("event_type", "-"),
                entry.get("user", entry.get("actor", "-")),
                entry.get("pii_type", "-"),
                entry.get("status", "-"),
            ]
        )
    print_table(["TIMESTAMP", "EVENT", "USER", "PII TYPE", "STATUS"], rows)


def cmd_sessions(args: Namespace, client: DashboardClient) -> None:
    """Show PII handling sessions."""
    data = client.get(
        "/api/pii/sessions",
        params={"limit": args.limit},
    )
    if getattr(args, "json", False):
        print_json(data)
        return

    sessions = data if isinstance(data, list) else data.get("items", [])
    if not sessions:
        print_ok("No PII sessions.")
        return

    rows = []
    for sess in sessions:
        rows.append(
            [
                str(sess.get("session_id", "-"))[:16],
                sess.get("purpose", "-"),
                sess.get("user", "-"),
                str(sess.get("access_count", 0)),
                sess.get("status", "-"),
            ]
        )
    print_table(
        ["SESSION ID", "PURPOSE", "USER", "ACCESSES", "STATUS"],
        rows,
    )


def cmd_rotate_keys(args: Namespace, client: DashboardClient) -> None:
    """Rotate PII vault encryption keys."""
    data = client.post("/api/pii/keys/rotate")
    if getattr(args, "json", False):
        print_json(data)
    else:
        print_ok("Encryption keys rotated successfully.")
