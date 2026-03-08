"""Generate a time-limited demo access link.

Produces a compact signed token with an expiration.
The dashboard validates the signature and rejects expired tokens.

Usage:
    python3 scripts/generate_demo_link.py --days 7
    python3 scripts/generate_demo_link.py --days 2 --user 1 --secret mysecret

User indices map to dashboard env vars:
    0 (default) -> DEMO_ACCOUNT_EMAIL / DEMO_ACCOUNT_PASSWORD
    1           -> DEMO_ACCOUNT_EMAIL_1 / DEMO_ACCOUNT_PASSWORD_1
    ...

Environment:
    DEMO_LINK_SECRET   Signing key (required if --secret not given)
    DASHBOARD_URL      Base URL (default https://demo.agentgate.tech)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import struct
import time


def generate_token(secret: str, days: int, user_index: int = 0) -> str:
    """Create a compact signed token with expiration.

    Format for user_index 0 (legacy, 16 chars):
        base64url( 4-byte expiry + 8-byte HMAC )

    Format for user_index > 0 (18 chars):
        base64url( 1-byte user_index + 4-byte expiry + 8-byte HMAC )
    """
    exp = int(time.time()) + (days * 86400)
    exp_bytes = struct.pack(">I", exp)

    if user_index == 0:
        signed_part = exp_bytes
    else:
        signed_part = struct.pack("B", user_index) + exp_bytes

    mac = hmac.new(
        secret.encode("utf-8"),
        signed_part,
        hashlib.sha256,
    ).digest()[:8]

    raw = signed_part + mac
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main() -> None:
    """Generate and print a demo access link."""
    parser = argparse.ArgumentParser(
        description="Generate a time-limited demo access link",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Days until link expires (default: 7)",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=0,
        help="Hours until link expires (added to --days)",
    )
    parser.add_argument(
        "--user",
        type=int,
        default=0,
        help="Demo user index (default: 0)",
    )
    parser.add_argument(
        "--secret",
        type=str,
        default=None,
        help="Signing secret (default: DEMO_LINK_SECRET env var)",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="Dashboard base URL",
    )
    args = parser.parse_args()

    secret = args.secret or os.getenv("DEMO_LINK_SECRET")
    if not secret:
        print("Error: provide --secret or set DEMO_LINK_SECRET")
        raise SystemExit(1)

    base_url = args.url or os.getenv("DASHBOARD_URL", "https://demo.agentgate.tech")

    token = generate_token(secret, args.days, args.user)
    # If --hours specified, regenerate with exact seconds
    if args.hours:
        total_seconds = (args.days * 86400) + (args.hours * 3600)
        exp = int(time.time()) + total_seconds
        exp_bytes = struct.pack(">I", exp)

        if args.user == 0:
            signed_part = exp_bytes
        else:
            signed_part = struct.pack("B", args.user) + exp_bytes

        mac = hmac.new(
            secret.encode("utf-8"),
            signed_part,
            hashlib.sha256,
        ).digest()[:8]
        raw = signed_part + mac
        token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    link = f"{base_url}/d/{token}"

    total_seconds = (args.days * 86400) + (args.hours * 3600)
    exp_ts = int(time.time()) + total_seconds
    exp_date = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(exp_ts))

    label = f"{args.days}d" if not args.hours else f"{args.days}d {args.hours}h"
    print(f"User index: {args.user}")
    print(f"Expires: {exp_date} ({label})")
    print(f"\n{link}\n")


if __name__ == "__main__":
    main()
