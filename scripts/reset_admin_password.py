#!/usr/bin/env python3
"""Reset or create the default admin user.

Usage:
  python3 scripts/reset_admin_password.py --email admin@test.com --password 'Password123!'

Reads DATABASE_URL from env (same as server). Supports sqlite/postgres.
"""

from __future__ import annotations

import argparse
import os
import sys

import bcrypt
from sqlmodel import Session, select

from server.models import User
from server.models.database import get_sync_engine


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Reset or create an admin user")
    parser.add_argument("--email", default=os.getenv("DEFAULT_ADMIN_EMAIL", "admin@test.com"))
    parser.add_argument("--password", default=os.getenv("DEFAULT_ADMIN_PASSWORD"))
    parser.add_argument("--role", default="admin")
    return parser.parse_args()


def main() -> int:
    """Run the password reset script."""
    args = parse_args()
    if not args.password:
        print("Password required: pass --password or set DEFAULT_ADMIN_PASSWORD", file=sys.stderr)
        return 2

    password_hash = bcrypt.hashpw(args.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    engine = get_sync_engine()
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == args.email)).one_or_none()
        if user is None:
            user = User(
                email=args.email, name="Admin", role=args.role, hashed_password=password_hash
            )
            session.add(user)
            session.commit()
            print(f"Created admin user: {args.email}")
            return 0

        user.hashed_password = password_hash
        user.role = args.role
        user.failed_login_attempts = 0
        user.last_failed_login = None
        session.add(user)
        session.commit()
        print(f"Updated admin user: {args.email}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
