"""Credential security checks and enforcement.

Provides functions to detect and block default/insecure credentials,
especially in production environments.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass

import bcrypt
from sqlmodel import select

from server.models import User, get_session_context
from server.utils.db import execute as db_execute

logger = logging.getLogger(__name__)

# Known default/weak credentials that should NEVER be used in production
# Stored as SHA256 hashes for security (don't store plaintext defaults)
KNOWN_WEAK_PASSWORDS_SHA256 = {
    # "password"
    "5e884898da28047d9165141ff6bfa3e9e24a85fc4e4b0e1e8b7e1a5c3b3b0a7c",
    # "admin"
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
    # "123456"
    "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    # "password123"
    "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
}

KNOWN_DEFAULT_EMAILS = {
    "admin@admin.com",
    "admin@example.com",
    "admin@localhost",
    "test@test.com",
    "user@example.com",
}


@dataclass
class SecurityCheckResult:
    """Result of credential security check."""

    is_secure: bool
    issues: list[str]
    warnings: list[str]

    @property
    def has_critical_issues(self) -> bool:
        """Check if there are issues that should block production startup."""
        return len(self.issues) > 0


def is_production() -> bool:
    """Check if running in production environment."""
    env = os.getenv("AGENTGATE_ENV", os.getenv("ENV", "development")).lower()
    return env == "production"


def is_known_weak_password(password: str) -> bool:
    """Check if password matches known weak passwords."""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return password_hash in KNOWN_WEAK_PASSWORDS_SHA256


def is_default_email(email: str) -> bool:
    """Check if email is a known default email."""
    return email.lower() in KNOWN_DEFAULT_EMAILS


def check_user_credentials(user: "User", password: str | None = None) -> SecurityCheckResult:
    """Check if user credentials are secure.

    Args:
        user: User object to check
        password: Optional plaintext password to check strength

    Returns:
        SecurityCheckResult with issues and warnings
    """
    issues: list[str] = []
    warnings: list[str] = []

    # Check email
    if is_default_email(user.email):
        if is_production():
            issues.append(f"Default email '{user.email}' cannot be used in production")
        else:
            warnings.append(f"Using default email '{user.email}' - change before production")

    # Check password if provided
    if password and is_known_weak_password(password):
        if is_production():
            issues.append("Default/weak password cannot be used in production")
        else:
            warnings.append("Using weak/default password - change before production")

    return SecurityCheckResult(
        is_secure=len(issues) == 0,
        issues=issues,
        warnings=warnings,
    )


def check_admin_password_against_hash(
    hashed_password: str,
    test_passwords: list[str] | None = None,
) -> bool:
    """Check if admin password matches any known defaults.

    Args:
        hashed_password: The bcrypt hashed password from database
        test_passwords: Optional list of passwords to test (defaults to common ones)

    Returns:
        True if password matches a known default (INSECURE)
    """
    if test_passwords is None:
        test_passwords = ["password", "admin", "123456", "password123"]

    for test_pwd in test_passwords:
        try:
            if bcrypt.checkpw(test_pwd.encode("utf-8"), hashed_password.encode("utf-8")):
                return True
        except (ValueError, TypeError):
            continue
    return False


async def check_system_security() -> SecurityCheckResult:
    """Run comprehensive security check on the system.

    Checks:
    - Admin users with default emails
    - Admin users with default passwords
    - Production environment requirements

    Returns:
        SecurityCheckResult with all issues and warnings
    """
    issues: list[str] = []
    warnings: list[str] = []

    async with get_session_context() as session:
        # Check all admin users
        result = await db_execute(
            session,
            select(User).where(User.role == "admin"),
        )
        admins = result.scalars().all()

        for admin in admins:
            # Check for default email
            if is_default_email(admin.email):
                msg = f"Admin user '{admin.email}' uses default email"
                if is_production():
                    issues.append(msg)
                else:
                    warnings.append(msg)

            # Check for default password
            if check_admin_password_against_hash(admin.hashed_password):
                msg = f"Admin user '{admin.email}' uses default password"
                if is_production():
                    issues.append(msg)
                else:
                    warnings.append(msg)

    return SecurityCheckResult(
        is_secure=len(issues) == 0,
        issues=issues,
        warnings=warnings,
    )


def enforce_production_security(check_result: SecurityCheckResult) -> None:
    """Enforce security requirements in production.

    Raises:
        RuntimeError: If critical security issues found in production
    """
    if not is_production():
        # In development, just log warnings
        for warning in check_result.warnings:
            logger.warning("SECURITY WARNING: %s", warning)
        return

    if check_result.has_critical_issues:
        for issue in check_result.issues:
            logger.critical("SECURITY ISSUE: %s", issue)
        raise RuntimeError(
            "Cannot start in production with default credentials. "
            f"Issues: {'; '.join(check_result.issues)}"
        )
