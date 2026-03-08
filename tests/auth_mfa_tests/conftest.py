"""Shared fixtures for MFA tests."""

from typing import NamedTuple

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.utils.mfa import (
    generate_backup_codes,
    generate_totp_secret,
    hash_backup_code,
)
from tests.router_test_support import create_test_user


class MfaTestData(NamedTuple):
    """Container for MFA test artifacts generated during fixture setup."""

    secret: str
    backup_codes_plain: list[str]


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session) -> User:
    """Create a test user without MFA."""
    return create_test_user(
        session,
        email="test@example.com",
        name="Test User",
        password="password123",
        role="admin",
        totp_secret=None,
        totp_enabled=False,
        backup_codes=None,
    )


@pytest.fixture(name="mfa_test_data")
def mfa_test_data_fixture() -> MfaTestData:
    """Generate TOTP secret and plain backup codes for MFA test fixtures."""
    return MfaTestData(
        secret=generate_totp_secret(),
        backup_codes_plain=generate_backup_codes(count=8),
    )


@pytest.fixture(name="user_with_mfa")
def user_with_mfa_fixture(
    session: Session,
    mfa_test_data: MfaTestData,
) -> User:
    """Create user with MFA enabled.

    Use the ``mfa_test_data`` fixture to retrieve the plain-text
    secret and backup codes that correspond to this user.
    """
    backup_codes_hashed = [hash_backup_code(code) for code in mfa_test_data.backup_codes_plain]

    return create_test_user(
        session,
        email="mfa@example.com",
        name="MFA User",
        password="password123",
        role="admin",
        totp_secret=mfa_test_data.secret,
        totp_enabled=True,
        backup_codes=backup_codes_hashed,
    )


@pytest.fixture(name="auth_token")
def auth_token_fixture(client: TestClient, test_user: User) -> str:
    """Get auth token for regular user."""
    response = client.post(
        "/api/auth/login",
        json={
            "email": test_user.email,
            "password": "password123",
        },
    )
    return response.json()["access_token"]


@pytest.fixture(name="auth_token_with_mfa")
def auth_token_with_mfa_fixture(
    client: TestClient,
    user_with_mfa: User,
    mfa_test_data: MfaTestData,
) -> str:
    """Get auth token for MFA user (bypassing MFA for setup)."""
    totp = pyotp.TOTP(mfa_test_data.secret)
    code = totp.now()

    response = client.post(
        "/api/auth/login",
        json={
            "email": user_with_mfa.email,
            "password": "password123",
            "totp_code": code,
        },
    )
    return response.json()["access_token"]
