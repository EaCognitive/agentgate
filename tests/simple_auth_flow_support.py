"""Helpers for simple register-and-login API test flows."""

from fastapi.testclient import TestClient


def register_user(
    client: TestClient,
    *,
    email: str,
    password: str,
    name: str,
) -> None:
    """Register a user for test setup."""
    client.post(
        "/api/auth/register",
        json={"email": email, "password": password, "name": name},
    )


def login_user(client: TestClient, *, email: str, password: str):
    """Submit a login request for test setup or assertions."""
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )


def register_and_login(
    client: TestClient,
    *,
    email: str,
    password: str,
    name: str,
) -> str:
    """Register a user and return its access token."""
    register_user(client, email=email, password=password, name=name)
    response = login_user(client, email=email, password=password)
    return response.json()["access_token"]
