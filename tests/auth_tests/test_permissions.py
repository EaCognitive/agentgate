"""Permission checking tests."""

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import User
from server.routers.auth import create_access_token
from server.routers.auth_utils import _get_password_hash_sync as get_password_hash


def test_require_permission_denies_access(client: TestClient, session: Session):
    """Test require_permission dependency denies access without permission."""
    # Create a viewer user (doesn't have DATASET_CREATE permission)
    viewer = User(
        email="viewer_perm@test.com",
        hashed_password=get_password_hash("password123"),
        name="Viewer Perm",
        role="viewer",
        is_active=True,
    )
    session.add(viewer)
    session.commit()

    token = create_access_token(
        data={"sub": viewer.email, "role": viewer.role},
        expires_delta=timedelta(minutes=15),
    )

    # Try to access an endpoint that requires DATASET_CREATE permission
    response = client.post(
        "/api/datasets",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Test Dataset",
            "type": "test_suite",
            "description": "Test",
        },
    )
    assert response.status_code == 403
    assert "permission required" in response.json()["detail"].lower()


def test_require_permission_allows_access(client: TestClient, session: Session):
    """Test require_permission dependency allows access with permission."""
    # Create a developer user (has DATASET_CREATE permission)
    developer = User(
        email="dev_perm@test.com",
        hashed_password=get_password_hash("password123"),
        name="Dev Perm",
        role="developer",
        is_active=True,
    )
    session.add(developer)
    session.commit()

    token = create_access_token(
        data={"sub": developer.email, "role": developer.role},
        expires_delta=timedelta(minutes=15),
    )

    # Access an endpoint that requires DATASET_CREATE permission
    response = client.post(
        "/api/datasets",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Test Dataset",
            "type": "test_suite",
            "description": "Test",
        },
    )
    # Should succeed (200 or 201)
    assert response.status_code in [200, 201]


def test_require_admin_denies_non_admin(client: TestClient, session: Session):
    """Test require_admin dependency denies non-admin access."""
    # Create a developer user (not admin)
    developer = User(
        email="dev_admin@test.com",
        hashed_password=get_password_hash("password123"),
        name="Dev Admin",
        role="developer",
        is_active=True,
    )
    session.add(developer)
    session.commit()

    token = create_access_token(
        data={"sub": developer.email, "role": developer.role},
        expires_delta=timedelta(minutes=15),
    )

    # Try to access an admin-only endpoint (/api/test/seed requires admin)
    response = client.post(
        "/api/test/seed",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert "admin access required" in response.json()["detail"].lower()


def test_require_admin_allows_admin(client: TestClient, session: Session):
    """Test require_admin dependency allows admin access."""
    # Create an admin user
    admin = User(
        email="admin_allow@test.com",
        hashed_password=get_password_hash("password123"),
        name="Admin Allow",
        role="admin",
        is_active=True,
    )
    session.add(admin)
    session.commit()

    token = create_access_token(
        data={"sub": admin.email, "role": admin.role},
        expires_delta=timedelta(minutes=15),
    )

    # Access an admin-only endpoint
    response = client.post(
        "/api/test/seed",
        headers={"Authorization": f"Bearer {token}"},
    )
    # Should succeed (200)
    assert response.status_code == 200
