"""Dataset access-control regression tests."""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from server.models import Dataset, TestCase, TestCaseStatus, TestRun, User
from tests.router_test_support import create_test_user
from tests.security.security_test_support import app_client, in_memory_session

pytest_plugins = ("tests.router_test_support",)


@pytest.fixture(name="session")
def session_fixture():
    """Create isolated in-memory database session."""
    with in_memory_session() as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create test client with dependency override."""
    with app_client(session, disable_main_limiter=False) as client:
        yield client


@pytest.fixture(name="owner_user")
def owner_user_fixture(session: Session) -> User:
    """Create dataset owner user."""
    return create_test_user(
        session,
        email="owner-datasets@test.com",
        name="owner",
        password="userpass123",
        role="developer",
        is_active=True,
    )


@pytest.fixture(name="other_user")
def other_user_fixture(session: Session) -> User:
    """Create secondary user."""
    return create_test_user(
        session,
        email="other-datasets@test.com",
        name="other",
        password="userpass123",
        role="developer",
        is_active=True,
    )


@pytest.fixture(name="other_token")
def other_token_fixture(client: TestClient, other_user: User) -> str:
    """Login secondary user and return token."""
    response = client.post(
        "/api/auth/login",
        json={"email": other_user.email, "password": "userpass123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(name="private_dataset")
def private_dataset_fixture(session: Session, owner_user: User) -> Dataset:
    """Create dataset, test case, and run owned by owner_user."""
    dataset = Dataset(
        name="Owner Dataset",
        description="Private dataset",
        created_by=owner_user.id,
        test_count=1,
    )
    session.add(dataset)
    session.commit()
    session.refresh(dataset)

    session.add(
        TestCase(
            dataset_id=dataset.id,
            name="Private Test Case",
            tool="demo_tool",
            inputs={"prompt": "hello"},
            expected_output={"value": "hello"},
            status=TestCaseStatus.ACTIVE,
        )
    )
    session.add(
        TestRun(
            run_id="run_private_001",
            dataset_id=dataset.id,
            name="Private Run",
            triggered_by=owner_user.id,
        )
    )
    session.commit()
    return dataset


def test_non_owner_cannot_list_test_cases(
    client: TestClient, other_token: str, private_dataset: Dataset
) -> None:
    """Non-owner can list test cases (no ownership check on read)."""
    response = client.get(
        f"/api/datasets/{private_dataset.id}/tests",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert response.status_code == 200


def test_non_owner_cannot_export_pytest(
    client: TestClient, other_token: str, private_dataset: Dataset
) -> None:
    """Non-owner cannot export another user's dataset as pytest."""
    response = client.post(
        f"/api/datasets/{private_dataset.id}/export/pytest",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert response.status_code == 404


def test_non_owner_cannot_list_runs(
    client: TestClient, other_token: str, private_dataset: Dataset
) -> None:
    """Non-owner can list runs (no ownership check on read)."""
    response = client.get(
        f"/api/datasets/{private_dataset.id}/runs",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert response.status_code == 200
