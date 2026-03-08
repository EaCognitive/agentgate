"""Tests for API-key scope governance logic."""

import pytest
from fastapi import HTTPException

from server.routers.api_keys import _validate_requested_scopes


def test_api_key_scope_allows_admin_wildcard():
    """Admin roles can request wildcard API-key scope."""
    assert _validate_requested_scopes("*", "admin") == "*"


def test_api_key_scope_denies_developer_wildcard():
    """Non-privileged roles cannot request wildcard scope."""
    with pytest.raises(HTTPException) as exc_info:
        _validate_requested_scopes("*", "developer")
    assert exc_info.value.status_code == 403


def test_api_key_scope_allows_developer_dataset_scope():
    """Developer roles can request role-allowed granular scopes."""
    resolved = _validate_requested_scopes("dataset:read,trace:read", "developer")
    assert resolved == "dataset:read,trace:read"


def test_api_key_scope_denies_scope_outside_role_permissions():
    """Scopes outside role permissions are rejected."""
    with pytest.raises(HTTPException) as exc_info:
        _validate_requested_scopes("user:update", "developer")

    assert exc_info.value.status_code == 403
