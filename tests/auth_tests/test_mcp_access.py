"""Tests for MCP privilege evaluation helpers."""

from server.security.identity.mcp_access import evaluate_mcp_privilege


def test_mcp_privilege_allows_admin_without_scope_in_development(monkeypatch):
    """Admin role is allowed when scope enforcement is disabled."""
    monkeypatch.setenv("MCP_PRIVILEGED_ROLES", "admin")
    monkeypatch.setenv("MCP_REQUIRE_SCOPE", "false")

    allowed, reason = evaluate_mcp_privilege(
        role="admin",
        claims={"sub": "admin@example.com"},
        environment="development",
    )

    assert allowed is True
    assert reason == ""


def test_mcp_privilege_denies_non_privileged_role(monkeypatch):
    """Non-privileged roles are rejected before scope checks."""
    monkeypatch.setenv("MCP_PRIVILEGED_ROLES", "admin")
    monkeypatch.setenv("MCP_REQUIRE_SCOPE", "false")

    allowed, reason = evaluate_mcp_privilege(
        role="developer",
        claims={"sub": "dev@example.com"},
        environment="production",
    )

    assert allowed is False
    assert reason == "Role is not permitted for MCP-privileged access"


def test_mcp_privilege_requires_scope_when_enforced(monkeypatch):
    """Production scope enforcement rejects missing required claims."""
    monkeypatch.setenv("MCP_PRIVILEGED_ROLES", "admin")
    monkeypatch.setenv("MCP_REQUIRE_SCOPE", "true")
    monkeypatch.setenv("MCP_REQUIRED_SCOPES", "mcp:admin,mcp:access")

    allowed, reason = evaluate_mcp_privilege(
        role="admin",
        claims={"sub": "admin@example.com", "scopes": ["dataset:read"]},
        environment="production",
    )

    assert allowed is False
    assert reason == "Required MCP scope claim is missing"


def test_mcp_privilege_allows_required_scope_when_enforced(monkeypatch):
    """Required scope claim satisfies enforced MCP privilege checks."""
    monkeypatch.setenv("MCP_PRIVILEGED_ROLES", "admin,security_admin")
    monkeypatch.setenv("MCP_REQUIRE_SCOPE", "true")
    monkeypatch.setenv("MCP_REQUIRED_SCOPES", "mcp:admin,mcp:access")

    allowed, reason = evaluate_mcp_privilege(
        role="admin",
        claims={"sub": "admin@example.com", "scopes": ["mcp:access"]},
        environment="production",
    )

    assert allowed is True
    assert reason == ""
