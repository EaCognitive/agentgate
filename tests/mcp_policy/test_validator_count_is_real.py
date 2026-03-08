"""Tests for policy-governance validator count contract semantics."""

from __future__ import annotations

import json
import types

import pytest

from scripts import validate_policy_governance_adapter as validator


def _make_tool_result(payload: dict, *, is_error: bool = False) -> types.SimpleNamespace:
    """Build a deterministic MCP tool result object."""
    return types.SimpleNamespace(
        isError=is_error,
        content=[types.SimpleNamespace(text=json.dumps(payload))],
    )


class _FakeMCPSession:
    """Deterministic fake MCP session for validator unit tests."""

    instance: "_FakeMCPSession | None" = None

    def __init__(self, _read, _write):
        self.evaluate_calls = 0
        self.verify_calls = 0
        self._decision_counter = 0
        _FakeMCPSession.instance = self

    async def __aenter__(self):
        """Enter the fake async session context."""
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Exit the fake async session context."""
        _ = exc_type, exc, tb

    async def initialize(self):
        """Return a stable MCP protocol version payload."""
        return types.SimpleNamespace(protocolVersion="2026-01-01")

    async def list_tools(self):
        """Return the tool catalog expected by the validator."""
        names = [
            "mcp_login",
            "mcp_guardrails_status",
            "apply_policy",
            "mcp_security_evaluate_admissibility",
            "mcp_security_verify_certificate",
            "mcp_list_jobs",
            "mcp_check_job_status",
        ]
        return types.SimpleNamespace(tools=[types.SimpleNamespace(name=name) for name in names])

    async def call_tool(self, name: str, arguments: dict):
        """Return deterministic tool responses used by validator tests."""
        if name == "mcp_security_evaluate_admissibility":
            self.evaluate_calls += 1
            self._decision_counter += 1
            payload = {
                "success": True,
                "certificate": {"decision_id": f"dec-{self._decision_counter}"},
                "runtime_solver": {"solver_backend": "z3"},
            }
            return _make_tool_result(payload)
        if name == "mcp_security_verify_certificate":
            self.verify_calls += 1
            return _make_tool_result({"success": True})

        simple_payloads = {
            "mcp_login": ({"status": "authenticated"}, False),
            "mcp_guardrails_status": ({"success": True}, False),
            "apply_policy": ({"error": "human_approval_required"}, True),
            "mcp_list_jobs": ({"mode": "sync", "result": {"jobs": [], "count": 0}}, False),
            "mcp_check_job_status": (
                {
                    "success": False,
                    "operation": "mcp_check_job_status",
                    "mode": "sync",
                    "error": {"status_code": 404, "message": "Job not found"},
                },
                False,
            ),
        }
        if name in simple_payloads:
            payload, is_error = simple_payloads[name]
            return _make_tool_result(payload, is_error=is_error)
        raise AssertionError(f"Unexpected tool call: {name}, args={arguments}")


class _FakeStdioContext:
    async def __aenter__(self):
        """Return fake stdio reader and writer handles."""
        return (object(), object())

    async def __aexit__(self, exc_type, exc, tb):
        """Exit the fake stdio context."""
        _ = exc_type, exc, tb


@pytest.mark.asyncio
async def test_validator_executes_real_requested_count(monkeypatch) -> None:
    """Validator must execute exactly requested_count admissibility evaluations."""
    monkeypatch.setattr(
        validator,
        "_probe_api_health",
        lambda _base_url: validator.StepResult(
            name="api_health",
            passed=True,
            detail="ok",
            payload={},
        ),
    )
    monkeypatch.setattr(validator, "stdio_client", lambda _params: _FakeStdioContext())
    monkeypatch.setattr(validator, "ClientSession", _FakeMCPSession)

    requested_count = 7
    report = await validator.run_validation(
        email="admin@admin.com",
        password="password",
        profile="dev",
        count=requested_count,
        base_url="http://localhost:8000",
    )

    assert report["requested_count"] == requested_count
    assert report["executed_count"] == requested_count
    assert report["first_failure_trace_id"] is None
    fake = _FakeMCPSession.instance
    assert fake is not None
    assert fake.evaluate_calls == requested_count
    assert fake.verify_calls == requested_count
