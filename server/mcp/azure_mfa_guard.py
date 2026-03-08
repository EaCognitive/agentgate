"""Azure AD MFA callback verification helpers.

This module is intentionally fail-closed by default. Full Azure token exchange
validation can be layered in without changing the callback contract.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class MFACompletionResult:
    """Result returned to callback router after MFA verification."""

    verified: bool
    message: str
    hint: str | None = None


async def verify_mfa_completion(
    challenge_id: str,
    state: str,
    code: str,
) -> MFACompletionResult:
    """Verify MFA callback payload in a fail-closed manner.

    In production, this returns a non-verified result until Azure code-exchange
    validation is configured. For local demo environments, set
    ``MCP_MFA_DEMO_MODE=true`` to allow deterministic callback completion when
    ``state`` is prefixed with ``<challenge_id>:`` and ``code`` is non-empty.
    """
    if not challenge_id or not state or not code:
        return MFACompletionResult(
            verified=False,
            message="MFA callback is missing required values",
            hint="Retry the sign-in flow and complete MFA again",
        )

    expected_prefix = f"{challenge_id}:"
    if not state.startswith(expected_prefix):
        return MFACompletionResult(
            verified=False,
            message="MFA callback state does not match challenge",
            hint="Start a new MFA challenge and retry",
        )

    demo_mode = os.getenv("MCP_MFA_DEMO_MODE", "false").lower() in {"1", "true", "yes"}
    if demo_mode:
        return MFACompletionResult(
            verified=True,
            message="MFA challenge verified",
        )

    return MFACompletionResult(
        verified=False,
        message="Azure MFA verification backend is not configured",
        hint="Enable MCP_MFA_DEMO_MODE only for local non-production testing",
    )
