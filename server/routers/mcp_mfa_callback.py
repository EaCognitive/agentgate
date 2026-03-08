"""Azure AD MFA callback endpoint for MCP operations.

Handles the OAuth callback from Azure AD after MFA completion,
verifying the authentication and marking the MFA challenge as complete.
"""

from __future__ import annotations

import logging
from importlib import import_module
from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

from ..audit import emit_audit_event
from ..models import get_session_context

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# Success page HTML template
SUCCESS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>MFA Verification Complete</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .card {{
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
        }}
        .success-icon {{
            font-size: 4rem;
            margin-bottom: 1rem;
        }}
        h1 {{
            color: #1a1a2e;
            margin-bottom: 0.5rem;
        }}
        p {{
            color: #4a4a6a;
            line-height: 1.6;
        }}
        .challenge-id {{
            background: #f0f0f5;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-family: monospace;
            font-size: 0.9rem;
            margin: 1rem 0;
            word-break: break-all;
        }}
        .instruction {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 1rem;
            margin-top: 1.5rem;
            text-align: left;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="success-icon">&#9989;</div>
        <h1>MFA Verification Complete</h1>
        <p>Your identity has been verified with Azure AD Multi-Factor Authentication.</p>
        <div class="challenge-id">{challenge_id}</div>
        <div class="instruction">
            <strong>Next Step:</strong><br>
            Return to your AI assistant and retry the operation with:<br>
            <code>mfa_challenge_id="{challenge_id}"</code>
        </div>
    </div>
</body>
</html>
"""

# Error page HTML template
ERROR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>MFA Verification Failed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #ff6b6b 0%, #c0392b 100%);
        }}
        .card {{
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
        }}
        .error-icon {{
            font-size: 4rem;
            margin-bottom: 1rem;
        }}
        h1 {{
            color: #c0392b;
            margin-bottom: 0.5rem;
        }}
        p {{
            color: #4a4a6a;
            line-height: 1.6;
        }}
        .error-detail {{
            background: #ffebee;
            border-left: 4px solid #c0392b;
            padding: 1rem;
            margin-top: 1.5rem;
            text-align: left;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="error-icon">&#10060;</div>
        <h1>MFA Verification Failed</h1>
        <p>{message}</p>
        <div class="error-detail">
            <strong>Error:</strong> {error}<br>
            <strong>Description:</strong> {error_description}
        </div>
    </div>
</body>
</html>
"""


@router.get("/mfa-callback", response_class=HTMLResponse)
async def mfa_callback(
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    error_description: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """Handle Azure AD OAuth callback after MFA completion.

    This endpoint is called by Azure AD after the user completes MFA.
    It verifies the authentication and marks the challenge as complete.
    """
    # Handle error response from Azure AD
    if error:
        logger.warning(
            "Azure AD MFA callback error: %s - %s",
            error,
            error_description,
        )
        return HTMLResponse(
            content=ERROR_HTML.format(
                message="Azure AD returned an error during authentication.",
                error=error or "unknown",
                error_description=error_description or "No description provided",
            ),
            status_code=400,
        )

    # Validate required parameters
    if not code or not state:
        return HTMLResponse(
            content=ERROR_HTML.format(
                message="Missing required parameters from Azure AD.",
                error="invalid_request",
                error_description="Code or state parameter is missing",
            ),
            status_code=400,
        )

    # Parse state to get challenge ID
    challenge_id, separator, _state_suffix = state.partition(":")
    if not separator or not challenge_id:
        return HTMLResponse(
            content=ERROR_HTML.format(
                message="Invalid state format.",
                error="invalid_state",
                error_description="State parameter has invalid format",
            ),
            status_code=400,
        )

    verify_mfa_completion = getattr(
        import_module("server.mcp.azure_mfa_guard"),
        "verify_mfa_completion",
    )

    # Verify MFA completion
    result = await verify_mfa_completion(challenge_id, state, code)

    if not result.verified:
        return HTMLResponse(
            content=ERROR_HTML.format(
                message=result.message,
                error="verification_failed",
                error_description=result.hint or "MFA verification could not be completed",
            ),
            status_code=400,
        )

    # Audit log
    async with get_session_context() as session:
        await emit_audit_event(
            session,
            event_type="mcp_mfa_completed",
            actor="azure_ad",
            result="success",
            details={
                "challenge_id": challenge_id,
                "method": "azure_ad_mfa",
            },
        )

    # Return success page
    return HTMLResponse(
        content=SUCCESS_HTML.format(challenge_id=challenge_id),
        status_code=200,
    )
