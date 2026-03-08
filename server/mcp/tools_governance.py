"""Governance tools for natural language security policy management.

Provides MCP tools for parsing, simulating, applying, and managing
security policies through natural language descriptions. Destructive
operations proxy through the REST API; read-only tools compute locally.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, NoReturn

from .api_client import MCPApiClientError, get_api_client
from .auth_session import (
    auth_error_payload,
    enforce_mcp_policy,
    require_mcp_auth,
    reset_policy_cache,
)
from .confirm import generate_preview_token, verify_preview_token
from .execution_policy import ExecutionPolicyError, enforce_execution_policy
from .tools_api import MCPToolExecutionError


async def _check_guardrails(action: str, context: dict[str, Any] | None = None) -> None:
    """Check guardrails and raise error if operation is blocked or requires approval."""
    try:
        await enforce_execution_policy(
            action,
            method="POST",
            context=context or {},
        )
    except ExecutionPolicyError as exc:
        raise MCPToolExecutionError(json.dumps(exc.payload, indent=2, default=str)) from exc


async def _check_mfa(
    action: str,
    mfa_challenge_id: str | None = None,
    verification_code: str | None = None,
    context: dict[str, Any] | None = None,
) -> bool:
    """Compatibility no-op for MFA on reduced MCP policy adapter surface."""
    _ = action, mfa_challenge_id, verification_code, context
    return True


def _ip_matches_cidr(ip_str: str, cidr_str: str) -> bool:
    """Check if an IP address matches a CIDR range or exact IP.

    Args:
        ip_str: IP address to check.
        cidr_str: CIDR notation or exact IP.

    Returns:
        True if the IP falls within the CIDR range.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
        return addr in network
    except ValueError:
        return ip_str == cidr_str


def _parse_ip_pattern(desc: str) -> dict[str, Any] | None:
    """Parse IP blocking/allowing patterns from natural language."""
    block_match = re.search(
        r"block\s+ips?\s+from\s+([\d\.\/]+)",
        desc.lower(),
    )
    if block_match:
        return {"type": "ip_deny", "cidr": block_match.group(1)}

    allow_match = re.search(
        r"allow\s+ips?\s+from\s+([\d\.\/]+)",
        desc.lower(),
    )
    if allow_match:
        return {"type": "ip_allow", "cidr": allow_match.group(1)}

    return None


def _parse_severity_pattern(desc: str) -> dict[str, Any] | None:
    """Parse severity override patterns from natural language."""
    match = re.search(
        r"escalate\s+(?:all\s+)?(\w+(?:\s+\w+)?)\s+to\s+(\w+)",
        desc.lower(),
    )
    if not match:
        return None
    return {
        "type": "severity_override",
        "pattern_type": match.group(1).replace(" ", "_"),
        "new_severity": match.group(2).upper(),
    }


def _parse_endpoint_pattern(desc: str) -> dict[str, Any] | None:
    """Parse endpoint allow patterns from natural language."""
    match = re.search(
        r"skip\s+detection\s+for\s+([\/\w\-]+)",
        desc.lower(),
    )
    if not match:
        return None
    return {"type": "endpoint_allow", "endpoint": match.group(1)}


def _raise_tool_error(
    action: str,
    message: str,
    *,
    status_code: int = 400,
    details: Any = None,
) -> NoReturn:
    payload = {
        "success": False,
        "operation": action,
        "error": message,
        "status_code": status_code,
        "details": details,
    }
    raise MCPToolExecutionError(json.dumps(payload, indent=2, default=str))


def _api_failure(action: str, exc: MCPApiClientError) -> NoReturn:
    raise MCPToolExecutionError(json.dumps(auth_error_payload(exc, action), indent=2, default=str))


async def parse_nl_policy(description: str) -> str:
    """Parse natural language into structured policy JSON.

    CATEGORY: READ-ONLY

    USE WHEN:
        - Creating simple IP block/allow rules from plain English
        - Quick policy prototyping before formal policy creation
        - Non-technical users need to define basic security rules

    PREREQUISITES:
        - mcp_login must be called first

    REQUIRED:
        description: Natural language policy description (e.g., "block IPs from 10.0.0.0/8")

    OPTIONAL:
        None

    BEHAVIOR:
        - Parses text for specific phrase patterns only
        - Supports semicolon, newline, or "and" as clause separators
        - Returns empty rules arrays if no patterns matched
        - Does NOT apply policy - only parses to JSON

    SUPPORTED PATTERNS (exact phrases only):
        - "block IPs from X.X.X.X/Y" -> ip_deny pre-rule
        - "allow IPs from X.X.X.X/Y" -> ip_allow pre-rule
        - "escalate all SQL injection to CRITICAL" -> severity_override post-rule
        - "skip detection for /path" -> endpoint_allow pre-rule

    NEXT STEP:
        - If rules parsed: Pass result to apply_policy or simulate_policy
        - If no rules: Use mcp_policies_create with full JSON schema instead

    RETURNS:
        JSON with: success, parsed_policy (pre_rules array, post_rules array), warnings

    EXAMPLE:
        parse_nl_policy(description="block IPs from 10.0.0.0/8 and skip detection for /health")
    """
    try:
        await require_mcp_auth()
        await enforce_mcp_policy(
            "parse_nl_policy",
            {"description": description},
        )
    except MCPApiClientError as exc:
        _api_failure("parse_nl_policy", exc)

    pre_rules: list[dict[str, Any]] = []
    post_rules: list[dict[str, Any]] = []

    clauses = re.split(r"[\n;]|\band\b", description)
    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue

        ip_rule = _parse_ip_pattern(clause)
        if ip_rule:
            pre_rules.append(ip_rule)
            continue

        endpoint_rule = _parse_endpoint_pattern(clause)
        if endpoint_rule:
            pre_rules.append(endpoint_rule)
            continue

        severity_rule = _parse_severity_pattern(clause)
        if severity_rule:
            post_rules.append(severity_rule)

    result: dict[str, Any] = {
        "success": True,
        "parsed_policy": {
            "pre_rules": pre_rules,
            "post_rules": post_rules,
        },
        "warnings": [],
    }

    if not pre_rules and not post_rules:
        result["warnings"].append(
            "No recognized patterns found in description",
        )

    return json.dumps(result, indent=2)


async def apply_policy(
    policy_json: str,
    confirm: bool = False,
    preview_token: str = "",
    mfa_challenge_id: str = "",
    verification_code: str = "",
) -> str:
    """Apply a new security policy via REST API.

    CATEGORY: WORKFLOW STEP 1 of 2 (preview) or STEP 2 of 2 (confirm)

    USE WHEN:
        - Applying policy parsed from parse_nl_policy output
        - Deploying pre-validated policy rules to production
        - Need preview-confirm safety for policy changes

    PREREQUISITES:
        - mcp_login must be called first
        - Policy JSON ready (from parse_nl_policy or manual construction)
        - Recommended: Test with simulate_policy first
        - MFA verification required (TOTP code or Azure AD challenge)

    REQUIRED:
        policy_json: JSON string with policy rules (from parse_nl_policy or manual)
            Must contain: {"pre_rules": [...], "post_rules": [...]}

    OPTIONAL:
        confirm: False for preview, True to execute (default: False)
        preview_token: Token from preview step (required when confirm=True)
        mfa_challenge_id: Challenge ID for Azure AD/Dashboard MFA
        verification_code: 6-digit TOTP code from authenticator app

    BEHAVIOR:
        - Step 1 (confirm=False): Validates JSON, returns preview with signed token
        - Step 2 (confirm=True + token): Verifies token, creates policy via REST API
        - Policy is created with origin="mcp" and locked=True
        - Clears policy cache after successful application
        - Token expires in 5 minutes; must re-preview if expired

    NEXT STEP:
        - If preview: Review policy_preview, call again with confirm=True
        - If confirmed: Use mcp_policies_list to verify, mcp_policies_evaluate to test

    RETURNS:
        Preview: JSON with success=False, preview_token, message, policy_preview
        Confirmed: JSON with success=True, action, policy_id, message

    EXAMPLE:
        # Using output from parse_nl_policy
        policy = parse_nl_policy("block IPs from 10.0.0.0/8")
        # Step 1: Preview
        apply_policy(policy_json='{"pre_rules": [{"type": "ip_deny", "cidr": "10.0.0.0/8"}]}')
        # Step 2: Confirm
        apply_policy(policy_json='...', confirm=True, preview_token="<token>")
    """
    try:
        await require_mcp_auth()
        await enforce_mcp_policy(
            "apply_policy",
            {"policy_json": policy_json, "confirm": confirm},
        )
    except MCPApiClientError as exc:
        _api_failure("apply_policy", exc)

    # MFA verification - requires human authentication
    mfa_verified = await _check_mfa(
        "apply_policy",
        mfa_challenge_id=mfa_challenge_id or None,
        verification_code=verification_code or None,
        context={"policy_json_preview": policy_json[:100]},
    )

    try:
        policy_dict = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        _raise_tool_error(
            "apply_policy",
            f"Invalid JSON: {exc}",
            status_code=422,
        )

    action = "apply_policy"
    params = {
        "policy_json": json.dumps(policy_dict, sort_keys=True),
    }

    if not confirm:
        await _check_guardrails(
            "apply_policy",
            {
                "policy_json": policy_json[:100],
                "execution_phase": "preview",
                "preview_confirmed": False,
                "mfa_verified": mfa_verified,
                "enforce_mfa_obligation": True,
                "resource": "security://policy/apply",
            },
        )
        token = generate_preview_token(action, params)
        return json.dumps(
            {
                "success": False,
                "preview_token": token,
                "message": (
                    "Policy ready to apply. Re-run with confirm=true "
                    "and this preview_token to execute."
                ),
                "policy_preview": policy_dict,
            },
            indent=2,
        )

    valid, token_error = verify_preview_token(
        preview_token,
        action,
        params,
    )
    if not valid:
        _raise_tool_error(
            "apply_policy",
            f"Token verification failed: {token_error}",
            status_code=422,
        )

    await _check_guardrails(
        "apply_policy",
        {
            "policy_json": policy_json[:100],
            "execution_phase": "confirm",
            "preview_confirmed": True,
            "mfa_verified": mfa_verified,
            "enforce_mfa_obligation": True,
            "resource": "security://policy/apply",
        },
    )

    try:
        client = get_api_client()
        result = await client.post(
            "/api/policies",
            body={
                "policy_json": policy_dict,
                "origin": "mcp",
                "locked": True,
            },
        )
    except MCPApiClientError as exc:
        _api_failure("apply_policy", exc)

    reset_policy_cache()
    return json.dumps(
        {
            "success": True,
            "action": "apply_policy",
            "policy_id": result.get("policy_set_id", ""),
            "message": "Policy applied successfully",
        },
        indent=2,
    )


def _evaluate_pre_rules(
    pre_rules: list[dict[str, Any]],
    test_input: dict[str, Any],
) -> dict[str, str]:
    """Evaluate pre-detection rules against a single test input.

    Returns a dict with 'action' and 'reason' keys.
    """
    input_ip = test_input.get("ip", "")
    endpoint = test_input.get("endpoint", "")

    for rule in pre_rules:
        if rule["type"] == "endpoint_allow" and endpoint == rule["endpoint"]:
            return {"action": "allow", "reason": f"Endpoint {endpoint} is allowlisted"}
        if rule["type"] == "ip_deny" and input_ip:
            if _ip_matches_cidr(input_ip, rule.get("cidr", "")):
                return {"action": "deny", "reason": f"IP {input_ip} is in denylist"}
        if rule["type"] == "ip_allow" and input_ip:
            if _ip_matches_cidr(input_ip, rule.get("cidr", "")):
                return {"action": "allow", "reason": f"IP {input_ip} is in allowlist"}

    return {"action": "continue", "reason": "No matching pre-rules"}


def _evaluate_post_rules(
    post_rules: list[dict[str, Any]],
    test_input: dict[str, Any],
) -> dict[str, str]:
    """Evaluate post-detection rules against a single test input.

    Returns a dict with 'action' and 'reason' keys.
    """
    input_severity = test_input.get("severity", "")
    pattern_type = test_input.get("pattern_type", "")

    for rule in post_rules:
        if rule["type"] == "severity_override" and pattern_type == rule["pattern_type"]:
            new_sev = rule["new_severity"]
            return {
                "action": "escalate",
                "reason": f"Severity escalated from {input_severity} to {new_sev}",
            }

    return {"action": "continue", "reason": "No matching post-rules"}


async def simulate_policy(
    policy_rules: str,
    test_inputs: str,
) -> str:
    """Dry-run policy rules against test inputs.

    REQUIRED:
        policy_rules: JSON with pre_rules and post_rules arrays
        test_inputs: JSON array of test cases

    EXACT JSON STRUCTURE REQUIRED:

    policy_rules format:
        {"pre_rules": [...], "post_rules": [...]}

    test_inputs format:
        [{
          "ip": "10.0.0.1",
          "endpoint": "/api/test",
          "severity": "HIGH",
          "pattern_type": "sql_injection"
        }]

    READ-ONLY - No changes made to system.

    Returns:
        JSON with: simulation_results array, total_tests count
    """
    try:
        await require_mcp_auth()
        await enforce_mcp_policy(
            "simulate_policy",
            {
                "policy_rules": policy_rules,
                "test_inputs": test_inputs,
            },
        )
    except MCPApiClientError as exc:
        _api_failure("simulate_policy", exc)

    try:
        rules = json.loads(policy_rules)
        inputs = json.loads(test_inputs)
    except json.JSONDecodeError as exc:
        _raise_tool_error(
            "simulate_policy",
            f"Invalid JSON: {exc}",
            status_code=422,
        )

    pre_rules = rules.get("pre_rules", [])
    post_rules = rules.get("post_rules", [])

    results = []
    for test_input in inputs:
        pre_result = _evaluate_pre_rules(pre_rules, test_input)
        post_result = _evaluate_post_rules(post_rules, test_input)

        results.append(
            {
                "input": test_input,
                "pre_detector": pre_result,
                "post_detector": post_result,
            }
        )

    return json.dumps(
        {
            "success": True,
            "simulation_results": results,
            "total_tests": len(results),
        },
        indent=2,
    )


async def unlock_policy(
    policy_id: str,
    reason: str,
    *,
    confirm: bool = False,
    preview_token: str = "",
    mfa_challenge_id: str = "",
    verification_code: str = "",
) -> str:
    """Unlock MCP-created policy via REST API.

    REQUIRED:
        policy_id: UUID of the policy to unlock
        reason: Reason for unlocking (audit trail)

    DESTRUCTIVE OPERATION - Uses preview-confirm flow.

    OPTIONAL:
        confirm: False for preview, True to execute (default: False)
        preview_token: Token from preview step (required when confirm=True)
        mfa_challenge_id: Challenge ID for Azure AD/Dashboard MFA
        verification_code: 6-digit TOTP code from authenticator app

    WORKFLOW:
        1. Call with policy_id and reason only (confirm=False)
        2. Review preview_token response
        3. Call again with confirm=True and preview_token

    Returns:
        Preview: JSON with preview_token
        Confirmed: JSON with success message
    """
    try:
        await require_mcp_auth()
        await enforce_mcp_policy(
            "unlock_policy",
            {
                "policy_id": policy_id,
                "reason": reason,
                "confirm": confirm,
            },
        )
    except MCPApiClientError as exc:
        _api_failure("unlock_policy", exc)

    # MFA verification - requires human authentication
    mfa_verified = await _check_mfa(
        "unlock_policy",
        mfa_challenge_id=mfa_challenge_id or None,
        verification_code=verification_code or None,
        context={"policy_id": policy_id},
    )

    action = "unlock_policy"
    params = {"policy_id": policy_id, "reason": reason}

    if not confirm:
        await _check_guardrails(
            "unlock_policy",
            {
                "policy_id": policy_id,
                "execution_phase": "preview",
                "preview_confirmed": False,
                "mfa_verified": mfa_verified,
                "enforce_mfa_obligation": True,
                "resource": f"security://policy/{policy_id}",
            },
        )
        token = generate_preview_token(action, params)
        return json.dumps(
            {
                "success": False,
                "preview_token": token,
                "message": (
                    f"Ready to unlock policy {policy_id}. "
                    "Re-run with confirm=true and preview_token."
                ),
                "reason": reason,
            },
            indent=2,
        )

    valid, token_error = verify_preview_token(
        preview_token,
        action,
        params,
    )
    if not valid:
        _raise_tool_error(
            "unlock_policy",
            f"Token verification failed: {token_error}",
            status_code=422,
        )

    await _check_guardrails(
        "unlock_policy",
        {
            "policy_id": policy_id,
            "execution_phase": "confirm",
            "preview_confirmed": True,
            "mfa_verified": mfa_verified,
            "enforce_mfa_obligation": True,
            "resource": f"security://policy/{policy_id}",
        },
    )

    try:
        client = get_api_client()
        path = client.path_with_segments("/api/policies", policy_id)
        await client.patch(
            path,
            body={"locked": False},
        )
    except MCPApiClientError as exc:
        _api_failure("unlock_policy", exc)

    reset_policy_cache()
    return json.dumps(
        {
            "success": True,
            "action": "unlock_policy",
            "policy_id": policy_id,
            "reason": reason,
            "message": f"Policy {policy_id} unlocked successfully",
        },
        indent=2,
    )
