#!/usr/bin/env python3
"""Bootstrap and validate Descope provider settings for AgentGate.

This helper provides a reproducible path to configure runtime variables required by
AgentGate for Descope-backed token exchange:

- DESCOPE_JWKS_URL
- DESCOPE_ISSUER
- DESCOPE_AUDIENCE
- IDENTITY_PROVIDER_MODE

It can also validate a Descope management key and write dashboard hosted-flow URLs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_API_BASE = "https://api.descope.com"
DEFAULT_AUTH_HOST_BASE = "https://auth.descope.io"
DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class HttpJsonResponse:
    """HTTP response payload for JSON endpoints."""

    status_code: int
    body: dict[str, Any]


@dataclass(frozen=True)
class ManagementKeyValidation:
    """Outcome of optional Descope management-key validation."""

    attempted: bool
    status_code: int | None
    valid: bool
    error_code: str | None
    error_description: str | None


def _http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> HttpJsonResponse:
    """Fetch JSON from an HTTP endpoint and return status + parsed object."""
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "agentgate-descope-bootstrap/1.0",
    }
    if headers:
        request_headers.update(headers)
    request = Request(url, method="GET", headers=request_headers)
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            raw = response.read().decode("utf-8", errors="replace")
            if raw.strip():
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return HttpJsonResponse(status_code=response.status, body=parsed)
            return HttpJsonResponse(status_code=response.status, body={})
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        parsed: dict[str, Any] = {}
        if raw.strip():
            try:
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    parsed = loaded
            except json.JSONDecodeError:
                parsed = {"raw": raw}
        return HttpJsonResponse(status_code=exc.code, body=parsed)
    except URLError as exc:
        raise RuntimeError(f"Network error while requesting '{url}': {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Endpoint returned non-JSON payload: {url}") from exc


def discover_oidc_configuration(
    *,
    project_id: str,
    api_base: str,
) -> tuple[str, str]:
    """Resolve issuer and JWKS URL using OIDC discovery."""
    discovery_url = f"{api_base.rstrip('/')}/{project_id}/.well-known/openid-configuration"
    response = _http_json(discovery_url)
    if response.status_code != 200:
        raise RuntimeError(
            f"Unable to discover Descope OIDC configuration (HTTP {response.status_code})."
        )

    issuer = str(response.body.get("issuer", "")).strip()
    jwks_uri = str(response.body.get("jwks_uri", "")).strip()
    if not issuer or not jwks_uri:
        raise RuntimeError("OIDC discovery response is missing issuer/jwks_uri fields.")
    return issuer, jwks_uri


def validate_jwks(jwks_url: str) -> int:
    """Validate JWKS endpoint is reachable and contains at least one key."""
    response = _http_json(jwks_url)
    if response.status_code != 200:
        raise RuntimeError(f"JWKS endpoint check failed (HTTP {response.status_code}).")

    keys = response.body.get("keys")
    if not isinstance(keys, list) or not keys:
        raise RuntimeError("JWKS endpoint returned no signing keys.")
    return len(keys)


def validate_management_key(
    *,
    project_id: str,
    management_key: str | None,
    api_base: str,
) -> ManagementKeyValidation:
    """Validate management-key format and runtime acceptance (optional)."""
    if not management_key:
        return ManagementKeyValidation(
            attempted=False,
            status_code=None,
            valid=False,
            error_code=None,
            error_description=None,
        )

    token = f"{project_id}:{management_key}"
    endpoint = f"{api_base.rstrip('/')}/v1/mgmt/role/all"
    response = _http_json(endpoint, headers={"Authorization": f"Bearer {token}"})
    error_code = str(response.body.get("errorCode", "")).strip() or None
    error_description = str(response.body.get("errorDescription", "")).strip() or None
    valid = response.status_code == 200
    return ManagementKeyValidation(
        attempted=True,
        status_code=response.status_code,
        valid=valid,
        error_code=error_code,
        error_description=error_description,
    )


def build_hosted_flow_url(
    *,
    auth_host_base: str,
    project_id: str,
    flow_id: str | None,
) -> str:
    """Build Descope hosted-flow URL for dashboard redirects."""
    base = f"{auth_host_base.rstrip('/')}/{project_id}"
    if not flow_id:
        return base
    query = urlencode({"flow": flow_id})
    return f"{base}?{query}"


def _upsert_env_lines(lines: list[str], updates: dict[str, str]) -> list[str]:
    """Replace or append KEY=VALUE assignments in .env text lines."""
    result = list(lines)
    for key, value in updates.items():
        assignment = f"{key}={value}"
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
        for index, line in enumerate(result):
            if pattern.match(line):
                result[index] = assignment
                break
        else:
            result.append(assignment)
    return result


def write_env_updates(path: Path, updates: dict[str, str]) -> None:
    """Write updates into an env file while preserving unrelated lines."""
    if path.exists():
        original_lines = path.read_text(encoding="utf-8").splitlines()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        original_lines = []
    updated_lines = _upsert_env_lines(original_lines, updates)
    path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True, help="Descope project identifier.")
    parser.add_argument(
        "--identity-mode",
        default="hybrid_migration",
        choices=["local", "hybrid_migration", "descope", "custom_oidc"],
        help="Identity provider mode to set in env files.",
    )
    parser.add_argument(
        "--audience",
        default="",
        help="Override DESCOPE_AUDIENCE. Defaults to project id when omitted.",
    )
    parser.add_argument(
        "--management-key",
        default="",
        help="Optional Descope management key (avoid passing directly in shared shells).",
    )
    parser.add_argument(
        "--management-key-env",
        default="DESCOPE_MANAGEMENT_KEY",
        help="Environment variable fallback for management key.",
    )
    parser.add_argument(
        "--api-base",
        default=DEFAULT_API_BASE,
        help="Descope API base URL for OIDC discovery and management validation.",
    )
    parser.add_argument(
        "--auth-host-base",
        default=DEFAULT_AUTH_HOST_BASE,
        help="Descope hosted auth base URL used to build sign-in/sign-up redirects.",
    )
    parser.add_argument(
        "--signin-flow-id",
        default="sign-up-or-in",
        help="Flow ID for NEXT_PUBLIC_DESCOPE_SIGNIN_URL.",
    )
    parser.add_argument(
        "--signup-flow-id",
        default="sign-up-or-in",
        help="Flow ID for NEXT_PUBLIC_DESCOPE_SIGNUP_URL.",
    )
    parser.add_argument(
        "--root-env",
        default=".env",
        help="Path to root env file to update.",
    )
    parser.add_argument(
        "--server-env",
        default="server/.env",
        help="Path to server env file to update.",
    )
    parser.add_argument(
        "--dashboard-env",
        default="dashboard/.env",
        help="Path to dashboard env file to update.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print computed values without writing files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    return parser.parse_args(argv)


def _bool_string(value: bool) -> str:
    return "true" if value else "false"


def run(argv: list[str]) -> int:
    """Execute setup flow."""
    args = parse_args(argv)
    project_id = args.project_id.strip()
    if not project_id:
        print("ERROR: --project-id must not be empty.", file=sys.stderr)
        return 2

    management_key = args.management_key.strip() or os.getenv(args.management_key_env, "").strip()
    try:
        issuer, jwks_uri = discover_oidc_configuration(
            project_id=project_id,
            api_base=args.api_base,
        )
        key_count = validate_jwks(jwks_uri)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    management_validation = validate_management_key(
        project_id=project_id,
        management_key=management_key,
        api_base=args.api_base,
    )

    allow_local_password_auth = args.identity_mode in {"local", "hybrid_migration"}
    audience = args.audience.strip() or project_id

    core_updates = {
        "IDENTITY_PROVIDER_MODE": args.identity_mode,
        "ALLOW_LOCAL_PASSWORD_AUTH": _bool_string(allow_local_password_auth),
        "ALLOW_PRODUCTION_LOCAL_AUTH": "false",
        "DESCOPE_JWKS_URL": jwks_uri,
        "DESCOPE_ISSUER": issuer,
        "DESCOPE_AUDIENCE": audience,
    }

    dashboard_updates = {
        "NEXT_PUBLIC_DESCOPE_SIGNIN_URL": build_hosted_flow_url(
            auth_host_base=args.auth_host_base,
            project_id=project_id,
            flow_id=args.signin_flow_id.strip(),
        ),
        "NEXT_PUBLIC_DESCOPE_SIGNUP_URL": build_hosted_flow_url(
            auth_host_base=args.auth_host_base,
            project_id=project_id,
            flow_id=args.signup_flow_id.strip(),
        ),
    }

    if not args.dry_run:
        write_env_updates(Path(args.root_env), {**core_updates, **dashboard_updates})
        write_env_updates(Path(args.server_env), core_updates)
        write_env_updates(Path(args.dashboard_env), dashboard_updates)

    payload = {
        "success": True,
        "project_id": project_id,
        "identity_mode": args.identity_mode,
        "oidc_discovery": {
            "issuer": issuer,
            "jwks_url": jwks_uri,
            "jwks_key_count": key_count,
        },
        "management_key_validation": {
            "attempted": management_validation.attempted,
            "status_code": management_validation.status_code,
            "valid": management_validation.valid,
            "error_code": management_validation.error_code,
            "error_description": management_validation.error_description,
        },
        "env_files": {
            "root_env": args.root_env,
            "server_env": args.server_env,
            "dashboard_env": args.dashboard_env,
        },
        "updates": {
            "core": core_updates,
            "dashboard": dashboard_updates,
        },
        "dry_run": args.dry_run,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("Descope provider setup complete.")
        print(f"- project_id: {project_id}")
        print(f"- identity_mode: {args.identity_mode}")
        print(f"- issuer: {issuer}")
        print(f"- jwks_url: {jwks_uri}")
        print(f"- jwks_keys: {key_count}")
        if management_validation.attempted:
            print(
                "- management_key_validation: "
                f"status={management_validation.status_code}, valid={management_validation.valid}"
            )
            if management_validation.error_code:
                print(
                    "- management_key_error: "
                    f"{management_validation.error_code} "
                    f"{management_validation.error_description or ''}".strip()
                )
        else:
            print("- management_key_validation: skipped (no key provided)")
        print(f"- dry_run: {args.dry_run}")
        if not args.dry_run:
            print(f"- updated: {args.root_env}, {args.server_env}, {args.dashboard_env}")

    if management_validation.attempted and not management_validation.valid:
        # Keep setup usable even when management-key scope or value is wrong.
        # Return non-zero so CI/gates can enforce valid management credentials.
        return 1
    return 0


def main() -> int:
    """CLI entrypoint."""
    return run(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
