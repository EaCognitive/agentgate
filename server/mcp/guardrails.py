"""MCP Guardrails - Hardcoded safety layer for AI operator actions.

This module enforces safety limits on MCP operations that CANNOT be bypassed
by AI operators. The guardrails configuration file can ONLY be modified by
humans with direct file system access.

SECURITY ARCHITECTURE:
1. Guardrails config is read from a protected file (not API-modifiable)
2. All destructive MCP operations are checked against guardrails
3. Blocked operations return 403 with explanation
4. Operations requiring approval create approval requests
5. No MCP tool or API endpoint can modify the guardrails file

This ensures humans remain in ultimate control of what AI operators can do.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from server.models.database import get_sync_engine
from server.runtime.profile import (
    RuntimeProfile,
    resolve_runtime_profile as resolve_runtime_profile_enum,
)
from server.policy_governance.kernel.enforcement import SecurityEnforcementError, enforce_action

logger = logging.getLogger(__name__)

GUARDRAILS_RELEASES_TABLE = "mcp_guardrails_releases"
GUARDRAILS_DEFINITIONS_TABLE = "mcp_guardrails_definitions"
_LOAD_ACTIVE_RELEASE_QUERY = text(
    """
    SELECT git_sha, release_hash
    FROM mcp_guardrails_releases
    WHERE is_active = :active_true OR is_active = 1
    ORDER BY activated_at DESC
    LIMIT 1
    """
)
_LOAD_RELEASE_DEFINITIONS_QUERY = text(
    """
    SELECT definition_json
    FROM mcp_guardrails_definitions
    WHERE git_sha = :git_sha
    ORDER BY source_file ASC, document_index ASC
    """
)

# Guardrails file locations (checked in order)
GUARDRAILS_PATHS = [
    Path("/etc/agentgate/mcp_guardrails.yaml"),  # System-wide (production)
    Path.home() / ".ea-agentgate" / "mcp_guardrails.yaml",  # User-specific
    Path.home() / ".agentgate" / "mcp_guardrails.yaml",  # Legacy user-specific
    Path(__file__).parent.parent.parent / "mcp_guardrails.yaml",  # Project root
]

# Default guardrails (used if no config file exists)
# These are the MINIMUM safety requirements - hardcoded and immutable
DEFAULT_GUARDRAILS: dict[str, Any] = {
    "version": "1.0",
    "blocked_operations": [
        # These operations are ALWAYS blocked for AI operators
        # They can only be performed via direct human interaction
    ],
    "require_approval": [
        # These operations require human approval before execution
        "block_ip_temp",  # Blocking IPs affects availability
        "revoke_token",  # Revoking sessions affects users
        "apply_policy",  # Policies affect security posture
        "create_incident",  # Incidents trigger alerts/escalations
        "unlock_policy",  # Unlocking policies is sensitive
        "mcp_users_create",  # Creating users is sensitive
        "mcp_users_update",  # Modifying users is sensitive
        "mcp_settings_update",  # System settings require explicit human approval
    ],
    "rate_limits": {
        # Maximum operations per hour for destructive actions
        "block_ip_temp": 10,
        "revoke_token": 5,
        "apply_policy": 3,
        "create_incident": 10,
    },
    "safety": {
        "require_confirm_flow": True,  # Require preview/confirm for destructive ops
        "max_ips_per_session": 10,  # Max IPs blockable in one MCP session
        "destructive_cooldown_seconds": 5,  # Min time between destructive ops
        "log_all_operations": True,  # Log every MCP operation for audit
    },
}

# Operations that are HARDCODED as blocked - cannot be overridden by config
# This is the ultimate safety net that no configuration can bypass
HARDCODED_BLOCKED = frozenset(
    {
        # No operation to modify guardrails (this file/config)
        "modify_guardrails",
        "update_guardrails",
        "delete_guardrails",
        # No operation to disable audit logging
        "disable_audit",
        "clear_audit",
        # No operation to bypass approval workflow
        "bypass_approval",
        "auto_approve",
    }
)

# Operations that ALWAYS require approval - cannot be made auto-approve
HARDCODED_REQUIRE_APPROVAL = frozenset(
    {
        "block_ip_temp",
        "revoke_token",
        "apply_policy",
        "mcp_settings_update",
    }
)


@dataclass
class GuardrailsConfig:
    """Parsed guardrails configuration."""

    version: str = "1.0"
    blocked_operations: set[str] = field(default_factory=set)
    require_approval: set[str] = field(default_factory=set)
    rate_limits: dict[str, int] = field(default_factory=dict)
    safety: dict[str, Any] = field(default_factory=dict)
    config_path: Path | None = None
    config_hash: str = ""

    def is_blocked(self, operation: str) -> bool:
        """Check if an operation is blocked."""
        # Check hardcoded blocks first (immutable)
        if operation in HARDCODED_BLOCKED:
            return True
        return operation in self.blocked_operations

    def requires_approval(self, operation: str) -> bool:
        """Check if an operation requires human approval."""
        # Check hardcoded requirements first (immutable)
        if operation in HARDCODED_REQUIRE_APPROVAL:
            return True
        return operation in self.require_approval

    def get_rate_limit(self, operation: str) -> int | None:
        """Get rate limit for an operation (ops/hour)."""
        return self.rate_limits.get(operation)


class _GuardrailsCacheState:
    """Module-level singleton for guardrails config cache."""

    config: GuardrailsConfig | None = None
    config_hash: str = ""

    @classmethod
    def get_cached(cls) -> tuple[GuardrailsConfig | None, str]:
        """Return the cached guardrails config and its hash."""
        return cls.config, cls.config_hash

    @classmethod
    def store(cls, config: GuardrailsConfig, config_hash: str) -> None:
        """Update the cached guardrails config state."""
        cls.config = config
        cls.config_hash = config_hash


def resolve_runtime_profile() -> str:
    """Resolve runtime profile from shared runtime profile policy."""
    return resolve_runtime_profile_enum().value


def is_strict_runtime_profile(profile: str | None = None) -> bool:
    """Return True when strict cloud profile controls are active."""
    resolved_profile = profile or resolve_runtime_profile()
    return resolved_profile == RuntimeProfile.CLOUD_STRICT.value


def _merge_user_guardrails(config_data: dict[str, Any], user_config: dict[str, Any]) -> None:
    """Merge user-supplied guardrails into defaults with safety-preserving semantics."""
    user_blocked = set(user_config.get("blocked_operations", []))
    config_data["blocked_operations"] = list(set(config_data["blocked_operations"]) | user_blocked)

    user_approval = set(user_config.get("require_approval", []))
    config_data["require_approval"] = list(set(config_data["require_approval"]) | user_approval)

    for operation, limit in user_config.get("rate_limits", {}).items():
        default_limit = config_data["rate_limits"].get(operation, float("inf"))
        config_data["rate_limits"][operation] = min(limit, default_limit)

    user_safety = user_config.get("safety", {})
    for key, value in user_safety.items():
        if key not in config_data["safety"]:
            continue
        default_value = config_data["safety"][key]
        if isinstance(default_value, bool):
            config_data["safety"][key] = default_value or value
            continue
        if isinstance(default_value, (int, float)):
            if "cooldown" in key or "min" in key:
                config_data["safety"][key] = max(default_value, value)
                continue
            config_data["safety"][key] = min(default_value, value)


def _load_guardrails_from_database() -> tuple[list[dict[str, Any]], str, str] | None:
    """Load active guardrails release documents from the database."""
    try:
        engine = get_sync_engine()
    except (RuntimeError, SQLAlchemyError) as exc:
        logger.warning("Guardrails DB loader unavailable: %s", exc)
        return None

    with engine.connect() as connection:
        try:
            release_row = (
                connection.execute(
                    _LOAD_ACTIVE_RELEASE_QUERY,
                    {"active_true": True},
                )
                .mappings()
                .first()
            )
        except SQLAlchemyError as exc:
            logger.warning("Guardrails release lookup failed: %s", exc)
            return None

        if release_row is None:
            return None

        definition_rows = (
            connection.execute(
                _LOAD_RELEASE_DEFINITIONS_QUERY,
                {"git_sha": release_row["git_sha"]},
            )
            .scalars()
            .all()
        )

    documents: list[dict[str, Any]] = []
    for row in definition_rows:
        if not isinstance(row, str):
            continue
        try:
            parsed = json.loads(row)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            documents.append(parsed)

    if not documents:
        logger.warning("Guardrails DB loader unavailable due to engine initialization failure.")
        return None

    return documents, str(release_row["release_hash"]), str(release_row["git_sha"])


def _compute_file_hash(path: Path) -> str:
    """Compute SHA256 hash of file for change detection."""
    if not path.exists():
        return ""
    try:
        content = path.read_bytes()
        return hashlib.sha256(content).hexdigest()[:16]
    except OSError:
        return ""


def _find_guardrails_file() -> Path | None:
    """Find the guardrails config file."""
    for path in GUARDRAILS_PATHS:
        if path.exists():
            logger.info("Found MCP guardrails config at: %s", path)
            return path
    return None


def _load_guardrails_from_file(path: Path) -> dict[str, Any]:
    """Load guardrails config from YAML file."""
    try:
        with path.open() as f:
            config = yaml.safe_load(f) or {}
        return config
    except (yaml.YAMLError, OSError) as exc:
        logger.error("Failed to load guardrails from %s: %s", path, exc)
        return {}


def _runtime_request_fields(
    operation: str,
    runtime_context: dict[str, Any],
) -> tuple[str, str, str | None, Any, str]:
    """Extract normalized enforcement request fields from runtime context."""
    principal = str(runtime_context.get("principal", "mcp:operator"))
    resource = str(runtime_context.get("resource", f"mcp://operation/{operation}"))
    tenant_id = runtime_context.get("tenant_id")
    delegation_ref = runtime_context.get("delegation_ref")
    chain_id = str(runtime_context.get("evidence_chain_id", "mcp-operations"))
    return principal, resource, tenant_id, delegation_ref, chain_id


def _requires_human_approval(
    guardrails: GuardrailsConfig,
    operation: str,
    proof_payload: dict[str, Any],
) -> bool:
    """Return whether the proof payload indicates a human approval requirement."""
    if guardrails.requires_approval(operation):
        return True
    for trace_row in proof_payload.get("trace", []):
        witness = trace_row.get("witness", {})
        failures = witness.get("failures", [])
        if any(item.get("reason") == "approval_missing" for item in failures):
            return True
    return False


def load_guardrails(force_reload: bool = False) -> GuardrailsConfig:
    """Load guardrails configuration.

    Checks for config file changes and reloads if necessary.
    Falls back to default guardrails if no config file exists.

    Args:
        force_reload: Force reload even if cache is valid.

    Returns:
        GuardrailsConfig with merged settings.
    """
    runtime_profile = resolve_runtime_profile()
    strict_profile = is_strict_runtime_profile(runtime_profile)
    config_path: Path | None = None
    current_hash = "default"
    database_source = None

    if strict_profile:
        database_source = _load_guardrails_from_database()
        if database_source is not None:
            _, release_hash, git_sha = database_source
            current_hash = f"db:{release_hash}"
            config_path = Path(f"db://{git_sha}")
        else:
            if os.getenv("TESTING", "").strip().lower() == "true":
                logger.warning(
                    "No active DB-backed guardrails release in cloud_strict profile; "
                    "falling back to file-based guardrails in TESTING mode."
                )
            else:
                message = (
                    "No active DB-backed guardrails release is available for "
                    "cloud_strict profile."
                )
                logger.error(message)
                raise RuntimeError(message)

    if database_source is None:
        config_path = _find_guardrails_file()
        current_hash = _compute_file_hash(config_path) if config_path else "default"

    # Return cached config if unchanged
    cached_config, cached_hash = _GuardrailsCacheState.get_cached()
    if not force_reload and cached_config and cached_hash == current_hash:
        return cached_config

    # Start with defaults
    config_data: dict[str, Any] = dict(DEFAULT_GUARDRAILS)

    if database_source is not None:
        documents, _, _ = database_source
        for user_config in documents:
            _merge_user_guardrails(config_data, user_config)
    elif config_path:
        user_config = _load_guardrails_from_file(config_path)
        if user_config:
            _merge_user_guardrails(config_data, user_config)

    # Build config object
    guardrails = GuardrailsConfig(
        version=config_data.get("version", "1.0"),
        blocked_operations=set(config_data.get("blocked_operations", [])),
        require_approval=set(config_data.get("require_approval", [])),
        rate_limits=config_data.get("rate_limits", {}),
        safety=config_data.get("safety", {}),
        config_path=config_path,
        config_hash=current_hash,
    )

    # Cache and return
    _GuardrailsCacheState.store(guardrails, current_hash)

    logger.info(
        "Loaded MCP guardrails: %d blocked, %d require approval, %d rate limits",
        len(guardrails.blocked_operations),
        len(guardrails.require_approval),
        len(guardrails.rate_limits),
    )

    return guardrails


@dataclass
class GuardrailCheckResult:
    """Result of a guardrail check."""

    allowed: bool
    reason: str
    requires_approval: bool = False
    approval_id: str | None = None
    rate_limit_remaining: int | None = None
    decision_certificate: dict[str, Any] | None = None


async def check_operation(
    operation: str,
    context: dict[str, Any] | None = None,
) -> GuardrailCheckResult:
    """Check if an MCP operation is allowed by guardrails.

    Args:
        operation: The MCP operation name (e.g., "block_ip_temp").
        context: Optional context (agent_id, session_id, etc.).

    Returns:
        GuardrailCheckResult indicating if operation is allowed.
    """
    guardrails = load_guardrails()

    runtime_context = dict(context or {})
    runtime_context.setdefault("authenticated", True)
    runtime_context.setdefault("direct_access", True)
    runtime_context.setdefault("direct_permit", False)

    principal, resource, tenant_id, delegation_ref, chain_id = _runtime_request_fields(
        operation,
        runtime_context,
    )

    try:
        certificate = await enforce_action(
            principal=principal,
            action=operation,
            resource=resource,
            runtime_context=runtime_context,
            delegation_ref=delegation_ref,
            tenant_id=tenant_id,
            chain_id=chain_id,
        )
        return GuardrailCheckResult(
            allowed=True,
            reason="Operation permitted by proof-carrying guardrail enforcement",
            decision_certificate=certificate.model_dump(mode="json"),
        )
    except SecurityEnforcementError as exc:
        certificate_payload = exc.certificate.model_dump(mode="json")
        proof_payload = certificate_payload.get("proof_payload", {})
        counterexample = proof_payload.get("counterexample", {})
        if _requires_human_approval(guardrails, operation, proof_payload):
            logger.info(
                "MCP operation REQUIRES APPROVAL: %s (context: %s)",
                operation,
                context,
            )
            return GuardrailCheckResult(
                allowed=False,
                requires_approval=True,
                reason=(
                    f"Operation '{operation}' requires human approval. "
                    "A human operator must approve this action before execution."
                ),
                decision_certificate=certificate_payload,
            )

        logger.warning(
            "MCP operation BLOCKED by formal guardrails: %s (context: %s)",
            operation,
            context,
        )
        blocked_reason = "Action inadmissible under formal proof constraints."
        matched_rule = counterexample.get("witness")
        if isinstance(matched_rule, dict) and matched_rule.get("type") == "guardrail_block":
            blocked_reason = (
                f"Operation '{operation}' is blocked by MCP guardrails. "
                "This operation can only be performed by humans with direct system access."
            )

        return GuardrailCheckResult(
            allowed=False,
            reason=blocked_reason,
            decision_certificate=certificate_payload,
        )


# Disclaimer text shown when MCP is initialized
MCP_DISCLAIMER = """
================================================================================
                        MCP OPERATOR SAFETY NOTICE
================================================================================

This MCP interface allows AI assistants to help with security operations.

IMPORTANT SAFETY INFORMATION:

1. HUMAN OVERSIGHT REQUIRED
   - All destructive operations require human approval
   - Blocked operations cannot be performed by AI operators
   - Humans can customize guardrails via config file

2. GUARDRAILS ENFORCED
   - Operations like IP blocking, token revocation require approval
   - Rate limits prevent runaway operations
   - All actions are logged for audit

3. AI LIMITATIONS
   - AI operators CANNOT modify guardrails or safety settings
   - AI operators CANNOT disable audit logging
   - AI operators CANNOT bypass approval workflows

4. CONFIGURATION
   - Guardrails config: ~/.ea-agentgate/mcp_guardrails.yaml
   - Only modifiable by humans with file system access
   - Changes require server restart

For security concerns, contact your system administrator.

================================================================================
"""


def get_disclaimer() -> str:
    """Get the MCP safety disclaimer text."""
    return MCP_DISCLAIMER


def get_guardrails_status() -> dict[str, Any]:
    """Get current guardrails status for display."""
    guardrails = load_guardrails()
    runtime_profile = resolve_runtime_profile()
    return {
        "version": guardrails.version,
        "config_path": str(guardrails.config_path) if guardrails.config_path else None,
        "runtime_profile": runtime_profile,
        "strict_profile": is_strict_runtime_profile(runtime_profile),
        "blocked_operations": sorted(guardrails.blocked_operations),
        "require_approval": sorted(guardrails.require_approval),
        "rate_limits": guardrails.rate_limits,
        "safety_settings": guardrails.safety,
        "hardcoded_blocked": sorted(HARDCODED_BLOCKED),
        "hardcoded_require_approval": sorted(HARDCODED_REQUIRE_APPROVAL),
    }
