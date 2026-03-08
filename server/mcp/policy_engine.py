"""Policy engine for evaluating security policies against requests.

This module provides the PolicyEngine class for loading and evaluating
active security policies from the database against incoming requests.
Supports both pre-detector and post-detector rule evaluation.
"""

import ipaddress
import json
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from ea_agentgate.security.integrity import HMACIntegrity
from server.models import get_session_context
from server.models.security_policy_schemas import SecurityPolicy
from server.routers.auth_utils import get_secret_key
from server.utils.db import execute as db_execute

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Evaluate security policies against incoming requests.

    This class loads the active security policy from the database
    and evaluates it against requests at two stages:
    1. Pre-detector: Before threat detection runs (allow/deny/continue)
    2. Post-detector: After threat detection runs (escalate/downgrade)

    The engine verifies policy integrity using HMAC signatures and
    maintains a fallback to the last known good policy if tampering
    is detected.
    """

    def __init__(self) -> None:
        """Initialize the policy engine with empty policy state."""
        self._active_policy: dict[str, Any] | None = None
        self._last_known_good: dict[str, Any] | None = None

    def _get_hmac_integrity(self) -> HMACIntegrity:
        """Create HMAC integrity instance with server secret key.

        Returns:
            HMACIntegrity: Configured HMAC instance for policy verification.
        """
        key = get_secret_key().encode("utf-8")[:32].ljust(32, b"\x00")
        return HMACIntegrity(key)

    def _verify_policy_integrity(self, policy_json: dict[str, Any], signature: str) -> bool:
        """Verify HMAC signature of policy JSON.

        Args:
            policy_json: Policy rules dictionary.
            signature: HMAC signature to verify.

        Returns:
            bool: True if signature is valid, False otherwise.
        """
        integrity = self._get_hmac_integrity()
        policy_json_str = json.dumps(policy_json, sort_keys=True)
        return integrity.verify(policy_json_str, signature)

    async def load_active_policy(self) -> None:
        """Load the currently active policy from database.

        Queries the database for the active policy, verifies its
        HMAC signature, and loads it into memory. If the signature
        verification fails, logs an error and falls back to the
        last known good policy.
        """
        try:
            async with get_session_context() as session:
                stmt = select(SecurityPolicy).where(SecurityPolicy.is_active)
                result = await db_execute(session, stmt)
                policy_row = result.first()

                if not policy_row:
                    logger.info("No active security policy found")
                    self._active_policy = None
                    return

                policy = policy_row[0]
                if not self._verify_policy_integrity(policy.policy_json, policy.hmac_signature):
                    logger.error(
                        "Policy %s failed HMAC verification, using fallback",
                        policy.policy_id,
                    )
                    if self._last_known_good:
                        self._active_policy = self._last_known_good
                    return

                self._active_policy = policy.policy_json
                self._last_known_good = policy.policy_json
                logger.info(
                    "Loaded active policy %s (version %d)",
                    policy.policy_id,
                    policy.version,
                )
        except (RuntimeError, SQLAlchemyError, TypeError, ValueError) as exc:
            logger.error("Failed to load active policy: %s", str(exc))
            self._active_policy = None

    def _check_ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP address is within CIDR range.

        Args:
            ip: IP address string to check.
            cidr: CIDR notation string (e.g., "10.0.0.0/8").

        Returns:
            bool: True if IP is in CIDR range, False otherwise.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cidr, strict=False)
            return ip_obj in network
        except ValueError:
            logger.warning("Invalid IP or CIDR: %s, %s", ip, cidr)
            return False

    def evaluate_pre_detector(
        self,
        ip: str,
        endpoint: str,
    ) -> tuple[str, str]:
        """Evaluate pre-detector rules (allow/deny/continue).

        Evaluates rules before threat detection runs. Can allow
        (bypass detection), deny (block immediately), or continue
        (proceed to detection).

        Supported rule types:
        - ip_allow: Allow specific CIDR ranges
        - ip_deny: Block specific CIDR ranges
        - endpoint_allow: Skip detection for specific endpoints

        Args:
            ip: Client IP address.
            endpoint: Request endpoint path.

        Returns:
            Tuple of (action, reason) where action is "allow", "deny",
            or "continue".
        """
        if not self._active_policy:
            return ("continue", "No active policy")

        pre_rules = self._active_policy.get("pre_rules", [])

        for rule in pre_rules:
            rule_type = rule.get("type")

            if rule_type == "ip_allow":
                cidr = rule.get("cidr", "")
                if self._check_ip_in_cidr(ip, cidr):
                    return (
                        "allow",
                        f"IP {ip} is in allowlist {cidr}",
                    )

            if rule_type == "ip_deny":
                cidr = rule.get("cidr", "")
                if self._check_ip_in_cidr(ip, cidr):
                    return (
                        "deny",
                        f"IP {ip} is in denylist {cidr}",
                    )

            if rule_type == "endpoint_allow":
                allowed_endpoint = rule.get("endpoint", "")
                if endpoint == allowed_endpoint:
                    return (
                        "allow",
                        f"Endpoint {endpoint} is allowlisted",
                    )

        return ("continue", "No matching pre-detector rules")

    def evaluate_post_detector(
        self,
        threats: list[dict[str, Any]],
        severity: str,
        pattern_type: str,
    ) -> tuple[str, str]:
        """Evaluate post-detector rules (escalate/downgrade/allow).

        Evaluates rules after threat detection runs. Can escalate
        severity, downgrade severity, or allow (suppress false positives).

        Supported rule types:
        - severity_override: Change severity for matching pattern types
        - type_allow: Allow specific threat types (false positive
          suppression)

        Args:
            threats: List of detected threats.
            severity: Current threat severity.
            pattern_type: Type of threat pattern detected.

        Returns:
            Tuple of (action, reason) where action is "escalate",
            "downgrade", or "continue".
        """
        _ = threats

        if not self._active_policy:
            return ("continue", "No active policy")

        post_rules = self._active_policy.get("post_rules", [])

        for rule in post_rules:
            rule_type = rule.get("type")

            if rule_type == "severity_override":
                rule_pattern = rule.get("pattern_type", "")
                new_severity = rule.get("new_severity", "")

                if pattern_type == rule_pattern:
                    current_severity_upper = severity.upper()
                    new_severity_upper = new_severity.upper()

                    if new_severity_upper != current_severity_upper:
                        if self._is_severity_higher(new_severity_upper, current_severity_upper):
                            return (
                                "escalate",
                                (
                                    f"Severity escalated from "
                                    f"{current_severity_upper} to "
                                    f"{new_severity_upper}"
                                ),
                            )
                        return (
                            "downgrade",
                            (
                                f"Severity downgraded from "
                                f"{current_severity_upper} to "
                                f"{new_severity_upper}"
                            ),
                        )

            if rule_type == "type_allow":
                allowed_type = rule.get("pattern_type", "")
                if pattern_type == allowed_type:
                    return (
                        "allow",
                        f"Threat type {pattern_type} is allowlisted",
                    )

        return ("continue", "No matching post-detector rules")

    def _is_severity_higher(self, new: str, current: str) -> bool:
        """Compare severity levels.

        Args:
            new: New severity level.
            current: Current severity level.

        Returns:
            bool: True if new severity is higher than current.
        """
        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        new_level = severity_order.get(new, 0)
        current_level = severity_order.get(current, 0)

        return new_level > current_level
