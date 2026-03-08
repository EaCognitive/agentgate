"""
Threat analysis and detection methods for ThreatDetector.

Contains detection logic for:
- Brute force attacks
- Privilege escalation
- Data exfiltration
- New location detection
- Input attack patterns
- Request threat aggregation
"""
# pylint: disable=protected-access

from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

from .threat_detector_events import (
    ThreatSeverity,
    ThreatType,
    ThreatEvent,
    ThreatEventContext,
    ThreatEventIdentification,
    ThreatEventPayload,
)
from .threat_detector_utils import (
    RequestCheckResults,
    ThreatDetectionResult,
    pattern_to_threat_type,
    pattern_to_threat_severity,
    is_suspicious_user_agent,
)

if TYPE_CHECKING:
    from .threat_detector import UserProtocol


def check_brute_force(
    detector_instance: Any,
    ip: str,
    email: str,
    success: bool,
    user_agent: str | None = None,
) -> ThreatEvent | None:
    """Detect brute force login attempts (10+/1h=HIGH, 20+=CRITICAL+block)."""
    detector_instance._increment_stat("total_checks")
    now = time.time()

    if success:
        # Reset counter on successful login
        detector_instance._clear_failed_logins(ip)
        return None

    # Record failed attempt
    count = detector_instance._record_failed_login(ip, now)

    # Check thresholds
    if count >= detector_instance.BRUTE_FORCE_THRESHOLD_CRITICAL:
        detector_instance._increment_stat("brute_force_detected")

        # Auto-block IP
        if detector_instance._auto_block:
            detector_instance.block_ip(
                ip, "brute_force_critical", detector_instance.DEFAULT_BLOCK_DURATION
            )

        detector_instance._record_metric("brute_force.critical")

        description = f"Critical brute force attack: {count} failed attempts from {ip}"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.BRUTE_FORCE,
                severity=ThreatSeverity.CRITICAL,
                timestamp=now,
            ),
            payload=ThreatEventPayload(
                ip_address=ip,
                blocked=True,
                details={
                    "failed_attempts": count,
                    "target_email": email,
                    "action": "ip_blocked",
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_agent=user_agent,
                action_taken="ip_blocked",
            ),
        )

        detector_instance._send_alert(event)
        return event

    if count >= detector_instance.BRUTE_FORCE_THRESHOLD_HIGH:
        detector_instance._increment_stat("brute_force_detected")
        detector_instance._state.suspicious_ips.add(ip)
        detector_instance._record_metric("brute_force.high")

        description = f"Brute force attack detected: {count} failed attempts from {ip}"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.BRUTE_FORCE,
                severity=ThreatSeverity.HIGH,
                timestamp=now,
            ),
            payload=ThreatEventPayload(
                ip_address=ip,
                details={
                    "failed_attempts": count,
                    "target_email": email,
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_agent=user_agent,
            ),
        )

        detector_instance._send_alert(event)
        return event

    return None


def check_privilege_escalation(
    detector_instance: Any,
    user: UserProtocol,
    action: str,
    target_role: str | None = None,
    ip: str | None = None,
) -> ThreatEvent | None:
    """Detect privilege escalation (non-admin admin actions, role escalation)."""
    detector_instance._increment_stat("total_checks")
    now = time.time()
    ip_address = ip or "unknown"

    # Admin-only actions attempted by non-admin
    if action.startswith("admin_") and user.role != "admin":
        detector_instance._increment_stat("threats_detected")
        detector_instance._record_metric("privilege_escalation")

        description = f"User {user.email} (role: {user.role}) attempted admin action: {action}"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.PRIVILEGE_ESCALATION,
                severity=ThreatSeverity.CRITICAL,
                timestamp=now,
            ),
            payload=ThreatEventPayload(
                ip_address=ip_address,
                details={
                    "user_role": user.role,
                    "attempted_action": action,
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_id=user.id,
                user_email=user.email,
            ),
        )

        detector_instance._send_alert(event)
        return event

    # Role escalation attempt
    if target_role and target_role == "admin" and user.role != "admin":
        detector_instance._increment_stat("threats_detected")
        detector_instance._record_metric("role_escalation")

        description = f"User {user.email} attempted to escalate to admin role"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.ROLE_ESCALATION,
                severity=ThreatSeverity.CRITICAL,
                timestamp=now,
            ),
            payload=ThreatEventPayload(
                ip_address=ip_address,
                details={
                    "current_role": user.role,
                    "target_role": target_role,
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_id=user.id,
                user_email=user.email,
            ),
        )

        detector_instance._send_alert(event)
        return event

    return None


def check_data_exfiltration(
    detector_instance: Any,
    user: UserProtocol,
    endpoint: str,
    response_size: int,
    ip: str | None = None,
) -> ThreatEvent | None:
    """Detect unusual data access (high request rate >100/min, large responses >10MB)."""
    detector_instance._increment_stat("total_checks")
    now = time.time()
    ip_address = ip or "unknown"

    # Track request rate
    rate_key = f"{user.id}:{endpoint}"
    rate = detector_instance._record_request(rate_key, now)

    # Check high request rate
    if rate > detector_instance.HIGH_REQUEST_RATE_THRESHOLD:
        detector_instance._increment_stat("threats_detected")
        detector_instance._record_metric("data_exfiltration.high_rate")

        description = f"High request rate detected: {rate} req/min to {endpoint}"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.DATA_EXFILTRATION,
                severity=ThreatSeverity.HIGH,
                timestamp=now,
            ),
            payload=ThreatEventPayload(
                ip_address=ip_address,
                details={
                    "endpoint": endpoint,
                    "request_rate": rate,
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_id=user.id,
                user_email=user.email,
                endpoint=endpoint,
            ),
        )

        detector_instance._send_alert(event)
        return event

    # Check large response
    response_size_mb = response_size / (1024 * 1024)
    if response_size_mb > detector_instance.LARGE_RESPONSE_SIZE_MB:
        detector_instance._increment_stat("threats_detected")
        detector_instance._record_metric("data_exfiltration.large_response")

        description = f"Large data transfer: {response_size_mb:.2f}MB from {endpoint}"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.DATA_EXFILTRATION,
                severity=ThreatSeverity.MEDIUM,
                timestamp=now,
            ),
            payload=ThreatEventPayload(
                ip_address=ip_address,
                details={
                    "endpoint": endpoint,
                    "response_size_mb": round(response_size_mb, 2),
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_id=user.id,
                user_email=user.email,
                endpoint=endpoint,
            ),
        )

        detector_instance._send_alert(event)
        return event

    return None


def check_new_location(
    detector_instance: Any,
    user: UserProtocol,
    ip: str,
    user_agent: str,
) -> ThreatEvent | None:
    """Detect login from unusual location by tracking known IPs per user."""
    detector_instance._increment_stat("total_checks")
    now = time.time()

    # Get known IPs for user
    known_ips = detector_instance._get_user_known_ips(user.id)

    if ip not in known_ips:
        # Add to known IPs
        detector_instance._add_user_known_ip(user.id, ip)

        # Only alert if user has previous known IPs (not first login)
        if len(known_ips) > 0:
            detector_instance._record_metric("new_location")

            description = f"Login from new location for {user.email}: {ip}"
            event = ThreatEvent(
                identification=ThreatEventIdentification(
                    event_id=detector_instance._generate_event_id(),
                    event_type=ThreatType.NEW_LOCATION,
                    severity=ThreatSeverity.MEDIUM,
                    timestamp=now,
                ),
                payload=ThreatEventPayload(
                    ip_address=ip,
                    details={
                        "new_ip": ip,
                        "known_ips_count": len(known_ips),
                        "user_agent": user_agent,
                        "description": description,
                    },
                ),
                context=ThreatEventContext(
                    user_id=user.id,
                    user_email=user.email,
                    user_agent=user_agent,
                ),
            )

            detector_instance._send_alert(event)
            return event

    return None


def build_input_attack_event(
    detector_instance: Any,
    ip: str,
    field_name: str,
    match: Any,
    *,
    user_id: int | None,
    user_email: str | None,
) -> tuple[ThreatEvent, bool]:
    """Build threat event for input attack match."""
    threat_type_str = pattern_to_threat_type(match.pattern_type)
    severity_str = pattern_to_threat_severity(match.severity)

    # Convert string types to enums
    threat_type = ThreatType(threat_type_str)
    severity = ThreatSeverity(severity_str)

    description = f"Attack pattern detected in {field_name}: {match.pattern_name}"

    event = ThreatEvent(
        identification=ThreatEventIdentification(
            event_id=detector_instance._generate_event_id(),
            event_type=threat_type,
            severity=severity,
            timestamp=time.time(),
        ),
        payload=ThreatEventPayload(
            ip_address=ip,
            details={
                "field": field_name,
                "pattern_name": match.pattern_name,
                "matched_value": match.matched_value[:100],
                "confidence": match.confidence,
                "description": description,
            },
            pattern_matches=[match.to_dict()],
        ),
        context=ThreatEventContext(
            user_id=user_id,
            user_email=user_email,
        ),
    )

    should_block = severity == ThreatSeverity.CRITICAL
    if should_block:
        detector_instance._record_metric(f"attack.{match.pattern_type}.blocked")

    return event, should_block


def check_input_attacks(
    detector_instance: Any,
    value: str,
    field_name: str,
    ip: str,
    *,
    user_id: int | None = None,
    user_email: str | None = None,
) -> ThreatDetectionResult:
    """Check input for attack patterns (SQLi, XSS, etc.)."""
    start_time = time.time()
    detector_instance._increment_stat("total_checks")

    threats: list[ThreatEvent] = []
    should_block = False

    # Run pattern matching
    matches = detector_instance._pattern_matcher.match_all(value)

    if matches:
        detector_instance._increment_stat("injection_detected")

        # Group by pattern type
        for match in matches:
            event, is_critical = build_input_attack_event(
                detector_instance, ip, field_name, match, user_id=user_id, user_email=user_email
            )
            threats.append(event)
            detector_instance._send_alert(event)

            if is_critical:
                should_block = True

    processing_time = (time.time() - start_time) * 1000

    return ThreatDetectionResult(
        is_threat=len(threats) > 0,
        threats=threats,
        should_block=should_block,
        block_reason="attack_pattern_detected" if should_block else None,
        processing_time_ms=processing_time,
    )


def check_request_body(
    detector_instance: Any,
    body: dict[str, Any],
    ip: str,
    user_id: int | None,
    user_email: str | None,
) -> tuple[list[ThreatEvent], bool]:
    """Check request body fields for attack patterns."""
    threats: list[ThreatEvent] = []
    should_block = False

    for field_name, value in body.items():
        if isinstance(value, str) and len(value) > 0:
            result = check_input_attacks(
                detector_instance,
                value=value,
                field_name=field_name,
                ip=ip,
                user_id=user_id,
                user_email=user_email,
            )
            threats.extend(result.threats)
            if result.should_block:
                should_block = True

    return threats, should_block


def check_request_query(
    detector_instance: Any,
    endpoint: str,
    ip: str,
    user_id: int | None,
    user_email: str | None,
) -> tuple[list[ThreatEvent], bool]:
    """Check query parameters for attack patterns."""
    if "?" not in endpoint:
        return [], False

    query_string = endpoint.split("?", 1)[1]
    result = check_input_attacks(
        detector_instance,
        value=query_string,
        field_name="query_params",
        ip=ip,
        user_id=user_id,
        user_email=user_email,
    )
    return result.threats, result.should_block


def check_request_headers(
    detector_instance: Any,
    headers: dict[str, str],
    ip: str,
    user_id: int | None,
    user_email: str | None,
) -> list[ThreatEvent]:
    """Check request headers for suspicious patterns."""
    threats: list[ThreatEvent] = []
    user_agent = headers.get("user-agent", "")

    if is_suspicious_user_agent(user_agent):
        description = f"Suspicious user agent detected: {user_agent[:50]}"
        event = ThreatEvent(
            identification=ThreatEventIdentification(
                event_id=detector_instance._generate_event_id(),
                event_type=ThreatType.SUSPICIOUS_USER_AGENT,
                severity=ThreatSeverity.LOW,
                timestamp=time.time(),
            ),
            payload=ThreatEventPayload(
                ip_address=ip,
                details={
                    "user_agent": user_agent,
                    "description": description,
                },
            ),
            context=ThreatEventContext(
                user_id=user_id,
                user_email=user_email,
                user_agent=user_agent,
            ),
        )
        threats.append(event)

    return threats


def aggregate_request_threats(
    detector_instance: Any,
    body: dict[str, Any] | None,
    endpoint: str,
    headers: dict[str, str],
    ip: str,
    *,
    user_id: int | None,
    user_email: str | None,
) -> RequestCheckResults:
    """Aggregate threats from all request components."""
    threats: list[ThreatEvent] = []
    should_block = False

    # Check request body for attacks
    if body:
        body_threats, body_blocked = check_request_body(
            detector_instance, body, ip, user_id, user_email
        )
        threats.extend(body_threats)
        should_block = should_block or body_blocked

    # Check URL parameters
    query_threats, query_blocked = check_request_query(
        detector_instance, endpoint, ip, user_id, user_email
    )
    threats.extend(query_threats)
    should_block = should_block or query_blocked

    # Check suspicious headers
    header_threats = check_request_headers(detector_instance, headers, ip, user_id, user_email)
    threats.extend(header_threats)

    return RequestCheckResults(threats=threats, should_block=should_block)


__all__ = [
    "check_brute_force",
    "check_privilege_escalation",
    "check_data_exfiltration",
    "check_new_location",
    "build_input_attack_event",
    "check_input_attacks",
    "check_request_body",
    "check_request_query",
    "check_request_headers",
    "aggregate_request_threats",
]
