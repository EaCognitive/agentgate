"""
Input and request-level threat detection strategies.

Provides pattern-based detection for:
- SQL injection
- Cross-site scripting (XSS)
- Path traversal
- Command injection
- Request body, query, and header analysis
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from . import threat_detector_analysis
from .threat_detector_events import ThreatEvent
from .threat_detector_utils import (
    RequestCheckResults,
    ThreatDetectionResult,
)

if TYPE_CHECKING:
    from .threat_detector import ThreatDetector


class InputDetector:
    """
    Detects input-based attack patterns.

    Scans request bodies, query parameters, and headers
    for injection attacks, XSS, path traversal, and
    other pattern-based threats.
    """

    def check_input_attacks(
        self,
        detector: ThreatDetector,
        value: str,
        field_name: str,
        ip: str,
        *,
        user_id: int | None = None,
        user_email: str | None = None,
    ) -> ThreatDetectionResult:
        """
        Check input for attack patterns.

        Scans the value against all registered threat
        patterns (SQLi, XSS, command injection, etc.).

        Args:
            detector: Parent ThreatDetector instance.
            value: Input string to scan.
            field_name: Name of the input field.
            ip: Source IP address.
            user_id: Associated user ID.
            user_email: Associated user email.

        Returns:
            ThreatDetectionResult with findings.
        """
        return threat_detector_analysis.check_input_attacks(
            detector,
            value,
            field_name,
            ip,
            user_id=user_id,
            user_email=user_email,
        )

    def build_input_attack_event(
        self,
        detector: ThreatDetector,
        ip: str,
        field_name: str,
        match: Any,
        *,
        user_id: int | None,
        user_email: str | None,
    ) -> tuple[ThreatEvent, bool]:
        """
        Build threat event for input attack match.

        Args:
            detector: Parent ThreatDetector instance.
            ip: Source IP address.
            field_name: Name of the matched field.
            match: Pattern match object.
            user_id: Associated user ID.
            user_email: Associated user email.

        Returns:
            Tuple of (ThreatEvent, should_block).
        """
        return threat_detector_analysis.build_input_attack_event(
            detector,
            ip,
            field_name,
            match,
            user_id=user_id,
            user_email=user_email,
        )

    def check_request_body(
        self,
        detector: ThreatDetector,
        body: dict[str, Any],
        ip: str,
        *,
        user_id: int | None,
        user_email: str | None,
    ) -> tuple[list[ThreatEvent], bool]:
        """
        Check request body fields for attack patterns.

        Args:
            detector: Parent ThreatDetector instance.
            body: Request body dictionary.
            ip: Source IP address.
            user_id: Associated user ID.
            user_email: Associated user email.

        Returns:
            Tuple of (threats, should_block).
        """
        return threat_detector_analysis.check_request_body(
            detector,
            body,
            ip,
            user_id,
            user_email,
        )

    def check_request_query(
        self,
        detector: ThreatDetector,
        endpoint: str,
        ip: str,
        *,
        user_id: int | None,
        user_email: str | None,
    ) -> tuple[list[ThreatEvent], bool]:
        """
        Check query parameters for attack patterns.

        Args:
            detector: Parent ThreatDetector instance.
            endpoint: Request endpoint with query.
            ip: Source IP address.
            user_id: Associated user ID.
            user_email: Associated user email.

        Returns:
            Tuple of (threats, should_block).
        """
        return threat_detector_analysis.check_request_query(
            detector, endpoint, ip, user_id, user_email
        )

    def check_request_headers(
        self,
        detector: ThreatDetector,
        headers: dict[str, str],
        ip: str,
        *,
        user_id: int | None,
        user_email: str | None,
    ) -> list[ThreatEvent]:
        """
        Check request headers for suspicious patterns.

        Args:
            detector: Parent ThreatDetector instance.
            headers: Request headers dictionary.
            ip: Source IP address.
            user_id: Associated user ID.
            user_email: Associated user email.

        Returns:
            List of detected threat events.
        """
        return threat_detector_analysis.check_request_headers(
            detector, headers, ip, user_id, user_email
        )

    def aggregate_request_threats(
        self,
        detector: ThreatDetector,
        *,
        body: dict[str, Any] | None,
        endpoint: str,
        headers: dict[str, str],
        ip: str,
        user_id: int | None,
        user_email: str | None,
    ) -> RequestCheckResults:
        """
        Aggregate threats from all request components.

        Args:
            detector: Parent ThreatDetector instance.
            body: Optional request body.
            endpoint: Request endpoint.
            headers: Request headers.
            ip: Source IP address.
            user_id: Associated user ID.
            user_email: Associated user email.

        Returns:
            Aggregated RequestCheckResults.
        """
        return threat_detector_analysis.aggregate_request_threats(
            detector,
            body,
            endpoint,
            headers,
            ip,
            user_id=user_id,
            user_email=user_email,
        )


__all__ = [
    "InputDetector",
]
