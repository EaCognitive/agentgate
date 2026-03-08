"""
Behavioral threat detection strategies.

Provides detection for behavioral threats including:
- Brute force login attacks
- Privilege escalation attempts
- Data exfiltration patterns
- New location anomalies
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import threat_detector_analysis
from .threat_detector_events import ThreatEvent

if TYPE_CHECKING:
    from .threat_detector import ThreatDetector, UserProtocol


class BehavioralDetector:
    """
    Detects behavioral threat patterns.

    Analyzes user and IP behavior for anomalies such as
    brute force attacks, privilege escalation, data
    exfiltration, and unusual access locations.
    """

    def check_brute_force(
        self,
        detector: ThreatDetector,
        ip: str,
        email: str,
        success: bool,
        *,
        user_agent: str | None = None,
    ) -> ThreatEvent | None:
        """
        Detect brute force login attempts.

        Triggers at 10+ failures/hour (HIGH) and
        20+ failures/hour (CRITICAL with auto-block).

        Args:
            detector: Parent ThreatDetector instance.
            ip: Source IP address.
            email: Target email address.
            success: Whether login succeeded.
            user_agent: Client user agent string.

        Returns:
            ThreatEvent if threat detected, else None.
        """
        return threat_detector_analysis.check_brute_force(detector, ip, email, success, user_agent)

    def check_privilege_escalation(
        self,
        detector: ThreatDetector,
        user: UserProtocol,
        action: str,
        *,
        target_role: str | None = None,
        ip: str | None = None,
    ) -> ThreatEvent | None:
        """
        Detect privilege escalation attempts.

        Flags non-admin users attempting admin actions
        or role escalation to admin.

        Args:
            detector: Parent ThreatDetector instance.
            user: User performing the action.
            action: Action being attempted.
            target_role: Target role for escalation.
            ip: Source IP address.

        Returns:
            ThreatEvent if threat detected, else None.
        """
        return threat_detector_analysis.check_privilege_escalation(
            detector, user, action, target_role, ip
        )

    def check_data_exfiltration(
        self,
        detector: ThreatDetector,
        user: UserProtocol,
        endpoint: str,
        response_size: int,
        *,
        ip: str | None = None,
    ) -> ThreatEvent | None:
        """
        Detect data exfiltration patterns.

        Flags high request rates (>100/min) and large
        data transfers (>10MB).

        Args:
            detector: Parent ThreatDetector instance.
            user: User making the request.
            endpoint: Target endpoint.
            response_size: Response size in bytes.
            ip: Source IP address.

        Returns:
            ThreatEvent if threat detected, else None.
        """
        return threat_detector_analysis.check_data_exfiltration(
            detector, user, endpoint, response_size, ip
        )

    def check_new_location(
        self,
        detector: ThreatDetector,
        user: UserProtocol,
        ip: str,
        user_agent: str,
    ) -> ThreatEvent | None:
        """
        Detect login from unusual location.

        Tracks known IPs per user and alerts on new
        IPs after the first login.

        Args:
            detector: Parent ThreatDetector instance.
            user: User logging in.
            ip: Source IP address.
            user_agent: Client user agent string.

        Returns:
            ThreatEvent if new location detected.
        """
        return threat_detector_analysis.check_new_location(detector, user, ip, user_agent)


__all__ = [
    "BehavioralDetector",
]
