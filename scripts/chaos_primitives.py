"""Shared configuration primitives for chaos verification scripts."""

from __future__ import annotations

import os
from dataclasses import dataclass


_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_VALID_COMPLIANCE_PROFILES = frozenset({"development", "soc2", "soc3", "hipaa", "regulated"})
_VALID_IDENTITY_PROFILES = frozenset({"local", "hybrid_migration", "descope", "custom_oidc"})
_REGULATED_COMPLIANCE_PROFILES = frozenset({"soc2", "soc3", "hipaa", "regulated"})


@dataclass(frozen=True, slots=True)
class ChaosCampaignConfiguration:
    """Validated campaign settings for a chaos verification run."""

    iterations: int
    workers: int
    seed: int
    compliance_profile: str
    identity_profile: str


def _normalize_profile(raw_value: str, *, valid_values: frozenset[str], label: str) -> str:
    """Normalize and validate a profile value."""
    normalized = raw_value.strip().lower()
    if normalized not in valid_values:
        valid_text = ", ".join(sorted(valid_values))
        raise ValueError(f"{label} must be one of: {valid_text}")
    return normalized


def _allow_identity_profile_mismatch() -> bool:
    """Return whether incompatible identity/compliance pairings are allowed."""
    raw_value = os.getenv("CHAOS_ALLOW_IDENTITY_PROFILE_MISMATCH", "")
    return raw_value.strip().lower() in _TRUE_VALUES


def resolve_chaos_campaign_configuration(
    *,
    iterations: int | None,
    workers: int | None,
    seed: int,
    compliance_profile: str,
    identity_profile: str,
) -> ChaosCampaignConfiguration:
    """Resolve and validate chaos campaign configuration."""
    resolved_iterations = iterations if iterations is not None else 10_000
    resolved_workers = workers if workers is not None else min(8, os.cpu_count() or 4)

    if resolved_iterations <= 0:
        raise ValueError("iterations must be > 0")
    if resolved_workers <= 0:
        raise ValueError("workers must be > 0")

    normalized_compliance = _normalize_profile(
        compliance_profile,
        valid_values=_VALID_COMPLIANCE_PROFILES,
        label="compliance_profile",
    )
    normalized_identity = _normalize_profile(
        identity_profile,
        valid_values=_VALID_IDENTITY_PROFILES,
        label="identity_profile",
    )

    if (
        normalized_compliance in _REGULATED_COMPLIANCE_PROFILES
        and normalized_identity == "local"
        and not _allow_identity_profile_mismatch()
    ):
        raise ValueError(
            "identity_profile=local is incompatible with regulated compliance profiles "
            "unless CHAOS_ALLOW_IDENTITY_PROFILE_MISMATCH=true"
        )

    return ChaosCampaignConfiguration(
        iterations=resolved_iterations,
        workers=min(resolved_workers, resolved_iterations),
        seed=seed,
        compliance_profile=normalized_compliance,
        identity_profile=normalized_identity,
    )


__all__ = ["ChaosCampaignConfiguration", "resolve_chaos_campaign_configuration"]
