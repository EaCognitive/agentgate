"""Runtime profile resolution and enforcement guards."""

from __future__ import annotations

import os
from enum import Enum


class RuntimeProfile(str, Enum):
    """Supported runtime profiles for cloud parity and strict enforcement."""

    LOCAL_COMPAT = "local_compat"
    DEV_CLOUD = "dev_cloud"
    CLOUD_STRICT = "cloud_strict"


STRICT_CLOUD_ENVIRONMENTS = frozenset({"production", "staging", "marketplace"})
CLOUD_PROFILES = frozenset({RuntimeProfile.DEV_CLOUD, RuntimeProfile.CLOUD_STRICT})


def parse_runtime_profile(value: str | RuntimeProfile | None) -> RuntimeProfile | None:
    """Parse a runtime profile value into a known enum."""
    if value is None:
        return None
    if isinstance(value, RuntimeProfile):
        return value

    normalized = str(value).strip().lower()
    if not normalized:
        return None
    try:
        return RuntimeProfile(normalized)
    except ValueError as exc:
        valid = ", ".join(profile.value for profile in RuntimeProfile)
        raise RuntimeError(
            f"Unsupported runtime profile '{value}'. Expected one of: {valid}."
        ) from exc


def require_profile_compatibility(profile: RuntimeProfile, environment: str) -> None:
    """Fail closed when strict environments attempt non-strict profiles."""
    normalized_env = str(environment).strip().lower()
    if normalized_env in STRICT_CLOUD_ENVIRONMENTS and profile != RuntimeProfile.CLOUD_STRICT:
        raise RuntimeError(
            "Strict runtime environments require AGENTGATE_RUNTIME_PROFILE=cloud_strict."
        )


def resolve_runtime_profile(
    profile_value: str | RuntimeProfile | None = None,
    environment: str | None = None,
) -> RuntimeProfile:
    """Resolve runtime profile from explicit input or process environment."""
    normalized_env = (
        str(environment if environment is not None else os.getenv("AGENTGATE_ENV", "development"))
        .strip()
        .lower()
    )

    requested = (
        profile_value
        if profile_value is not None
        else os.getenv("AGENTGATE_RUNTIME_PROFILE") or os.getenv("AGENTGATE_PROFILE")
    )
    resolved = parse_runtime_profile(requested)
    if resolved is None:
        if normalized_env in STRICT_CLOUD_ENVIRONMENTS:
            resolved = RuntimeProfile.CLOUD_STRICT
        else:
            resolved = RuntimeProfile.LOCAL_COMPAT

    require_profile_compatibility(resolved, normalized_env)
    return resolved


def is_cloud_profile(profile: RuntimeProfile) -> bool:
    """Return whether the profile is cloud-authenticated."""
    return profile in CLOUD_PROFILES
