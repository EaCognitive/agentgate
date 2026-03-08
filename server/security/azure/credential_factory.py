"""Azure credential factory with runtime-profile-aware selection."""

from __future__ import annotations

from typing import Any, TypeAlias

from server.runtime.profile import RuntimeProfile, resolve_runtime_profile

try:
    from azure.identity import (
        AzureCliCredential,
        ChainedTokenCredential,
        DefaultAzureCredential,
        ManagedIdentityCredential,
        WorkloadIdentityCredential,
    )

    _AZURE_IDENTITY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by runtime import fallback
    AzureCliCredential = None  # type: ignore[assignment,misc]
    ChainedTokenCredential = None  # type: ignore[assignment,misc]
    DefaultAzureCredential = None  # type: ignore[assignment,misc]
    ManagedIdentityCredential = None  # type: ignore[assignment,misc]
    WorkloadIdentityCredential = None  # type: ignore[assignment,misc]
    _AZURE_IDENTITY_AVAILABLE = False


SupportsGetToken: TypeAlias = Any


def _require_azure_identity() -> None:
    """Fail closed when cloud credential flow is requested without Azure SDK."""
    if _AZURE_IDENTITY_AVAILABLE:
        return
    raise RuntimeError(
        "azure-identity is required for dev_cloud and cloud_strict credential flows."
    )


def _build_dev_cloud_credential() -> SupportsGetToken:
    """Prefer Azure CLI identity locally, then managed and workload identity."""
    assert ChainedTokenCredential is not None
    assert AzureCliCredential is not None
    assert ManagedIdentityCredential is not None
    candidates: list[SupportsGetToken] = [
        AzureCliCredential(),
        ManagedIdentityCredential(),
    ]

    if WorkloadIdentityCredential is not None:
        try:
            candidates.append(WorkloadIdentityCredential())
        except (TypeError, ValueError):
            # WorkloadIdentityCredential requires env wiring in some runtimes.
            # Keep chain functional with CLI + MI when unavailable.
            pass

    return ChainedTokenCredential(*candidates)


def _build_default_credential(cli_enabled: bool) -> SupportsGetToken:
    """Build a constrained DefaultAzureCredential chain."""
    assert DefaultAzureCredential is not None
    return DefaultAzureCredential(
        exclude_shared_token_cache_credential=True,
        exclude_visual_studio_code_credential=True,
        exclude_powershell_credential=True,
        exclude_developer_cli_credential=True,
        exclude_interactive_browser_credential=True,
        exclude_cli_credential=not cli_enabled,
    )


def create_runtime_credential(
    profile: RuntimeProfile | str | None = None,
    environment: str | None = None,
) -> SupportsGetToken:
    """Create a runtime-profile-aware Azure token credential chain."""
    resolved = resolve_runtime_profile(profile_value=profile, environment=environment)
    _require_azure_identity()

    if resolved == RuntimeProfile.DEV_CLOUD:
        return _build_dev_cloud_credential()
    if resolved == RuntimeProfile.CLOUD_STRICT:
        return _build_default_credential(cli_enabled=False)
    return _build_default_credential(cli_enabled=True)
