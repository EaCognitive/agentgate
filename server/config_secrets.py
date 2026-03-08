"""Secret configuration with explicit Key Vault allowlist retrieval."""

from __future__ import annotations

import logging
import re
import types
from typing import Any, get_args, get_origin

from pydantic import Field, SecretStr
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, SettingsConfigDict

from server.runtime.profile import RuntimeProfile
from server.security.azure.credential_factory import create_runtime_credential


class _AKVNotFoundPlaceholder(Exception):
    """Placeholder when Azure SDK packages are unavailable."""


try:
    from azure.core.exceptions import ResourceNotFoundError as AzureNotFound
    from azure.keyvault.secrets import SecretClient as AzureSecretClient

    _AKV_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when Azure SDK not installed
    AzureNotFound = _AKVNotFoundPlaceholder  # type: ignore[assignment,misc]
    AzureSecretClient = None  # type: ignore[assignment,misc]
    _AKV_AVAILABLE = False

logger = logging.getLogger(__name__)
_KEY_VAULT_SECRET_NAME_PATTERN = re.compile(r"^[0-9A-Za-z-]{1,127}$")

KEY_VAULT_SECRET_ALLOWLIST = frozenset(
    {
        "DEFAULT_ADMIN_PASSWORD",
        "SENTRY_DSN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    }
)


class SecretSettings(BaseSettings):
    """Secret settings loaded from env/dotenv and optional Key Vault overlay."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    default_admin_password: SecretStr | None = Field(default=None, alias="DEFAULT_ADMIN_PASSWORD")
    sentry_dsn: SecretStr | None = Field(default=None, alias="SENTRY_DSN")
    aws_access_key_id: str = Field(default="", alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: SecretStr = Field(default=SecretStr(""), alias="AWS_SECRET_ACCESS_KEY")


def _is_secret_str_field(field: FieldInfo) -> bool:
    """Check if a field expects SecretStr type."""
    # Check if the annotation is SecretStr or Optional[SecretStr]
    annotation = field.annotation
    if annotation is SecretStr:
        return True

    # Handle Optional[SecretStr] or SecretStr | None
    origin = get_origin(annotation)
    if origin in (types.UnionType, type(None)):
        args = get_args(annotation)
        return SecretStr in args

    return False


def _secret_name_candidates(alias: str) -> tuple[str, ...]:
    """Return deterministic candidate names for Key Vault secret lookup."""
    raw_candidates = (
        alias.strip(),
        alias.lower().replace("_", "-").strip(),
        alias.lower().strip(),
    )
    valid_candidates: list[str] = []
    for candidate in raw_candidates:
        if not candidate:
            continue
        if candidate in valid_candidates:
            continue
        if not _KEY_VAULT_SECRET_NAME_PATTERN.fullmatch(candidate):
            continue
        valid_candidates.append(candidate)
    return tuple(valid_candidates)


def _fetch_secret_from_client(client: Any, alias: str) -> str | None:
    """Fetch first available alias variant from Azure Key Vault."""
    for candidate in _secret_name_candidates(alias):
        try:
            secret_bundle = client.get_secret(candidate)
            value = getattr(secret_bundle, "value", None)
            if isinstance(value, str):
                return value
        except AzureNotFound:
            continue
    return None


def _load_allowed_key_vault_secrets(
    *,
    runtime_profile: RuntimeProfile,
    vault_url: str,
) -> dict[str, Any]:
    """Load allowlisted secrets from Azure Key Vault only."""
    if not _AKV_AVAILABLE or AzureSecretClient is None:
        if runtime_profile == RuntimeProfile.CLOUD_STRICT:
            raise RuntimeError(
                "cloud_strict profile requires Azure Key Vault SDK packages for secrets retrieval."
            )
        logger.warning(
            "Azure Key Vault SDK unavailable; using env/dotenv secret sources in profile=%s",
            runtime_profile.value,
        )
        return {}

    credential = create_runtime_credential(profile=runtime_profile)
    client = AzureSecretClient(vault_url=vault_url, credential=credential)

    resolved: dict[str, Any] = {}
    for field_name, field in SecretSettings.model_fields.items():
        alias = str(field.alias or field_name)
        if alias not in KEY_VAULT_SECRET_ALLOWLIST:
            continue
        secret_value = _fetch_secret_from_client(client, alias)
        if secret_value is not None:
            # Wrap in SecretStr if the field expects it
            if _is_secret_str_field(field):
                resolved[field_name] = SecretStr(secret_value)
            else:
                resolved[field_name] = secret_value
    return resolved


def load_secret_settings(
    *,
    runtime_profile: RuntimeProfile,
    vault_url: str | None,
) -> tuple[SecretSettings, str]:
    """Load secret settings and annotate source metadata for runtime logging."""
    base_settings = SecretSettings()
    normalized_vault_url = (vault_url or "").strip()
    if runtime_profile == RuntimeProfile.CLOUD_STRICT and not normalized_vault_url:
        raise RuntimeError(
            "cloud_strict profile requires AZURE_KEY_VAULT_URL for secrets retrieval."
        )

    if not normalized_vault_url:
        return base_settings, "env"

    overlay = _load_allowed_key_vault_secrets(
        runtime_profile=runtime_profile,
        vault_url=normalized_vault_url,
    )
    if not overlay:
        return base_settings, "env"

    # Use model_copy to merge, which preserves SecretStr types
    return base_settings.model_copy(update=overlay), "azure_key_vault"


def get_secret_settings(
    runtime_profile: RuntimeProfile,
    vault_url: str | None,
) -> tuple[SecretSettings, str]:
    """Secret settings accessor keyed by runtime profile and vault URL."""
    return load_secret_settings(runtime_profile=runtime_profile, vault_url=vault_url)


def _clear_secret_settings_cache() -> None:
    """Compatibility hook for tests that clear settings caches."""
    return None


get_secret_settings.cache_clear = _clear_secret_settings_cache  # type: ignore[attr-defined]
