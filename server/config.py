"""Application configuration facade for runtime and secret settings."""

from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from server.config_runtime import get_runtime_settings
from server.config_secrets import get_secret_settings
from server.runtime.profile import RuntimeProfile

logger = logging.getLogger(__name__)


class AppSettings(BaseModel):
    """Unified settings view used by application runtime code paths."""

    model_config = ConfigDict(extra="allow")

    environment: str = Field(default="development")
    runtime_profile: RuntimeProfile = Field(default=RuntimeProfile.LOCAL_COMPAT)
    database_auth_mode: str = Field(default="auto")
    log_level: str = Field(default="INFO")
    redis_url: str = Field(default="memory://")
    audit_pipeline: str = Field(default="sync")
    default_admin_email: str | None = Field(default=None)
    default_admin_password: SecretStr | None = Field(default=None)
    allowed_origins: str | None = Field(default=None)
    sentry_dsn: SecretStr | None = Field(default=None)
    azure_key_vault_url: str | None = Field(default=None)
    cloud_provider: str = Field(default="")
    cloud_bucket: str = Field(default="")
    cloud_auto_create_bucket: bool = Field(default=False)
    aws_access_key_id: str = Field(default="")
    aws_secret_access_key: SecretStr = Field(default=SecretStr(""))
    aws_region: str = Field(default="us-east-1")


def _build_settings() -> AppSettings:
    """Build consolidated app settings from runtime and secret sources."""
    runtime_settings = get_runtime_settings()
    runtime_profile = runtime_settings.runtime_profile or RuntimeProfile.LOCAL_COMPAT
    secret_settings, secret_source = get_secret_settings(
        runtime_profile=runtime_profile,
        vault_url=runtime_settings.azure_key_vault_url,
    )

    settings = AppSettings(
        **runtime_settings.model_dump(),
        **secret_settings.model_dump(),
    )
    profile_value = settings.runtime_profile
    resolved_profile = str(profile_value)
    logger.info(
        "Loaded configuration profile=%s runtime_source=env secrets_source=%s",
        resolved_profile,
        secret_source,
    )
    return settings


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Settings accessor."""
    return _build_settings()


_get_settings_cache_clear = get_settings.cache_clear


def _clear_settings_cache() -> None:
    """Compatibility cache-clear hook for test fixtures."""
    _get_settings_cache_clear()
    get_runtime_settings.cache_clear()
    get_secret_settings.cache_clear()


get_settings.cache_clear = _clear_settings_cache  # type: ignore[attr-defined]
