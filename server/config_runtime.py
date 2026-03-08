"""Runtime configuration sourced from environment variables and ConfigMaps."""

from __future__ import annotations

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from server.runtime.profile import RuntimeProfile, resolve_runtime_profile


class RuntimeSettings(BaseSettings):
    """Non-secret runtime configuration loaded from env and dotenv."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = Field(default="development", alias="AGENTGATE_ENV")
    runtime_profile: RuntimeProfile | None = Field(
        default=None,
        validation_alias=AliasChoices("AGENTGATE_RUNTIME_PROFILE", "AGENTGATE_PROFILE"),
    )
    database_auth_mode: str = Field(
        default="auto",
        validation_alias=AliasChoices("DATABASE_AUTH_MODE", "AGENTGATE_DB_AUTH_MODE"),
    )
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    redis_url: str = Field(default="memory://", alias="REDIS_URL")
    audit_pipeline: str = Field(default="sync", alias="AUDIT_PIPELINE")
    default_admin_email: str | None = Field(default=None, alias="DEFAULT_ADMIN_EMAIL")
    allowed_origins: str | None = Field(default=None, alias="ALLOWED_ORIGINS")
    azure_key_vault_url: str | None = Field(default=None, alias="AZURE_KEY_VAULT_URL")
    cloud_provider: str = Field(default="", alias="CLOUD_PROVIDER")
    cloud_bucket: str = Field(default="", alias="CLOUD_BUCKET")
    cloud_auto_create_bucket: bool = Field(default=False, alias="CLOUD_AUTO_CREATE_BUCKET")
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")

    @model_validator(mode="after")
    def apply_runtime_profile_defaults(self) -> "RuntimeSettings":
        """Resolve runtime profile from explicit env or environment-aware defaults."""
        self.runtime_profile = resolve_runtime_profile(
            profile_value=self.runtime_profile,
            environment=self.environment,
        )
        return self


def get_runtime_settings() -> RuntimeSettings:
    """Runtime settings accessor."""
    return RuntimeSettings()


def _clear_runtime_settings_cache() -> None:
    """Compatibility hook for tests that clear settings caches."""
    return None


get_runtime_settings.cache_clear = _clear_runtime_settings_cache  # type: ignore[attr-defined]
