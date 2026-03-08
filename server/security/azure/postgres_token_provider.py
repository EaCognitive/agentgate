"""Azure PostgreSQL Entra token provider helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from server.runtime.profile import RuntimeProfile
from .credential_factory import SupportsGetToken, create_runtime_credential

AZURE_POSTGRES_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"


@dataclass(frozen=True)
class AzureAccessToken:
    """Azure access token metadata used for DB pool lifecycle enforcement."""

    token: str
    expires_on: int

    @property
    def expires_at_utc(self) -> datetime:
        """Get token expiration as timezone-aware UTC datetime."""
        return datetime.fromtimestamp(self.expires_on, tz=timezone.utc)


class AzurePostgresTokenProvider:
    """Issue Entra access tokens for PostgreSQL server authentication."""

    def __init__(
        self,
        credential: SupportsGetToken,
        scope: str = AZURE_POSTGRES_SCOPE,
    ) -> None:
        self._credential = credential
        self._scope = scope

    @property
    def scope(self) -> str:
        """Return the Azure scope requested from the credential."""
        return self._scope

    def get_access_token(self) -> AzureAccessToken:
        """Get a fresh access token from Azure Identity credentials."""
        raw_token: Any = self._credential.get_token(self._scope)
        token_value = getattr(raw_token, "token", None)
        expires_on = getattr(raw_token, "expires_on", None)
        if not isinstance(token_value, str) or not token_value:
            raise RuntimeError("Azure credential returned an empty token for PostgreSQL scope.")
        if not isinstance(expires_on, int):
            raise RuntimeError("Azure credential returned token without integer expires_on.")
        return AzureAccessToken(token=token_value, expires_on=expires_on)


def create_azure_postgres_token_provider(
    profile: RuntimeProfile | str | None = None,
    environment: str | None = None,
) -> AzurePostgresTokenProvider:
    """Build token provider with runtime-profile credential selection."""
    credential = create_runtime_credential(profile=profile, environment=environment)
    return AzurePostgresTokenProvider(credential=credential)
