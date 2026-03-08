"""Azure identity and token lifecycle helpers for cloud runtime profiles."""

from .credential_factory import create_runtime_credential
from .postgres_token_provider import (
    AZURE_POSTGRES_SCOPE,
    AzureAccessToken,
    AzurePostgresTokenProvider,
    create_azure_postgres_token_provider,
)

__all__ = [
    "AZURE_POSTGRES_SCOPE",
    "AzureAccessToken",
    "AzurePostgresTokenProvider",
    "create_azure_postgres_token_provider",
    "create_runtime_credential",
]
