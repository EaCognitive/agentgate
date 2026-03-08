"""Keyring-first runtime secret loading utilities.

Resolution order:
1. OS keyring (`keyring` package)
2. Environment variable
3. Docker-style file secret (`<NAME>_FILE`)
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache


class _KeyringErrorPlaceholder(Exception):
    """Fallback error type used when keyring is unavailable."""


try:
    import keyring
    from keyring.errors import KeyringError

    _HAS_KEYRING = True
except ImportError:
    keyring = None  # type: ignore[assignment]
    KeyringError = _KeyringErrorPlaceholder  # type: ignore[assignment,misc]
    _HAS_KEYRING = False


logger = logging.getLogger(__name__)
DEFAULT_KEYRING_SERVICE = "agentgate"


def _get_keyring_service_name(service_name: str | None = None) -> str:
    """Return keyring service namespace."""
    resolved = service_name or os.getenv("AGENTGATE_KEYRING_SERVICE")
    if resolved:
        return resolved
    return DEFAULT_KEYRING_SERVICE


@lru_cache(maxsize=256)
def get_keyring_secret(
    name: str,
    service_name: str | None = None,
    username: str | None = None,
) -> str | None:
    """Load a secret from OS keyring.

    The default username key is the secret name itself.
    """
    if not _HAS_KEYRING or keyring is None:
        return None

    effective_service = _get_keyring_service_name(service_name)
    effective_username = username or name

    try:
        return keyring.get_password(effective_service, effective_username)
    except (KeyringError, OSError, RuntimeError) as exc:
        logger.warning(
            "Keyring lookup failed for service=%s key=%s: %s",
            effective_service,
            effective_username,
            exc,
        )
        return None


def _read_secret_file(path: str) -> str | None:
    """Read a secret value from a file path."""
    try:
        with open(path, "r", encoding="utf-8") as secret_file:
            value = secret_file.read().strip()
            return value or None
    except OSError:
        return None


def get_env_secret(name: str, default: str | None = None) -> str | None:
    """Load secret from environment or `<NAME>_FILE` path."""
    direct_value = os.getenv(name)
    if direct_value:
        return direct_value

    file_env_name = f"{name}_FILE"
    file_path = os.getenv(file_env_name)
    if file_path:
        file_value = _read_secret_file(file_path)
        if file_value:
            return file_value

    return default


def get_runtime_secret(
    name: str,
    default: str | None = None,
    service_name: str | None = None,
    username: str | None = None,
) -> str | None:
    """Resolve secret using keyring first, then environment."""
    keyring_value = get_keyring_secret(
        name=name,
        service_name=service_name,
        username=username,
    )
    if keyring_value:
        return keyring_value

    return get_env_secret(name, default=default)


def clear_secret_cache() -> None:
    """Clear memoized keyring lookups."""
    get_keyring_secret.cache_clear()
