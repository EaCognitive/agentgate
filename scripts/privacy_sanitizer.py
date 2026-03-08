#!/usr/bin/env python3
"""Shared privacy sanitization helpers for formal verification artifacts."""

from __future__ import annotations

import re
from typing import Any

REDACTED_EMAIL = "<REDACTED_EMAIL>"
REDACTED_TOKEN = "<REDACTED_TOKEN>"
REDACTED_SECRET = "<REDACTED_SECRET>"
REDACTED_USER = "<REDACTED_USER>"

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)
BEARER_PATTERN = re.compile(
    r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]+\b",
    flags=re.IGNORECASE,
)
UNIX_USERS_PATH_PATTERN = re.compile(r"(/Users/)([^/\s]+)")
UNIX_HOME_PATH_PATTERN = re.compile(r"(/home/)([^/\s]+)")
WINDOWS_USERS_PATH_PATTERN = re.compile(r"([A-Za-z]:\\Users\\)([^\\\s]+)")

UNSAFE_BEARER_PATTERN = re.compile(
    r"\bBearer\s+(?!<REDACTED_TOKEN>)[A-Za-z0-9._~+/=-]+\b",
    flags=re.IGNORECASE,
)
UNSAFE_UNIX_USERS_PATH_PATTERN = re.compile(r"/Users/(?!<REDACTED_USER>)[^/\s]+")
UNSAFE_UNIX_HOME_PATH_PATTERN = re.compile(r"/home/(?!<REDACTED_USER>)[^/\s]+")
UNSAFE_WINDOWS_USERS_PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\Users\\(?!<REDACTED_USER>)[^\\\s]+",
)
UNSAFE_SECRET_FIELD_VALUE_PATTERN = re.compile(
    r'"(access_token|refresh_token|authorization|api_key|password|secret|secret_key|private_key)"'
    r'\s*:\s*"(?!<REDACTED_SECRET>|<REDACTED_TOKEN>)[^"]+"',
    flags=re.IGNORECASE,
)

SENSITIVE_FIELDS = frozenset(
    {
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "password",
        "secret",
        "secret_key",
        "private_key",
    }
)


def sanitize_text(raw: str) -> str:
    """Redact sensitive patterns from free-form text."""
    sanitized = EMAIL_PATTERN.sub(REDACTED_EMAIL, raw)
    sanitized = BEARER_PATTERN.sub(rf"\1{REDACTED_TOKEN}", sanitized)
    sanitized = UNIX_USERS_PATH_PATTERN.sub(rf"\1{REDACTED_USER}", sanitized)
    sanitized = UNIX_HOME_PATH_PATTERN.sub(rf"\1{REDACTED_USER}", sanitized)
    sanitized = WINDOWS_USERS_PATH_PATTERN.sub(rf"\1{REDACTED_USER}", sanitized)
    return sanitized


def sanitize_value(value: Any) -> Any:
    """Recursively redact sensitive values in structured payloads."""
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        sanitized_dict: dict[str, Any] = {}
        for key, inner in value.items():
            key_str = str(key)
            if key_str.lower() in SENSITIVE_FIELDS and inner is not None:
                sanitized_dict[key_str] = REDACTED_SECRET
            else:
                sanitized_dict[key_str] = sanitize_value(inner)
        return sanitized_dict
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_value(item) for item in value]
    return value


def detect_sensitive_text(raw: str) -> list[str]:
    """Return sensitive pattern labels found in text."""
    findings: list[str] = []
    if EMAIL_PATTERN.search(raw):
        findings.append("email")
    if UNSAFE_BEARER_PATTERN.search(raw):
        findings.append("bearer_token")
    if UNSAFE_UNIX_USERS_PATH_PATTERN.search(raw):
        findings.append("users_path")
    if UNSAFE_UNIX_HOME_PATH_PATTERN.search(raw):
        findings.append("home_path")
    if UNSAFE_WINDOWS_USERS_PATH_PATTERN.search(raw):
        findings.append("windows_users_path")
    if UNSAFE_SECRET_FIELD_VALUE_PATTERN.search(raw):
        findings.append("secret_field_value")
    return findings
