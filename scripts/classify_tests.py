"""Classify test files as KEEP (endpoint tests) or ARCHIVE (internal unit tests).

A file is classified as KEEP if it contains any of the following HTTP-client markers:
  - TestClient
  - AsyncClient
  - httpx.

Otherwise it is classified as ARCHIVE.

Usage:
    python scripts/classify_tests.py            # prints classification report
    python scripts/classify_tests.py --dry-run  # same, explicit flag
"""

import argparse
import re
import sys
from pathlib import Path

# Signals that a test file makes actual HTTP calls against the router layer.
HTTP_CLIENT_PATTERNS = [
    re.compile(r"\bTestClient\b"),
    re.compile(r"\bAsyncClient\b"),
    re.compile(r"\bhttpx\."),
]

# Subdirectories relative to tests/ that are always kept entirely.
ALWAYS_KEEP_DIRS = {
    "auth_tests",
    "auth_mfa_tests",
    "dataset_tests",
    "trace_tests",
    "main_tests",
    "integration_tests",
    "e2e",
    "schemas_utils_tests",
    "mcp_policy",
}

# Individual files relative to tests/ that are always kept regardless of content.
ALWAYS_KEEP_FILES = {
    "conftest.py",
    "server_test_auth.py",
    "server_test_captcha.py",
    "server_test_traces.py",
    "server_test_rate_limiting.py",
    "server_test_rate_limiting_advanced.py",
    "test_audit_router.py",
    "test_audit_router_export.py",
    "test_auth_registration_router.py",
    "test_device_auth_router.py",
    "test_mcp_mfa_callback_router.py",
    "test_policy_governance_verification_router.py",
    "test_access_mode_router.py",
    "test_approvals_coverage.py",
    "test_formal_api_contract.py",
    "test_webauthn_endpoints.py",
    "test_webauthn_database_coverage.py",
    "test_routing.py",
    "test_datasets.py",
    "test_async.py",
    "test_agent.py",
    "test_verification.py",
    "test_middleware.py",
    "test_guardrail.py",
    "test_captcha_utils.py",
    "test_mfa_utils.py",
    "test_policy_middleware.py",
}

# Security sub-files to keep (use TestClient / endpoint-level assertions).
ALWAYS_KEEP_SECURITY_FILES = {
    "test_authorization.py",
    "test_authorization_escalation.py",
    "test_authorization_extended.py",
    "test_authorization_isolation.py",
    "test_dataset_access_control.py",
    "test_sql_injection.py",
    "test_sql_injection_extended.py",
    "test_xss_csrf.py",
    "test_xss_csrf_extended.py",
    "test_threat_detection.py",
    "test_threat_detection_advanced.py",
    "test_threat_detection_location_blocking.py",
    "test_verification_controls.py",
    "conftest.py",
}


def uses_http_client(path: Path) -> bool:
    """Return True if the file contains any HTTP-client import or usage."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(pattern.search(source) for pattern in HTTP_CLIENT_PATTERNS)


def is_always_kept(rel: Path) -> bool:
    """Return True if the file is in an always-keep list."""
    parts = rel.parts

    # Keep everything in always-keep dirs (first path component).
    if parts[0] in ALWAYS_KEEP_DIRS:
        return True

    # Top-level files.
    if len(parts) == 1 and parts[0] in ALWAYS_KEEP_FILES:
        return True

    # Security directory: only specific files stay.
    if parts[0] == "security" and len(parts) == 2:
        return parts[1] in ALWAYS_KEEP_SECURITY_FILES

    return False


def classify(tests_root: Path) -> tuple[list[Path], list[Path]]:
    """Return (keep, archive) lists of relative paths under tests_root."""
    keep: list[Path] = []
    archive: list[Path] = []

    for abs_path in sorted(tests_root.rglob("*.py")):
        rel = abs_path.relative_to(tests_root)
        parts = rel.parts

        # Skip __pycache__, __init__, non-test files.
        if any(part.startswith("__") for part in parts):
            continue

        # Skip artifacts directory.
        if parts[0] == "artifacts":
            continue

        if is_always_kept(rel):
            keep.append(rel)
            continue

        if uses_http_client(abs_path):
            keep.append(rel)
        else:
            archive.append(rel)

    return keep, archive


def main() -> int:
    """Entry point for the classification script."""
    parser = argparse.ArgumentParser(description="Classify test files as KEEP or ARCHIVE.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Print the classification without moving files (default: True)",
    )
    parser.add_argument(
        "--tests-dir",
        default="tests",
        help="Path to the tests directory (default: tests)",
    )
    args = parser.parse_args()

    tests_root = Path(args.tests_dir).resolve()
    if not tests_root.is_dir():
        print(f"ERROR: tests directory not found: {tests_root}", file=sys.stderr)
        return 1

    keep, archive = classify(tests_root)

    print("=" * 70)
    print(f"KEEP  ({len(keep)} files) — endpoint / integration tests")
    print("=" * 70)
    for rel in keep:
        print(f"  KEEP    {rel}")

    print()
    print("=" * 70)
    print(f"ARCHIVE ({len(archive)} files) — internal unit tests")
    print("=" * 70)
    for rel in archive:
        print(f"  ARCHIVE {rel}")

    print()
    print(f"Total: {len(keep)} KEEP, {len(archive)} ARCHIVE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
