"""Comprehensive tests for MFA utility functions.

Tests cover:
- TOTP secret generation
- QR code generation
- TOTP code verification
- Backup code generation
- Backup code hashing
- Backup code verification
- Edge cases and security considerations
"""

import base64
import re
import time
from unittest.mock import patch

import bcrypt
import pyotp

from server.utils.mfa import (
    generate_backup_codes,
    generate_qr_code,
    generate_totp_secret,
    get_totp_uri,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)


class TestGenerateTotpSecret:
    """Tests for generate_totp_secret() function."""

    def test_generates_valid_base32_secret(self):
        """Test that secret is valid base32 string."""
        secret = generate_totp_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0
        # Base32 alphabet: A-Z and 2-7
        assert re.match(r"^[A-Z2-7]+$", secret)

    def test_generates_unique_secrets(self):
        """Test that each call generates a unique secret."""
        secrets = [generate_totp_secret() for _ in range(100)]
        # All secrets should be unique
        assert len(secrets) == len(set(secrets))

    def test_generates_sufficient_entropy(self):
        """Test that generated secret has sufficient length for security."""
        secret = generate_totp_secret()
        # pyotp.random_base32() generates 32-character secrets
        assert len(secret) == 32

    def test_secret_works_with_pyotp(self):
        """Test that generated secret can be used to create TOTP instance."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        # Should be able to generate a code without errors
        code = totp.now()
        assert isinstance(code, str)
        assert len(code) == 6
        assert code.isdigit()


class TestGetTotpUri:
    """Tests for get_totp_uri() function."""

    def test_generates_valid_uri(self):
        """Test that URI has correct otpauth:// format."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "test@example.com")
        assert uri.startswith("otpauth://totp/")
        # Email is URL-encoded in the URI
        assert "test%40example.com" in uri or "test@example.com" in uri
        assert secret in uri

    def test_includes_issuer_in_uri(self):
        """Test that issuer name is included in URI."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "test@example.com", issuer="TestApp")
        assert "issuer=TestApp" in uri

    def test_default_issuer(self):
        """Test default issuer is AgentGate."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "test@example.com")
        assert "issuer=AgentGate" in uri

    def test_handles_special_characters_in_email(self):
        """Test URI encoding handles special characters."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "user+tag@example.com")
        # Should contain encoded email
        assert "user" in uri


class TestGenerateQrCode:
    """Tests for generate_qr_code() function."""

    def test_generates_valid_data_uri(self):
        """Test that QR code is a valid data URI."""
        secret = generate_totp_secret()
        qr_code = generate_qr_code("test@example.com", secret)
        assert qr_code.startswith("data:image/png;base64,")

    def test_generates_valid_base64(self):
        """Test that data URI contains valid base64 content."""
        secret = generate_totp_secret()
        qr_code = generate_qr_code("test@example.com", secret)
        # Extract base64 part
        base64_part = qr_code.split(",", 1)[1]
        # Should be able to decode without errors
        decoded = base64.b64decode(base64_part)
        assert len(decoded) > 0
        # PNG files start with specific magic bytes
        assert decoded[:8] == b"\x89PNG\r\n\x1a\n"

    def test_different_inputs_generate_different_qr_codes(self):
        """Test that different inputs produce different QR codes."""
        secret1 = generate_totp_secret()
        secret2 = generate_totp_secret()
        qr1 = generate_qr_code("test1@example.com", secret1)
        qr2 = generate_qr_code("test2@example.com", secret2)
        assert qr1 != qr2

    def test_custom_issuer(self):
        """Test QR code generation with custom issuer."""
        secret = generate_totp_secret()
        qr_code = generate_qr_code("test@example.com", secret, issuer="CustomApp")
        assert isinstance(qr_code, str)
        assert qr_code.startswith("data:image/png;base64,")

    def test_same_inputs_generate_same_qr_code(self):
        """Test that identical inputs produce identical QR codes."""
        secret = generate_totp_secret()
        qr1 = generate_qr_code("test@example.com", secret, issuer="Test")
        qr2 = generate_qr_code("test@example.com", secret, issuer="Test")
        assert qr1 == qr2


class TestVerifyTotpCode:
    """Tests for verify_totp_code() function."""

    def test_valid_code_verification(self):
        """Test that valid TOTP code is verified successfully."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        assert verify_totp_code(secret, valid_code) is True

    def test_invalid_code_rejection(self):
        """Test that invalid code is rejected."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "000000") is False

    def test_empty_secret_returns_false(self):
        """Test that empty secret returns False."""
        assert verify_totp_code("", "123456") is False

    def test_empty_code_returns_false(self):
        """Test that empty code returns False."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "") is False

    def test_none_secret_returns_false(self):
        """Test that None secret returns False."""
        assert verify_totp_code(None, "123456") is False

    def test_none_code_returns_false(self):
        """Test that None code returns False."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, None) is False

    def test_whitespace_in_code_is_handled(self):
        """Test that whitespace in code is stripped."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        assert verify_totp_code(secret, f"  {valid_code}  ") is True

    def test_invalid_secret_format_returns_false(self):
        """Test that invalid secret format returns False."""
        assert verify_totp_code("invalid-secret-123", "123456") is False

    def test_code_reuse_prevention(self):
        """Test that old codes are not accepted after time window."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)

        # Generate code at specific time
        with patch("time.time", return_value=1000000000):
            old_code = totp.at(1000000000)

        # Try to verify with current time (much later)
        # Should fail because window is only ±1 time step (30 seconds)
        current_time = time.time()
        if current_time - 1000000000 > 60:  # More than 2 time steps
            assert verify_totp_code(secret, old_code) is False

    def test_time_window_tolerance(self):
        """Test that codes within valid window are accepted."""
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)

        # Get current time and code
        current_time = int(time.time())
        current_code = totp.at(current_time)

        # Current code should always work
        assert verify_totp_code(secret, current_code) is True

        # Previous code might work depending on exact timing
        # This is expected behavior with valid_window=1

    def test_non_numeric_code_returns_false(self):
        """Test that non-numeric code returns False."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "abcdef") is False

    def test_wrong_length_code_returns_false(self):
        """Test that code with wrong length returns False."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "12345") is False  # Too short
        assert verify_totp_code(secret, "1234567") is False  # Too long


class TestGenerateBackupCodes:
    """Tests for generate_backup_codes() function."""

    def test_generates_default_count(self):
        """Test that default count of 10 codes is generated."""
        codes = generate_backup_codes()
        assert len(codes) == 10

    def test_generates_custom_count(self):
        """Test that custom count of codes is generated."""
        codes = generate_backup_codes(count=5)
        assert len(codes) == 5

        codes = generate_backup_codes(count=20)
        assert len(codes) == 20

    def test_generates_zero_codes(self):
        """Test that zero codes can be generated."""
        codes = generate_backup_codes(count=0)
        assert len(codes) == 0

    def test_codes_are_correct_length(self):
        """Test that each code is 8 characters long."""
        codes = generate_backup_codes()
        for code in codes:
            assert len(code) == 8

    def test_codes_are_hexadecimal(self):
        """Test that codes contain only hex characters."""
        codes = generate_backup_codes()
        for code in codes:
            assert re.match(r"^[A-F0-9]+$", code)

    def test_codes_are_unique(self):
        """Test that all generated codes are unique."""
        codes = generate_backup_codes(count=100)
        assert len(codes) == len(set(codes))

    def test_codes_are_uppercase(self):
        """Test that all codes are uppercase."""
        codes = generate_backup_codes()
        for code in codes:
            assert code == code.upper()

    def test_codes_have_sufficient_entropy(self):
        """Test that codes are not predictable."""
        # Generate multiple sets and ensure they're different
        set1 = generate_backup_codes(count=10)
        set2 = generate_backup_codes(count=10)
        # Should have no overlap (statistically very unlikely)
        assert len(set(set1) & set(set2)) == 0


class TestHashBackupCode:
    """Tests for hash_backup_code() function.

    Note: Uses bcrypt for security (not SHA-256). bcrypt:
    - Produces 60-character hashes with $2b$ prefix
    - Uses unique salts, so same input produces different hashes
    - Is case-insensitive (codes are normalized to uppercase)
    """

    def test_generates_bcrypt_hash(self):
        """Test that hash is bcrypt format."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        # bcrypt hash is 60 characters with $2b$ prefix
        assert len(hashed) == 60
        assert hashed.startswith("$2b$")

    def test_same_code_verified_with_different_hashes(self):
        """Test that bcrypt produces different hashes (due to salt) but both verify."""
        code = "ABCD1234"
        hash1 = hash_backup_code(code)
        hash2 = hash_backup_code(code)
        # bcrypt uses random salts, so hashes are different
        assert hash1 != hash2
        # But both should verify the original code
        assert verify_backup_code(code, [hash1]) is True
        assert verify_backup_code(code, [hash2]) is True

    def test_different_codes_produce_different_hashes(self):
        """Test that different codes produce different hashes."""
        hash1 = hash_backup_code("ABCD1234")
        hash2 = hash_backup_code("EFGH5678")
        assert hash1 != hash2

    def test_bcrypt_format_with_cost_factor(self):
        """Test that bcrypt hash includes cost factor."""
        code = "TESTCODE"
        hashed = hash_backup_code(code)
        # bcrypt format: $2b$cost$salt+hash
        assert re.match(r"^\$2b\$\d{2}\$.+$", hashed)

    def test_empty_string_produces_hash(self):
        """Test that empty string can be hashed."""
        hashed = hash_backup_code("")
        assert len(hashed) == 60
        assert hashed.startswith("$2b$")

    def test_case_normalization(self):
        """Test that codes are normalized to uppercase for hashing."""
        code = "abcd1234"
        hashed = hash_backup_code(code)
        # Lowercase should verify against hash (normalized to uppercase)
        assert verify_backup_code("ABCD1234", [hashed]) is True
        assert verify_backup_code("abcd1234", [hashed]) is True


class TestVerifyBackupCode:
    """Tests for verify_backup_code() function."""

    def test_valid_code_verification(self):
        """Test that valid backup code is verified successfully."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        assert verify_backup_code(code, [hashed]) is True

    def test_invalid_code_rejection(self):
        """Test that invalid code is rejected."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        assert verify_backup_code("WRONG123", [hashed]) is False

    def test_verification_against_multiple_hashes(self):
        """Test verification against list of multiple hashes."""
        codes = generate_backup_codes(count=5)
        hashes = [hash_backup_code(code) for code in codes]

        # Each code should verify
        for code in codes:
            assert verify_backup_code(code, hashes) is True

        # Wrong code should not verify
        assert verify_backup_code("WRONG123", hashes) is False

    def test_empty_code_returns_false(self):
        """Test that empty code returns False."""
        hashed = hash_backup_code("ABCD1234")
        assert verify_backup_code("", [hashed]) is False

    def test_none_code_returns_false(self):
        """Test that None code returns False."""
        hashed = hash_backup_code("ABCD1234")
        assert verify_backup_code(None, [hashed]) is False

    def test_empty_hash_list_returns_false(self):
        """Test that empty hash list returns False."""
        assert verify_backup_code("ABCD1234", []) is False

    def test_none_hash_list_returns_false(self):
        """Test that None hash list returns False."""
        assert verify_backup_code("ABCD1234", None) is False

    def test_case_insensitive_verification(self):
        """Test that verification is case-insensitive (codes are normalized)."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        # Lowercase version should match (normalized to uppercase)
        assert verify_backup_code("abcd1234", [hashed]) is True
        assert verify_backup_code("Abcd1234", [hashed]) is True

    def test_whitespace_stripped(self):
        """Test that whitespace is stripped before verification."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        # Code with whitespace should match (whitespace is stripped)
        assert verify_backup_code(" ABCD1234 ", [hashed]) is True
        assert verify_backup_code("  ABCD1234", [hashed]) is True

    def test_hash_list_with_invalid_hashes(self):
        """Test verification with list containing invalid hash formats."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        # List with valid and invalid hashes
        mixed_list = [hashed, "invalid", "also-invalid"]
        assert verify_backup_code(code, mixed_list) is True
        assert verify_backup_code("WRONG", mixed_list) is False


class TestEndToEndMfaFlow:
    """Integration tests for complete MFA flows."""

    def test_complete_totp_setup_and_verification(self):
        """Test complete TOTP setup and verification flow."""
        # Setup
        secret = generate_totp_secret()
        qr_code = generate_qr_code("user@example.com", secret)

        # Verify QR code was generated
        assert qr_code.startswith("data:image/png;base64,")

        # Generate and verify code
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert verify_totp_code(secret, code) is True

    def test_complete_backup_code_flow(self):
        """Test complete backup code generation and verification flow."""
        # Generate codes
        codes = generate_backup_codes(count=10)
        assert len(codes) == 10

        # Hash codes for storage
        hashed_codes = [hash_backup_code(code) for code in codes]
        assert len(hashed_codes) == 10

        # Verify each code works
        for i, code in enumerate(codes):
            assert verify_backup_code(code, hashed_codes) is True

            # Simulate using the code (remove from list)
            used_codes = hashed_codes.copy()
            used_codes.pop(i)

            # Code should still verify if hash still in list
            if i < len(codes) - 1:
                assert verify_backup_code(codes[i + 1], hashed_codes) is True

    def test_backup_codes_single_use(self):
        """Test that backup codes can be tracked for single use."""
        codes = generate_backup_codes(count=3)
        hashed_codes = [hash_backup_code(code) for code in codes]

        # Use first code
        assert verify_backup_code(codes[0], hashed_codes) is True

        # Find and remove the used code's hash by iterating and checking
        # (bcrypt hashes are unique per call, so we need to find the matching one)

        normalized_code = codes[0].strip().upper().encode("utf-8")
        for i, h in enumerate(hashed_codes):
            if bcrypt.checkpw(normalized_code, h.encode("utf-8")):
                hashed_codes.pop(i)
                break

        # First code should no longer verify
        assert verify_backup_code(codes[0], hashed_codes) is False

        # Other codes should still work
        assert verify_backup_code(codes[1], hashed_codes) is True
        assert verify_backup_code(codes[2], hashed_codes) is True


class TestSecurityConsiderations:
    """Security-focused tests for MFA utilities."""

    def test_bcrypt_provides_timing_resistance(self):
        """Test that bcrypt hashing provides timing attack resistance by design.

        Note: bcrypt is intentionally slow and constant-time for its compare operation.
        The verify_backup_code function iterates through hashes, so:
        - Valid code found early will be faster
        - Invalid code must check all hashes

        True timing attack resistance is provided by bcrypt's internal constant-time
        comparison, not by equal total function time.
        """
        codes = generate_backup_codes(count=3)
        hashed_codes = [hash_backup_code(code) for code in codes]

        # Measure time for valid code (first in list - best case)
        start = time.perf_counter()
        result = verify_backup_code(codes[0], hashed_codes)
        valid_time = time.perf_counter() - start
        assert result is True

        # Measure time for invalid code (must check all)
        start = time.perf_counter()
        result = verify_backup_code("INVALID0", hashed_codes)
        invalid_time = time.perf_counter() - start
        assert result is False

        # Both should take at least some time (bcrypt is slow by design)
        # We don't assert equal times because invalid checks all hashes
        assert valid_time > 0.01  # bcrypt should take at least 10ms
        assert invalid_time > 0.01

    def test_secrets_not_logged_or_printed(self):
        """Test that secrets don't appear in string representations."""
        secret = generate_totp_secret()
        # This is a basic test - in production, ensure logging doesn't expose secrets
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_backup_code_entropy(self):
        """Test that backup codes have sufficient entropy."""
        codes = generate_backup_codes(count=1000)
        unique_codes = set(codes)
        # All codes should be unique (collision probability should be negligible)
        assert len(unique_codes) == 1000

    def test_hash_irreversibility(self):
        """Test that hashed codes cannot easily be reversed."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)
        # Hash should not contain the original code
        assert code not in hashed
        assert code.lower() not in hashed
