"""Tests for MFA utilities."""

from server.utils.mfa import (
    generate_backup_codes,
    generate_qr_code,
    generate_totp_secret,
    get_totp_uri,
    hash_backup_code,
    verify_backup_code,
    verify_totp_code,
)


class TestMFAUtilities:
    """Test MFA utility functions."""

    def test_generate_totp_secret(self):
        """Test TOTP secret generation."""
        secret1 = generate_totp_secret()
        secret2 = generate_totp_secret()

        # Should be base32 encoded
        assert isinstance(secret1, str)
        assert len(secret1) > 0

        # Should be unique
        assert secret1 != secret2

    def test_get_totp_uri(self):
        """Test TOTP URI generation."""
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, "test@example.com", "AgentGate")

        assert uri.startswith("otpauth://totp/")
        # Email is URL-encoded in the URI (@ becomes %40)
        assert "test%40example.com" in uri or "test@example.com" in uri
        assert "AgentGate" in uri
        assert f"secret={secret}" in uri

    def test_generate_qr_code(self):
        """Test QR code generation."""
        secret = generate_totp_secret()
        qr_data = generate_qr_code("test@example.com", secret)

        assert qr_data.startswith("data:image/png;base64,")
        assert len(qr_data) > 100  # Should contain actual image data

    def test_verify_totp_code_invalid_inputs(self):
        """Test TOTP verification with invalid inputs."""
        assert verify_totp_code("", "123456") is False
        assert verify_totp_code("SECRET", "") is False
        assert verify_totp_code("", "") is False

    def test_verify_totp_code_invalid_code(self):
        """Test TOTP verification with invalid code."""
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "000000") is False

    def test_generate_backup_codes(self):
        """Test backup code generation."""
        codes = generate_backup_codes(10)

        assert len(codes) == 10
        assert all(len(code) == 8 for code in codes)

        # Should be unique
        assert len(set(codes)) == 10

    def test_generate_backup_codes_custom_count(self):
        """Test backup code generation with custom count."""
        codes = generate_backup_codes(5)
        assert len(codes) == 5

    def test_hash_backup_code(self):
        """Test backup code hashing."""
        code = "ABCD1234"
        hashed = hash_backup_code(code)

        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")
        assert len(hashed) == 60  # bcrypt hash length
        assert verify_backup_code(code, [hashed]) is True

    def test_verify_backup_code_success(self):
        """Test successful backup code verification."""
        codes = generate_backup_codes(5)
        hashed_codes = [hash_backup_code(code) for code in codes]

        # Should verify first code
        assert verify_backup_code(codes[0], hashed_codes) is True

    def test_verify_backup_code_failure(self):
        """Test failed backup code verification."""
        codes = generate_backup_codes(5)
        hashed_codes = [hash_backup_code(code) for code in codes]

        # Invalid code should not verify
        assert verify_backup_code("INVALID", hashed_codes) is False

    def test_verify_backup_code_invalid_inputs(self):
        """Test backup code verification with invalid inputs."""
        assert verify_backup_code("", ["hash1", "hash2"]) is False
        assert verify_backup_code("CODE123", []) is False
        assert verify_backup_code("", []) is False
