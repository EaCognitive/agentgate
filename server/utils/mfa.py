"""Multi-Factor Authentication utilities for AgentGate.

Provides TOTP (Time-based One-Time Password) support for 2FA.
Includes functions for secret generation, TOTP verification, and backup code management.

Security Note: Backup codes are hashed with bcrypt (not SHA-256) to resist brute force attacks.
"""

import base64
import io
import secrets

import bcrypt
import pyotp
import qrcode


def generate_totp_secret() -> str:
    """Generate a secure random TOTP secret.

    Returns:
        Base32-encoded secret string suitable for TOTP usage.
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "AgentGate") -> str:
    """Generate provisioning URI for QR code generation.

    Args:
        secret: The TOTP secret key
        email: User's email address
        issuer: Application name (default: AgentGate)

    Returns:
        otpauth:// URI for QR code generation
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def generate_qr_code(email: str, secret: str, issuer: str = "AgentGate") -> str:
    """Generate QR code as base64-encoded data URI.

    Args:
        email: User's email address
        secret: The TOTP secret key
        issuer: Application name (default: AgentGate)

    Returns:
        Base64-encoded data URI of the QR code image
    """
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name=issuer)

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)

    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{qr_base64}"


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret.

    Args:
        secret: The TOTP secret key
        code: The 6-digit code to verify

    Returns:
        True if code is valid, False otherwise
    """
    if not secret or not code:
        return False

    try:
        # Strip whitespace and normalize code
        code = code.strip()
        totp = pyotp.TOTP(secret)
        # Allow 1 time step before/after for clock skew tolerance
        return totp.verify(code, valid_window=1)
    except (ValueError, TypeError):
        return False


def generate_backup_codes(count: int = 10) -> list[str]:
    """Generate backup codes for emergency access.

    Args:
        count: Number of backup codes to generate (default: 10)

    Returns:
        List of backup codes (8 characters each)
    """
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()  # 8 hex characters
        codes.append(code)
    return codes


def hash_backup_code(code: str) -> str:
    """Hash a backup code for secure storage using bcrypt.

    Uses bcrypt instead of SHA-256 for resistance to brute force attacks.
    Backup codes are short (8 chars) so bcrypt's slowness is essential.

    Args:
        code: Plain text backup code

    Returns:
        bcrypt hash of the code
    """
    # Normalize to uppercase for consistent hashing
    normalized = code.strip().upper()
    return bcrypt.hashpw(normalized.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_backup_code(code: str, hashed_codes: list[str]) -> bool:
    """Verify a backup code against stored bcrypt hashes.

    Args:
        code: Plain text backup code to verify
        hashed_codes: List of bcrypt-hashed backup codes

    Returns:
        True if code matches any stored hash, False otherwise
    """
    if not code or not hashed_codes:
        return False

    # Normalize to uppercase for consistent comparison
    normalized = code.strip().upper()
    code_bytes = normalized.encode("utf-8")

    for hashed in hashed_codes:
        try:
            if bcrypt.checkpw(code_bytes, hashed.encode("utf-8")):
                return True
        except (ValueError, TypeError):
            # Invalid hash format, skip it
            continue
    return False
