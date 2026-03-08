"""WebAuthn/Passkey authentication utilities.

This module provides utilities for WebAuthn-based passwordless authentication
using biometrics (Face ID, Touch ID, Windows Hello) or hardware security keys.

Security features:
- Phishing-proof cryptographic verification
- Hardware-backed authentication
- No password transmission
- FIDO2 standard compliance
"""

import base64
import logging
import os
import secrets
from datetime import datetime, timezone

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers import options_to_json_dict
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorTransport,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

logger = logging.getLogger(__name__)


# RP (Relying Party) configuration
# These should be configured via environment variables in production
def get_rp_config() -> tuple[str, str, str]:
    """Get Relying Party configuration from environment.

    Returns:
        Tuple of (rp_id, rp_name, origin)
    """
    env = os.getenv("AGENTGATE_ENV", "development")

    if env == "production":
        return (
            os.getenv("WEBAUTHN_RP_ID", "agentgate.com"),
            os.getenv("WEBAUTHN_RP_NAME", "AgentGate"),
            os.getenv("WEBAUTHN_ORIGIN", "https://agentgate.com"),
        )

    # Development defaults
    return (
        os.getenv("WEBAUTHN_RP_ID", "localhost"),
        os.getenv("WEBAUTHN_RP_NAME", "AgentGate Dev"),
        os.getenv("WEBAUTHN_ORIGIN", "http://localhost:3000"),
    )


def generate_challenge() -> bytes:
    """Generate a cryptographic challenge for WebAuthn.

    Returns:
        32-byte random challenge
    """
    return secrets.token_bytes(32)


def get_registration_options(
    user_id: int,
    user_email: str,
    user_name: str,
    existing_credentials: list[dict] | None = None,
) -> dict:
    """Generate options for registering a new passkey.

    Args:
        user_id: User's database ID
        user_email: User's email address
        user_name: User's display name
        existing_credentials: List of existing credentials to exclude

    Returns:
        Dictionary containing registration options and challenge
    """
    rp_id, rp_name, _ = get_rp_config()

    # Convert existing credentials to exclude list
    exclude_credentials = []
    if existing_credentials:
        for cred in existing_credentials:
            try:
                credential_id = base64.b64decode(cred["credential_id"])
                transports = [AuthenticatorTransport(t) for t in cred.get("transports", [])]
                exclude_credentials.append(
                    PublicKeyCredentialDescriptor(id=credential_id, transports=transports)
                )
            except (ValueError, KeyError, TypeError):
                # Skip invalid credentials
                continue

    # Generate registration options
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=str(user_id).encode("utf-8"),
        user_name=user_email,
        user_display_name=user_name or user_email,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )

    # Convert to JSON-serializable format
    return {
        "options": options_to_json_dict(options),
        "challenge": base64.b64encode(options.challenge).decode("utf-8"),
    }


def verify_registration(
    credential: dict,
    expected_challenge: bytes,
    user_id: int,
) -> dict:
    """Verify registration response and return credential data.

    Args:
        credential: Registration credential from client
        expected_challenge: The challenge that was sent to the client
        user_id: User's database ID (unused but kept for API compatibility)

    Returns:
        Dictionary containing verified credential data

    Raises:
        Exception: If verification fails
    """
    del user_id  # Unused - kept for API compatibility
    _, _, origin = get_rp_config()
    rp_id, _, _ = get_rp_config()

    # Verify the registration response
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_origin=origin,
        expected_rp_id=rp_id,
    )

    # Return credential data for storage
    return {
        "credential_id": base64.b64encode(verification.credential_id).decode("utf-8"),
        "public_key": base64.b64encode(verification.credential_public_key).decode("utf-8"),
        "sign_count": verification.sign_count,
        "transports": credential.get("response", {}).get("transports", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_used": datetime.now(timezone.utc).isoformat(),
        "name": "Passkey",  # User can rename later
    }


def get_authentication_options(existing_credentials: list[dict] | None = None) -> dict:
    """Generate options for authenticating with passkey.

    Args:
        existing_credentials: List of user's existing credentials

    Returns:
        Dictionary containing authentication options and challenge
    """
    rp_id, _, _ = get_rp_config()

    # Convert existing credentials to allow list
    allow_credentials = []
    if existing_credentials:
        for cred in existing_credentials:
            try:
                credential_id = base64.b64decode(cred["credential_id"])
                transports = [AuthenticatorTransport(t) for t in cred.get("transports", [])]
                allow_credentials.append(
                    PublicKeyCredentialDescriptor(id=credential_id, transports=transports)
                )
            except (ValueError, KeyError, TypeError):
                # Skip invalid credentials
                continue

    # Generate authentication options
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    # Convert to JSON-serializable format
    return {
        "options": options_to_json_dict(options),
        "challenge": base64.b64encode(options.challenge).decode("utf-8"),
    }


def verify_authentication(
    credential: dict,
    expected_challenge: bytes,
    stored_credential: dict,
) -> tuple[bool, int]:
    """Verify authentication response.

    Args:
        credential: Authentication credential from client
        expected_challenge: The challenge that was sent to the client
        stored_credential: The stored credential data from database

    Returns:
        Tuple of (success: bool, new_sign_count: int)
    """
    _, _, origin = get_rp_config()
    rp_id, _, _ = get_rp_config()

    # Extract sign count early to ensure it is always available for error handling
    current_sign_count: int = stored_credential.get("sign_count", 0)

    try:
        # Decode stored credential data
        credential_public_key = base64.b64decode(stored_credential["public_key"])

        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=credential_public_key,
            credential_current_sign_count=current_sign_count,
        )

        return True, verification.new_sign_count
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("WebAuthn verification failed")
        return False, current_sign_count


def find_credential(credentials: list[dict], credential_id: str) -> dict | None:
    """Find a credential by its ID.

    Args:
        credentials: List of stored credentials
        credential_id: Base64-encoded credential ID to find

    Returns:
        The matching credential or None
    """
    for cred in credentials:
        if cred["credential_id"] == credential_id:
            return cred
    return None


def update_credential_last_used(credential: dict) -> dict:
    """Update the last_used timestamp of a credential.

    Args:
        credential: The credential to update

    Returns:
        Updated credential dictionary
    """
    credential["last_used"] = datetime.now(timezone.utc).isoformat()
    return credential
