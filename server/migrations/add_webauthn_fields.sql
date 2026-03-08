-- Add WebAuthn/Passkey fields to users table
-- Migration: add_webauthn_fields
-- Date: 2025-01-28

-- Add webauthn_credentials column to store passkey credentials
ALTER TABLE users ADD COLUMN IF NOT EXISTS webauthn_credentials JSON DEFAULT NULL;

-- Add comment for documentation
COMMENT ON COLUMN users.webauthn_credentials IS 'WebAuthn credentials for passwordless authentication. Each credential contains: credential_id, public_key, sign_count, transports, created_at, last_used, name';
