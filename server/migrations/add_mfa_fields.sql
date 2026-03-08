-- Add MFA columns to users table
ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255);
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT FALSE NOT NULL;
ALTER TABLE users ADD COLUMN backup_codes JSON;

-- Add index for performance
CREATE INDEX idx_users_totp_enabled ON users(totp_enabled) WHERE totp_enabled = TRUE;
