-- Add failed login tracking columns to users table
-- This enables CAPTCHA protection after 3 failed login attempts

ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN last_failed_login TIMESTAMP;
