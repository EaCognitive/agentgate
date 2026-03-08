# Multi-Factor Authentication (MFA) Setup Guide

## Overview

AgentGate supports Time-based One-Time Password (TOTP) 2FA for enhanced account security.

Compatible with:
- Google Authenticator
- Authy
- Microsoft Authenticator
- Any TOTP-compatible app

## Enabling MFA

### Step 1: Initialize MFA

```bash
POST /api/auth/enable-2fa
Authorization: Bearer {your_token}
```

Response:
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,...",
  "backup_codes": [
    "AAAA1111",
    "BBBB2222",
    ...
  ]
}
```

**Important**: Save your backup codes in a secure location. They will not be shown again.

### Step 2: Scan QR Code

1. Open your authenticator app
2. Scan the QR code from the response
3. Or manually enter the secret key

### Step 3: Verify and Enable

```bash
POST /api/auth/verify-2fa
Authorization: Bearer {your_token}
{
  "code": "123456"
}
```

MFA is now enabled!

## Logging In with MFA

### First Request (without code)

```bash
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "your_password"
}
```

Response:
```json
{
  "mfa_required": true,
  "message": "2FA code required"
}
```

### Second Request (with code)

```bash
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "your_password",
  "totp_code": "123456"
}
```

Response:
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "user": { ... }
}
```

## Using Backup Codes

If you lose access to your authenticator app, use a backup code:

```bash
POST /api/auth/login
{
  "email": "user@example.com",
  "password": "your_password",
  "totp_code": "AAAA1111"
}
```

**Note**: Each backup code can only be used once.

## Regenerating Backup Codes

```bash
POST /api/auth/regenerate-backup-codes
Authorization: Bearer {your_token}
{
  "password": "your_password"
}
```

## Disabling MFA

```bash
POST /api/auth/disable-2fa
Authorization: Bearer {your_token}
{
  "password": "your_password"
}
```

## Security Best Practices

1. **Store backup codes securely** - Print them or store in a password manager
2. **Use a unique password** - Don't reuse passwords from other sites
3. **Keep authenticator app synced** - Ensure device time is accurate
4. **Regenerate codes periodically** - Refresh backup codes every 6 months

## Troubleshooting

### "Invalid 2FA code" Error

- Ensure your device clock is accurate (within 30 seconds)
- Try the next code if you're at a time boundary
- Use a backup code if your authenticator is unavailable

### Lost Access to Authenticator

- Use one of your backup codes to log in
- Once logged in, disable and re-enable MFA
- Generate new backup codes

### Backup Codes Not Working

- Ensure you're using the correct format (8 characters)
- Remember: each code works only once
- If all codes are used, regenerate new ones

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/enable-2fa` | POST | Initialize MFA setup |
| `/api/auth/verify-2fa` | POST | Verify code and enable MFA |
| `/api/auth/disable-2fa` | POST | Disable MFA (password in JSON body) |
| `/api/auth/regenerate-backup-codes` | POST | Generate new backup codes (password in JSON body) |
| `/api/auth/check-mfa` | POST | Check if email has MFA enabled |

## Client Implementation Example

```python
import requests

# Check if user has MFA
response = requests.post(
    "http://localhost:8000/api/auth/check-mfa",
    params={"email": "user@example.com"}
)
has_mfa = response.json()["mfa_enabled"]

# Login
if has_mfa:
    code = input("Enter 2FA code: ")
    response = requests.post(
        "http://localhost:8000/api/auth/login",
        json={
            "email": "user@example.com",
            "password": password,
            "totp_code": code
        }
    )
else:
    response = requests.post(
        "http://localhost:8000/api/auth/login",
        json={
            "email": "user@example.com",
            "password": password
        }
    )
```
