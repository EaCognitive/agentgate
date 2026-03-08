# Passkey Authentication Guide

This guide explains how to use WebAuthn-based passkey authentication in AgentGate for passwordless, phishing-proof security.

## Table of Contents

- [What Are Passkeys?](#what-are-passkeys)
- [Benefits](#benefits)
- [Browser Compatibility](#browser-compatibility)
- [User Guide](#user-guide)
  - [Registering a Passkey](#registering-a-passkey)
  - [Logging In with a Passkey](#logging-in-with-a-passkey)
  - [Managing Passkeys](#managing-passkeys)
- [Developer Guide](#developer-guide)
  - [API Endpoints](#api-endpoints)
  - [Frontend Integration](#frontend-integration)
  - [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## What Are Passkeys?

Passkeys are a modern, passwordless authentication method based on the WebAuthn standard. They use public-key cryptography and can be backed by:

- **Built-in biometrics**: Face ID, Touch ID, Windows Hello
- **Hardware security keys**: YubiKey, Titan Security Key
- **Phone as authenticator**: Cross-device authentication

Unlike passwords:
- **Cannot be phished**: Credentials are cryptographically bound to your domain
- **Cannot be reused**: Each site gets unique credentials
- **Cannot be stolen**: Private keys never leave your device
- **Easier to use**: Just biometric verification, no typing

## Benefits

1. **Security**: Phishing-proof, hardware-backed, cryptographic authentication
2. **User Experience**: Faster than passwords, no typing required
3. **Privacy**: No password databases to breach
4. **Compliance**: Meets modern security standards (FIDO2, WebAuthn)

## Browser Compatibility

Passkeys are supported in:

✅ **Desktop**:
- Chrome/Edge 108+ (Windows, macOS, Linux)
- Safari 16+ (macOS)
- Firefox 122+ (Windows, macOS, Linux)

✅ **Mobile**:
- Safari iOS 16+
- Chrome Android 108+
- Samsung Internet 20+

Check support: Visit [caniuse.com/webauthn](https://caniuse.com/webauthn)

## User Guide

### Registering a Passkey

1. **Login** to your account with email/password
2. **Navigate** to Settings → Security → Passkeys
3. **Click** "Add Passkey"
4. **Choose a name** (e.g., "MacBook Touch ID", "YubiKey")
5. **Follow browser prompt**:
   - Touch ID: Touch the fingerprint sensor
   - Face ID: Look at the camera
   - Windows Hello: Use PIN or biometric
   - Security key: Insert and tap the key
6. **Done!** Your passkey is registered

**Tip**: Register multiple passkeys (laptop, phone, security key) for backup access.

### Logging In with a Passkey

1. **Navigate** to login page
2. **Enter your email**
3. **Click** "Sign in with Passkey" instead of password
4. **Verify your identity**:
   - Touch ID: Touch sensor
   - Face ID: Look at camera
   - Security key: Insert and tap
5. **Logged in!** No password needed

### Managing Passkeys

**View Passkeys**:
- Settings → Security → Passkeys
- Shows all registered passkeys with names and last used dates

**Rename a Passkey**:
1. Click "Rename" next to the passkey
2. Enter new name
3. Save

**Delete a Passkey**:
1. Click "Delete" next to the passkey
2. Confirm deletion

⚠️ **Warning**: Don't delete your last passkey if you don't have a password!

## Developer Guide

### API Endpoints

#### 1. Start Passkey Registration

```http
POST /api/auth/passkey/register-start
Authorization: Bearer <access_token>
```

Response:
```json
{
  "options": { /* PublicKeyCredentialCreationOptions */ },
  "challenge_id": "random-challenge-id"
}
```

#### 2. Finish Passkey Registration

```http
POST /api/auth/passkey/register-finish
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "credential": { /* PublicKeyCredential from browser */ },
  "challenge_id": "random-challenge-id",
  "name": "MacBook Touch ID"
}
```

Response:
```json
{
  "status": "registered",
  "credential_id": "base64-credential-id",
  "name": "MacBook Touch ID"
}
```

#### 3. Start Passkey Login

```http
POST /api/auth/passkey/login-start
Content-Type: application/json

{
  "email": "user@example.com"
}
```

Response:
```json
{
  "options": { /* PublicKeyCredentialRequestOptions */ },
  "challenge_id": "random-challenge-id"
}
```

#### 4. Finish Passkey Login

```http
POST /api/auth/passkey/login-finish
Content-Type: application/json

{
  "credential": { /* PublicKeyCredential from browser */ },
  "challenge_id": "random-challenge-id",
  "email": "user@example.com"
}
```

Response:
```json
{
  "access_token": "jwt-token",
  "refresh_token": "refresh-token",
  "token_type": "bearer",
  "expires_in": 900,
  "user": { /* UserRead */ }
}
```

#### 5. List Passkeys

```http
GET /api/auth/passkey/list
Authorization: Bearer <access_token>
```

Response:
```json
[
  {
    "credential_id": "base64-credential-id",
    "name": "MacBook Touch ID",
    "created_at": "2025-01-28T10:00:00Z",
    "last_used": "2025-01-28T12:00:00Z",
    "transports": ["internal"]
  }
]
```

#### 6. Delete Passkey

```http
DELETE /api/auth/passkey/{credential_id}
Authorization: Bearer <access_token>
```

#### 7. Rename Passkey

```http
PATCH /api/auth/passkey/{credential_id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "New Name"
}
```

### Frontend Integration

#### Basic Usage

```typescript
import {
  registerPasskey,
  loginWithPasskey,
  listPasskeys,
  deletePasskey,
  renamePasskey,
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
} from '@/lib/webauthn';

// Check if supported
if (await isPlatformAuthenticatorAvailable()) {
  console.log('Passkeys available!');
}

// Register a passkey
try {
  await registerPasskey('My Laptop');
  console.log('Passkey registered!');
} catch (error) {
  console.error('Registration failed:', error);
}

// Login with passkey
try {
  const { access_token, user } = await loginWithPasskey('user@example.com');
  localStorage.setItem('access_token', access_token);
  console.log('Logged in:', user);
} catch (error) {
  console.error('Login failed:', error);
}

// List passkeys
const passkeys = await listPasskeys();
console.log('Registered passkeys:', passkeys);

// Delete a passkey
await deletePasskey(credentialId);

// Rename a passkey
await renamePasskey(credentialId, 'New Name');
```

#### React Component Example

```tsx
'use client';

import { useState } from 'react';
import { registerPasskey, isPlatformAuthenticatorAvailable } from '@/lib/webauthn';

export default function PasskeySetup() {
  const [loading, setLoading] = useState(false);
  const [supported, setSupported] = useState(false);

  useEffect(() => {
    isPlatformAuthenticatorAvailable().then(setSupported);
  }, []);

  const handleRegister = async () => {
    setLoading(true);
    try {
      await registerPasskey('My Device');
      alert('Passkey registered!');
    } catch (error) {
      alert('Failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  if (!supported) {
    return <p>Passkeys not supported on this device</p>;
  }

  return (
    <button onClick={handleRegister} disabled={loading}>
      {loading ? 'Registering...' : 'Add Passkey'}
    </button>
  );
}
```

### Configuration

Set environment variables:

```bash
# Development (localhost)
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME="AgentGate Dev"
WEBAUTHN_ORIGIN=http://localhost:3000

# Production
WEBAUTHN_RP_ID=agentgate.com
WEBAUTHN_RP_NAME="AgentGate"
WEBAUTHN_ORIGIN=https://agentgate.com
```

⚠️ **Important**:
- `WEBAUTHN_RP_ID` must match your domain (no protocol, no port)
- `WEBAUTHN_ORIGIN` must include protocol and match exactly
- For localhost testing, use `localhost` not `127.0.0.1`

## Security Considerations

### Best Practices

1. **Always use HTTPS** in production (WebAuthn requires secure context)
2. **Validate RP ID** matches your domain to prevent phishing
3. **Store challenges securely** (use Redis with TTL, not in-memory)
4. **Implement rate limiting** on all endpoints
5. **Audit all operations** for compliance and security monitoring
6. **Allow multiple passkeys** per user for backup access
7. **Don't force passwordless** - offer it as an option alongside passwords

### Threat Model

✅ **Protected Against**:
- Phishing attacks (credentials bound to domain)
- Credential theft (private keys never leave device)
- Password reuse
- Brute force attacks
- Man-in-the-middle attacks

⚠️ **Still Vulnerable To**:
- Device theft (mitigated by biometric/PIN protection)
- Social engineering (teaching users good practices)
- Malware on device (OS-level security required)

### Compliance

Passkeys help meet:
- **NIST 800-63-3**: Phishing-resistant authenticators
- **PSD2 SCA**: Strong customer authentication
- **GDPR**: Data minimization (no passwords stored)
- **FIDO2**: Open authentication standard

## Troubleshooting

### "WebAuthn not supported"

**Solution**: Update browser to latest version. Check [caniuse.com/webauthn](https://caniuse.com/webauthn).

### "No platform authenticator available"

**Causes**:
- Device lacks biometric hardware
- Biometric not set up in OS settings
- Browser doesn't have permission

**Solution**:
1. Check OS biometric settings (Touch ID, Face ID, Windows Hello)
2. Try a hardware security key instead
3. Use password + 2FA as fallback

### "Invalid or expired challenge"

**Causes**:
- Challenge expired (5 min timeout)
- Server restarted (in-memory storage)
- Clock skew between client/server

**Solution**:
1. Retry authentication
2. In production, use Redis for challenge storage
3. Check system time is correct

### "Origin mismatch"

**Causes**:
- `WEBAUTHN_ORIGIN` doesn't match browser URL
- Using IP address instead of domain
- HTTP/HTTPS mismatch

**Solution**:
1. Check environment variables match your URL exactly
2. Use `localhost` not `127.0.0.1` for development
3. Use HTTPS in production

### "Credential not found"

**Causes**:
- Passkey was deleted
- Wrong email address
- Database was cleared

**Solution**:
1. Re-register the passkey
2. Check email is correct
3. Use password login as fallback

### Touch ID/Face ID not working

**macOS**:
1. System Settings → Touch ID & Password
2. Enable "Use Touch ID for..."
3. Add fingerprints if needed
4. Restart browser

**iOS**:
1. Settings → Face ID & Passcode
2. Enable Face ID for Safari
3. Restart Safari

**Windows**:
1. Settings → Accounts → Sign-in options
2. Set up Windows Hello
3. Restart browser

## Resources

- [WebAuthn Guide](https://webauthn.guide/)
- [FIDO Alliance](https://fidoalliance.org/)
- [W3C WebAuthn Spec](https://www.w3.org/TR/webauthn/)
- [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

## Support

For issues or questions:
- GitHub Issues: [agentgate/issues](https://github.com/EaCognitive/agentgate/issues)
- Documentation: [README.md](../README.md)
- Security: See [Security Model](security.md)
