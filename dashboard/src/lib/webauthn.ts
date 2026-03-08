/**
 * WebAuthn/Passkey client utilities
 *
 * Provides browser-side functions for passwordless authentication using:
 * - Platform authenticators (Touch ID, Face ID, Windows Hello)
 * - Security keys (YubiKey, etc.)
 *
 * @module webauthn
 */

import { getSession } from 'next-auth/react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/**
 * Get access token from NextAuth session
 */
async function getAccessToken(): Promise<string | null> {
  if (typeof window === 'undefined') return null;
  const session = await getSession();
  return session?.accessToken || null;
}

/**
 * Convert ArrayBuffer to Base64URL string (WebAuthn standard encoding)
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Convert standard base64 to base64url
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Convert Base64 or Base64URL string to ArrayBuffer
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  // Convert base64url to standard base64
  let standardBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  while (standardBase64.length % 4 !== 0) {
    standardBase64 += '=';
  }
  const binary = atob(standardBase64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert PublicKeyCredential to JSON format
 */
function credentialToJSON(credential: PublicKeyCredential): any {
  const response = credential.response;

  if (response instanceof AuthenticatorAttestationResponse) {
    // Registration response
    return {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
        attestationObject: arrayBufferToBase64(response.attestationObject),
        transports: response.getTransports ? response.getTransports() : [],
      },
    };
  } else if (response instanceof AuthenticatorAssertionResponse) {
    // Authentication response
    return {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
        authenticatorData: arrayBufferToBase64(response.authenticatorData),
        signature: arrayBufferToBase64(response.signature),
        userHandle: response.userHandle ? arrayBufferToBase64(response.userHandle) : null,
      },
    };
  }

  throw new Error('Unknown credential response type');
}

/**
 * Convert registration options from server to browser format
 */
function parseRegistrationOptions(options: any): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: base64ToArrayBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64ToArrayBuffer(options.user.id),
    },
    excludeCredentials: options.excludeCredentials?.map((cred: any) => ({
      ...cred,
      id: base64ToArrayBuffer(cred.id),
    })),
  };
}

/**
 * Convert authentication options from server to browser format
 */
function parseAuthenticationOptions(options: any): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64ToArrayBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((cred: any) => ({
      ...cred,
      id: base64ToArrayBuffer(cred.id),
    })),
  };
}

/**
 * Check if WebAuthn is supported in this browser
 */
export function isWebAuthnSupported(): boolean {
  return !!(
    typeof window !== 'undefined' &&
    window.PublicKeyCredential &&
    navigator.credentials &&
    typeof navigator.credentials.create === 'function' &&
    typeof navigator.credentials.get === 'function'
  );
}

/**
 * Check if platform authenticator is available (Touch ID, Face ID, Windows Hello)
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Register a new passkey for the current user
 *
 * @param name - Friendly name for the passkey (e.g., "MacBook Touch ID")
 * @returns Promise that resolves when registration is complete
 * @throws Error if registration fails or is cancelled
 */
export async function registerPasskey(name: string = 'Passkey'): Promise<void> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  const token = await getAccessToken();
  if (!token) {
    throw new Error('Not authenticated');
  }

  // Start registration
  const startResponse = await fetch(`${API_BASE}/api/auth/passkey/register-start`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (!startResponse.ok) {
    const error = await startResponse.json();
    throw new Error(error.detail || 'Failed to start registration');
  }

  const { options, challenge_id } = await startResponse.json();

  // Parse options for browser API
  const creationOptions = parseRegistrationOptions(options);

  // Create credential
  const credential = await navigator.credentials.create({
    publicKey: creationOptions,
  }) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Credential creation was cancelled');
  }

  // Finish registration
  const finishResponse = await fetch(`${API_BASE}/api/auth/passkey/register-finish`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      credential: credentialToJSON(credential),
      challenge_id,
      name,
    }),
  });

  if (!finishResponse.ok) {
    const error = await finishResponse.json();
    throw new Error(error.detail || 'Failed to finish registration');
  }
}

/**
 * Authenticate using a passkey
 *
 * @param email - User's email address
 * @returns Authentication tokens and user info
 * @throws Error if authentication fails or is cancelled
 */
export async function loginWithPasskey(email: string): Promise<{
  access_token: string;
  refresh_token: string;
  user: any;
}> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Start authentication
  const startResponse = await fetch(`${API_BASE}/api/auth/passkey/login-start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });

  if (!startResponse.ok) {
    const error = await startResponse.json();
    throw new Error(error.detail || 'Failed to start authentication');
  }

  const { options, challenge_id } = await startResponse.json();

  // Parse options for browser API
  const requestOptions = parseAuthenticationOptions(options);

  // Get credential
  const credential = await navigator.credentials.get({
    publicKey: requestOptions,
  }) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Authentication was cancelled');
  }

  // Finish authentication
  const finishResponse = await fetch(`${API_BASE}/api/auth/passkey/login-finish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential: credentialToJSON(credential),
      challenge_id,
      email,
    }),
  });

  if (!finishResponse.ok) {
    const error = await finishResponse.json();
    throw new Error(error.detail || 'Failed to finish authentication');
  }

  return finishResponse.json();
}

/**
 * List all registered passkeys for the current user
 *
 * @returns Array of passkey metadata
 */
export async function listPasskeys(): Promise<Array<{
  credential_id: string;
  name: string;
  created_at: string;
  last_used: string;
  transports: string[];
}>> {
  const token = await getAccessToken();
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch(`${API_BASE}/api/auth/passkey/list`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to list passkeys');
  }

  return response.json();
}

/**
 * Delete a passkey
 *
 * @param credentialId - ID of the credential to delete
 */
export async function deletePasskey(credentialId: string): Promise<void> {
  const token = await getAccessToken();
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch(`${API_BASE}/api/auth/passkey/${credentialId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to delete passkey');
  }
}

/**
 * Rename a passkey
 *
 * @param credentialId - ID of the credential to rename
 * @param name - New name for the passkey
 */
export async function renamePasskey(credentialId: string, name: string): Promise<void> {
  const token = await getAccessToken();
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch(`${API_BASE}/api/auth/passkey/${credentialId}`, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to rename passkey');
  }
}
