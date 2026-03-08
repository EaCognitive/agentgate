import { type NextAuthOptions } from 'next-auth';
import { JWT } from 'next-auth/jwt';
import CredentialsProvider from 'next-auth/providers/credentials';
import { UserRole } from '@/types';

/**
 * Extended JWT type that includes user role
 */
declare module 'next-auth/jwt' {
  interface JWT {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    accessToken?: string;
    refreshToken?: string;
    accessTokenExpires?: number;
  }
}

/**
 * Extended Session type that includes user role
 */
declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      email: string;
      name: string;
      role: UserRole;
    };
    accessToken?: string;
  }
}

/**
 * Backend API login response type
 */
interface BackendLoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: {
    id: string;
    email: string;
    name: string;
    role: UserRole;
  };
}

/**
 * Backend error response type
 */
interface BackendErrorResponse {
  error: string;
  message: string;
  status_code: number;
}

function normalizeBackendBase(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, '');
  return trimmed.replace(/\/api$/, '');
}

function resolveBackendUrl(): string {
  const candidates = [
    process.env.API_URL,
    process.env.AGENTGATE_API_URL,
    process.env.NEXT_PUBLIC_API_URL,
  ];

  for (const candidate of candidates) {
    if (candidate && candidate.trim()) {
      return normalizeBackendBase(candidate);
    }
  }

  return 'http://localhost:8000';
}

// Server-side API URL used for auth/login/refresh calls.
const BACKEND_URL = resolveBackendUrl();

/**
 * Refresh the backend access token using a refresh token.
 */
async function refreshAccessToken(token: JWT): Promise<JWT> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: token.refreshToken }),
    });

    if (!response.ok) {
      throw new Error('Refresh failed');
    }

    const data = await response.json();
    return {
      ...token,
      accessToken: data.access_token,
      accessTokenExpires: Date.now() + data.expires_in * 1000,
    };
  } catch {
    // Refresh failed - return token as-is, forcing re-login
    return { ...token, accessToken: undefined };
  }
}

/**
 * NextAuth configuration for AgentGate dashboard
 */
export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'email', placeholder: 'user@example.com' },
        password: { label: 'Password', type: 'password' },
        providerToken: { label: 'Provider Token', type: 'text' },
        providerHint: { label: 'Provider Hint', type: 'text' },
      },
      async authorize(credentials) {
        const providerToken = credentials?.providerToken?.trim();
        const providerHint = credentials?.providerHint?.trim();

        try {
          let response: Response;
          if (providerToken && providerHint === 'demo_link') {
            // Demo link flow: the token is already a backend JWT.
            // Validate it by fetching user info, then wrap into session.
            const meRes = await fetch(`${BACKEND_URL}/api/auth/me`, {
              headers: { 'Authorization': `Bearer ${providerToken}` },
            });
            if (!meRes.ok) {
              throw new Error('Demo link token is invalid or expired');
            }
            const user = await meRes.json();
            return {
              id: user.id ?? user.user_id ?? '0',
              email: user.email ?? '',
              name: user.name ?? 'Demo User',
              role: user.role ?? 'viewer',
              accessToken: providerToken,
              refreshToken: '',
              accessTokenExpires: Date.now() + 7 * 24 * 60 * 60 * 1000,
            };
          } else if (providerToken) {
            response = await fetch(`${BACKEND_URL}/api/auth/exchange`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                provider_token: providerToken,
                provider_hint: providerHint || undefined,
              }),
            });
          } else {
            if (!credentials?.email || !credentials?.password) {
              throw new Error('Email and password are required');
            }
            response = await fetch(`${BACKEND_URL}/api/auth/login`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                email: credentials.email,
                password: credentials.password,
              }),
            });
          }

          if (!response.ok) {
            const errorData = await response.json().catch(() => ({} as BackendErrorResponse));
            const detail = (errorData as any).detail;
            if (typeof detail === 'string' && detail.trim()) {
              throw new Error(detail);
            }
            throw new Error((errorData as BackendErrorResponse).message || 'Authentication failed');
          }

          const data: BackendLoginResponse = await response.json();

          return {
            id: data.user.id,
            email: data.user.email,
            name: data.user.name,
            role: data.user.role,
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            accessTokenExpires: Date.now() + data.expires_in * 1000,
          };
        } catch (error) {
          if (error instanceof Error) {
            throw new Error(error.message);
          }
          throw new Error('Authentication failed');
        }
      },
    }),
  ],
  pages: {
    signIn: '/login',
    error: '/login',
  },
  callbacks: {
    /**
     * JWT callback to include user data in token and auto-refresh
     */
    async jwt({ token, user }) {
      // Initial sign-in: store all fields from authorize()
      if (user) {
        token.id = user.id;
        token.email = user.email ?? '';
        token.name = user.name ?? '';
        token.role = (user as any).role || UserRole.Viewer;
        token.accessToken = (user as any).accessToken;
        token.refreshToken = (user as any).refreshToken;
        token.accessTokenExpires = (user as any).accessTokenExpires;
        return token;
      }

      // Subsequent requests: refresh if token expired or about to expire (60s buffer)
      if (token.accessTokenExpires && Date.now() < token.accessTokenExpires - 60_000) {
        return token;
      }

      // Token expired - attempt refresh
      if (token.refreshToken) {
        return refreshAccessToken(token);
      }

      return token;
    },

    /**
     * Session callback to include user role in session
     */
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id;
        session.user.email = token.email;
        session.user.name = token.name;
        session.user.role = token.role as UserRole;
      }
      session.accessToken = token.accessToken;
      return session;
    },

    /**
     * Redirect callback for post-login navigation
     */
    async redirect({ url, baseUrl }) {
      // Allows relative callback URLs
      if (url.startsWith('/')) {
        return `${baseUrl}${url}`;
      }
      // Allows callback URLs on the same origin
      if (new URL(url).origin === baseUrl) {
        return url;
      }
      return baseUrl;
    },
  },
  events: {
    // Sign-in and sign-out events can be extended for analytics/logging
  },
  session: {
    strategy: 'jwt',
    maxAge: 7 * 24 * 60 * 60, // 7 days
  },
  jwt: {
    secret: process.env.NEXTAUTH_SECRET,
    maxAge: 7 * 24 * 60 * 60, // 7 days
  },
  secret: process.env.NEXTAUTH_SECRET,
};
