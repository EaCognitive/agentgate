import { authOptions } from '@/lib/auth';
import NextAuth from 'next-auth';

/**
 * NextAuth handler for dynamic route [...nextauth]
 * Handles all authentication endpoints:
 * - /api/auth/signin
 * - /api/auth/callback/[provider]
 * - /api/auth/session
 * - /api/auth/signout
 * - /api/auth/providers
 */
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
