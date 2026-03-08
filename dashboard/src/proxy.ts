import { withAuth } from 'next-auth/middleware';
import { NextResponse } from 'next/server';

function isPublicRoute(pathname: string): boolean {
  return (
    pathname === '/login' ||
    pathname === '/signup' ||
    pathname === '/setup' ||
    pathname === '/docs' ||
    pathname.startsWith('/docs/')
  );
}

export default withAuth(
  function middleware(req) {
    const { pathname } = req.nextUrl;
    const token = req.nextauth?.token;

    // If user is authenticated and trying to access auth pages, redirect to dashboard
    if (token && (pathname === '/login' || pathname === '/signup' || pathname === '/setup')) {
      return NextResponse.redirect(new URL('/', req.url));
    }

    const response = NextResponse.next();

    // Prevent caching of protected pages to stop back-button access after logout
    if (!isPublicRoute(pathname)) {
      response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      response.headers.set('Pragma', 'no-cache');
      response.headers.set('Expires', '0');
    }

    return response;
  },
  {
    callbacks: {
      authorized: ({ token, req }) => {
        const { pathname } = req.nextUrl;

        // Allow public routes without authentication
        if (isPublicRoute(pathname)) {
          return true;
        }

        // All other routes require authentication
        return !!token;
      },
    },
    pages: {
      signIn: '/login',
    },
  }
);

export const config = {
  matcher: [
    /*
     * Match all paths except:
     * - api routes (they handle their own auth)
     * - _next (Next.js internals)
     * - static files
     */
    '/((?!api|d/|_next/static|_next/image|favicon.ico|.*\\.png$|.*\\.svg$).*)',
  ],
};
