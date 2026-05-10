import { NextRequest, NextResponse } from 'next/server';

const AUTH_TOKEN = process.env.VANE_AUTH_TOKEN;
const SESSION_COOKIE = 'vane_session';
const LOGIN_PATH = '/login';
const LOGIN_API_PATH = '/api/auth/login';

/**
 * Auth middleware for Vane.
 *
 * When VANE_AUTH_TOKEN is NOT set: all requests pass through (localhost default).
 * When VANE_AUTH_TOKEN IS set:
 *   - /api/* routes: require Authorization: Bearer <token> header
 *   - UI routes: require vane_session cookie; redirect to /login if absent
 *   - /login and /api/auth/login: always allowed
 */
export function middleware(request: NextRequest): NextResponse {
  // Auth disabled — pass through
  if (!AUTH_TOKEN) {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;

  // Always allow login page and login API
  if (pathname === LOGIN_PATH || pathname === LOGIN_API_PATH) {
    return NextResponse.next();
  }

  // API routes: require Authorization: Bearer header
  if (pathname.startsWith('/api/')) {
    const authHeader = request.headers.get('authorization') ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (token !== AUTH_TOKEN) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.next();
  }

  // UI routes: require session cookie
  const sessionCookie = request.cookies.get(SESSION_COOKIE)?.value ?? '';
  if (sessionCookie !== AUTH_TOKEN) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = LOGIN_PATH;
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
