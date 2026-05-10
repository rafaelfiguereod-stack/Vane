import { NextRequest, NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';

const AUTH_TOKEN = process.env.VANE_AUTH_TOKEN;
const SESSION_COOKIE = 'vane_session';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!AUTH_TOKEN) {
    // Auth disabled — login endpoint is a no-op
    return NextResponse.json({ ok: true });
  }

  let password: string;
  try {
    const body = await request.json();
    password = typeof body?.password === 'string' ? body.password : '';
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }

  // Timing-safe comparison to prevent timing attacks
  const tokenBuf = Buffer.from(AUTH_TOKEN, 'utf8');
  const inputBuf = Buffer.from(password, 'utf8');

  const match =
    tokenBuf.length === inputBuf.length &&
    timingSafeEqual(tokenBuf, inputBuf);

  if (!match) {
    return NextResponse.json({ error: 'Invalid password' }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE, AUTH_TOKEN, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: COOKIE_MAX_AGE,
    path: '/',
  });

  return response;
}
