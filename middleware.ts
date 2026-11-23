// ============================================================
// NEXT.JS MIDDLEWARE
// - Generates per-request cryptographic nonce for strict CSP
// - Applies hardened HTTP security headers to all responses
// - Refreshes Supabase Auth SSR session cookies when cloud sync
//   is configured (HttpOnly, SameSite=Lax, Secure in prod)
// ============================================================

import { NextResponse, type NextRequest } from 'next/server';
import { createServerClient } from '@supabase/ssr';
import { getSecurityHeaders } from '@/lib/security/csp';

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

export async function middleware(request: NextRequest) {
  const isDev = process.env.NODE_ENV !== 'production';
  const nonce = generateNonce();
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  const securityHeaders = getSecurityHeaders({
    nonce,
    isDev,
    supabaseUrl,
  });

  // Pass CSP on request headers so Next.js App Router attaches the nonce to its inline scripts
  requestHeaders.set('Content-Security-Policy', securityHeaders['Content-Security-Policy']);

  let response = NextResponse.next({
    request: { headers: requestHeaders },
  });

  // Refresh Supabase SSR session cookies transparently if cloud sync is configured
  if (supabaseUrl && supabaseAnonKey) {
    const supabase = createServerClient(supabaseUrl, supabaseAnonKey, {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => {
            request.cookies.set(name, value);
          });
          response = NextResponse.next({
            request: { headers: requestHeaders },
          });
          cookiesToSet.forEach(({ name, value, options }) => {
            response.cookies.set(name, value, {
              ...options,
              httpOnly: true,
              sameSite: 'lax',
              secure: !isDev,
              path: '/',
            });
          });
        },
      },
    });

    await supabase.auth.getUser().catch(() => undefined);
  }

  for (const [key, value] of Object.entries(securityHeaders)) {
    response.headers.set(key, value);
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Apply to all routes except Next.js internal static/image assets and favicon.
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
