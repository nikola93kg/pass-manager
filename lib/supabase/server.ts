// ============================================================
// SUPABASE SERVER CLIENT (@supabase/ssr)
// Uses ONLY the public anon key + user's HttpOnly session cookies
// so PostgreSQL RLS (owner + aal2) is enforced end-to-end.
// Never uses or exposes service_role credentials.
// ============================================================

import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { getPublicSupabaseConfig } from '@/lib/env';

export async function createSupabaseServerClient() {
  const config = getPublicSupabaseConfig();
  if (!config) {
    return null;
  }

  const cookieStore = await cookies();
  const isProd = process.env.NODE_ENV === 'production';

  return createServerClient(config.url, config.anonKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) => {
            cookieStore.set(name, value, {
              ...options,
              httpOnly: true,
              sameSite: 'lax',
              secure: isProd,
              path: '/',
            });
          });
        } catch {
          // Called from a Server Component where setting cookies is disallowed;
          // middleware refreshes sessions cleanly.
        }
      },
    },
  });
}
