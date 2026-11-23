// ============================================================
// /api/auth/session
// GET  — Return current authentication & MFA assurance state.
//        Fails closed (503) in production if cloud auth is
//        unconfigured unless ALLOW_LOCAL_ONLY_MODE=true.
// POST — Single-admin email/password sign-in (NO public sign-up),
//        protected by distributed IP + account-hash rate limiting.
// ============================================================

import { NextResponse } from 'next/server';
import { z } from 'zod';
import { createSupabaseServerClient } from '@/lib/supabase/server';
import {
  isCloudSyncConfigured,
  isLocalOnlyModeAllowed,
  isUserAllowedAdmin,
} from '@/lib/env';
import {
  enforceRateLimit,
  getClientIpFromHeaders,
  hashRateLimitKey,
  RATE_LIMIT_TIERS,
} from '@/lib/security/rateLimit';
import { verifySameOriginRequest } from '@/lib/security/csrf';
import type { AuthSessionState } from '@/lib/types';

export const dynamic = 'force-dynamic';

const SignInSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(256),
});

const NO_STORE = { 'Cache-Control': 'no-store' };

export async function GET() {
  if (!isCloudSyncConfigured()) {
    if (isLocalOnlyModeAllowed()) {
      const localState: AuthSessionState = {
        mode: 'local',
        step: 'local_only',
        userEmail: null,
        userId: null,
        aal: null,
        hasTotpFactor: false,
      };
      return NextResponse.json(localState, { headers: NO_STORE });
    }

    // Fail closed in production when cloud auth is not configured and local-only is not explicitly opted in
    return NextResponse.json(
      {
        error:
          'Cloud authentication is required in production but Supabase is not configured.',
        code: 'CLOUD_AUTH_MISCONFIGURED',
      },
      { status: 503, headers: NO_STORE }
    );
  }

  const supabase = await createSupabaseServerClient();
  if (!supabase) {
    return NextResponse.json(
      { error: 'Cloud authentication unavailable.' },
      { status: 503, headers: NO_STORE }
    );
  }

  const { data: userData, error: userErr } = await supabase.auth.getUser();
  if (userErr || !userData.user) {
    const state: AuthSessionState = {
      mode: 'cloud',
      step: 'sign_in',
      userEmail: null,
      userId: null,
      aal: null,
      hasTotpFactor: false,
    };
    return NextResponse.json(state, { headers: NO_STORE });
  }

  const user = userData.user;
  if (!isUserAllowedAdmin({ id: user.id, email: user.email })) {
    await supabase.auth.signOut();
    const state: AuthSessionState = {
      mode: 'cloud',
      step: 'forbidden',
      userEmail: null,
      userId: null,
      aal: null,
      hasTotpFactor: false,
    };
    return NextResponse.json(state, { status: 403, headers: NO_STORE });
  }

  const [{ data: aalData }, { data: factorsData }] = await Promise.all([
    supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
    supabase.auth.mfa.listFactors(),
  ]);

  const verifiedTotp = (factorsData?.totp ?? []).filter((f) => f.status === 'verified');
  const hasTotpFactor = verifiedTotp.length > 0;
  const currentAal = (aalData?.currentLevel as 'aal1' | 'aal2' | null) ?? null;

  let step: AuthSessionState['step'];
  if (currentAal === 'aal2') {
    step = 'authenticated';
  } else if (hasTotpFactor) {
    step = 'mfa_challenge';
  } else {
    step = 'mfa_enroll';
  }

  const state: AuthSessionState = {
    mode: 'cloud',
    step,
    userEmail: user.email ?? null,
    userId: user.id,
    aal: currentAal,
    hasTotpFactor,
  };

  return NextResponse.json(state, { headers: NO_STORE });
}

export async function POST(request: Request) {
  const csrf = verifySameOriginRequest(request);
  if (!csrf.ok) {
    return NextResponse.json({ error: csrf.reason }, { status: 403, headers: NO_STORE });
  }

  if (!isCloudSyncConfigured()) {
    return NextResponse.json(
      { error: 'Cloud authentication is not configured.' },
      { status: 503, headers: NO_STORE }
    );
  }

  const ip = getClientIpFromHeaders(request.headers);
  const ipLimit = await enforceRateLimit(`auth:signin:ip:${ip}`, RATE_LIMIT_TIERS.auth);
  if (!ipLimit.allowed) {
    return NextResponse.json(
      { error: 'Too many authentication attempts. Please try again later.' },
      { status: 429, headers: NO_STORE }
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400, headers: NO_STORE });
  }

  const parsed = SignInSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Please provide a valid email and password.' },
      { status: 400, headers: NO_STORE }
    );
  }

  // Secondary account-hashed rate limit prevents IP-rotation brute force against the admin email
  const emailHash = await hashRateLimitKey(parsed.data.email);
  const acctLimit = await enforceRateLimit(
    `auth:signin:acct:${emailHash}`,
    RATE_LIMIT_TIERS.auth
  );
  if (!acctLimit.allowed) {
    return NextResponse.json(
      { error: 'Too many authentication attempts. Please try again later.' },
      { status: 429, headers: NO_STORE }
    );
  }

  const supabase = await createSupabaseServerClient();
  if (!supabase) {
    return NextResponse.json(
      { error: 'Cloud authentication unavailable.' },
      { status: 503, headers: NO_STORE }
    );
  }

  const { data, error } = await supabase.auth.signInWithPassword({
    email: parsed.data.email,
    password: parsed.data.password,
  });

  if (error || !data.user) {
    return NextResponse.json(
      { error: 'Invalid credentials or access denied.' },
      { status: 401, headers: NO_STORE }
    );
  }

  if (!isUserAllowedAdmin({ id: data.user.id, email: data.user.email })) {
    await supabase.auth.signOut();
    return NextResponse.json(
      { error: 'Invalid credentials or access denied.' },
      { status: 403, headers: NO_STORE }
    );
  }

  const [{ data: aalData }, { data: factorsData }] = await Promise.all([
    supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
    supabase.auth.mfa.listFactors(),
  ]);

  const hasTotpFactor = (factorsData?.totp ?? []).some((f) => f.status === 'verified');
  const currentAal = (aalData?.currentLevel as 'aal1' | 'aal2' | null) ?? 'aal1';

  const state: AuthSessionState = {
    mode: 'cloud',
    step: currentAal === 'aal2' ? 'authenticated' : hasTotpFactor ? 'mfa_challenge' : 'mfa_enroll',
    userEmail: data.user.email ?? null,
    userId: data.user.id,
    aal: currentAal,
    hasTotpFactor,
  };

  return NextResponse.json(state, { headers: NO_STORE });
}
