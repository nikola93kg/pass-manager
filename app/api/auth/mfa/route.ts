// ============================================================
// /api/auth/mfa — Mandatory TOTP MFA Enrollment & Verification
// Elevates an authenticated single-admin session from aal1 -> aal2.
// ============================================================

import { NextResponse } from 'next/server';
import { z } from 'zod';
import { createSupabaseServerClient } from '@/lib/supabase/server';
import { authorizeVaultAccess } from '@/lib/auth/guard';
import {
  checkRateLimit,
  getClientIpFromHeaders,
  RATE_LIMIT_TIERS,
} from '@/lib/security/rateLimit';
import { verifySameOriginRequest } from '@/lib/security/csrf';
import { isSafeQrDataUri } from '@/lib/urlSafety';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' };

const MfaActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('enroll'),
    friendlyName: z.string().trim().min(1).max(64).optional(),
  }),
  z.object({
    action: z.literal('verify'),
    factorId: z.string().trim().min(1).max(128).optional(),
    code: z.string().trim().regex(/^\d{6}$/, 'Enter a 6-digit authenticator code.'),
  }),
]);

export async function POST(request: Request) {
  const csrf = verifySameOriginRequest(request);
  if (!csrf.ok) {
    return NextResponse.json({ error: csrf.reason }, { status: 403, headers: NO_STORE });
  }

  const ip = getClientIpFromHeaders(request.headers);
  const rl = checkRateLimit(`auth:mfa:${ip}`, RATE_LIMIT_TIERS.mfa);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Too many MFA attempts. Please wait and try again.' },
      { status: 429, headers: NO_STORE }
    );
  }

  const supabase = await createSupabaseServerClient();
  // Require authenticated + allowlisted admin, without requiring aal2 yet
  const authz = await authorizeVaultAccess(supabase, { requireMfa: false });
  if (!authz.authorized || !supabase) {
    return NextResponse.json(
      { error: authz.authorized ? 'Unavailable.' : authz.error },
      { status: authz.authorized ? 503 : authz.status, headers: NO_STORE }
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400, headers: NO_STORE });
  }

  const parsed = MfaActionSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message || 'Invalid MFA request.' },
      { status: 400, headers: NO_STORE }
    );
  }

  if (parsed.data.action === 'enroll') {
    // Clean up any stale unverified TOTP factors so enrollment stays tidy
    const { data: factors } = await supabase.auth.mfa.listFactors();
    const unverified = (factors?.totp ?? []).filter((f) => f.status !== 'verified');
    for (const f of unverified) {
      await supabase.auth.mfa.unenroll({ factorId: f.id }).catch(() => undefined);
    }

    const { data, error } = await supabase.auth.mfa.enroll({
      factorType: 'totp',
      issuer: 'NMark Pass Vault',
      friendlyName: parsed.data.friendlyName ?? 'Admin Authenticator',
    });

    if (error || !data || data.type !== 'totp') {
      return NextResponse.json(
        { error: 'Failed to start TOTP enrollment.' },
        { status: 400, headers: NO_STORE }
      );
    }

    return NextResponse.json(
      {
        factorId: data.id,
        qrCode: isSafeQrDataUri(data.totp.qr_code) ? data.totp.qr_code : null,
        secret: data.totp.secret,
      },
      { headers: NO_STORE }
    );
  }

  // Verify TOTP code (for either enrollment confirmation or login challenge)
  let factorId = parsed.data.factorId;
  if (!factorId) {
    const { data: factors, error: listErr } = await supabase.auth.mfa.listFactors();
    if (listErr || !factors) {
      return NextResponse.json(
        { error: 'Unable to load MFA factors.' },
        { status: 400, headers: NO_STORE }
      );
    }
    const verifiedTotp = factors.totp.find((f) => f.status === 'verified');
    if (!verifiedTotp) {
      return NextResponse.json(
        { error: 'No verified TOTP factor found. Please enroll first.' },
        { status: 400, headers: NO_STORE }
      );
    }
    factorId = verifiedTotp.id;
  }

  const { data: challenge, error: challengeErr } = await supabase.auth.mfa.challenge({
    factorId,
  });
  if (challengeErr || !challenge) {
    return NextResponse.json(
      { error: 'Failed to initiate MFA challenge.' },
      { status: 400, headers: NO_STORE }
    );
  }

  const { error: verifyErr } = await supabase.auth.mfa.verify({
    factorId,
    challengeId: challenge.id,
    code: parsed.data.code,
  });

  if (verifyErr) {
    return NextResponse.json(
      { error: 'Invalid or expired authenticator code.' },
      { status: 401, headers: NO_STORE }
    );
  }

  return NextResponse.json({ verified: true, aal: 'aal2' }, { headers: NO_STORE });
}
