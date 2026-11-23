// ============================================================
// /api/vault/snapshots — Encrypted Cloud Recovery Snapshots
// Stores ONLY validated encrypted vault blobs, gated by Auth + Admin + aal2.
// ============================================================

import { NextResponse } from 'next/server';
import { z } from 'zod';
import { createSupabaseServerClient } from '@/lib/supabase/server';
import { authorizeVaultAccess } from '@/lib/auth/guard';
import {
  enforceRateLimit,
  getClientIpFromHeaders,
  RATE_LIMIT_TIERS,
} from '@/lib/security/rateLimit';
import { verifySameOriginRequest } from '@/lib/security/csrf';
import { validateBlobStructure, getBlobRevision } from '@/lib/crypto';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' };

const SnapshotSchema = z.object({
  reason: z.enum([
    'import',
    'password_change',
    'cloud_migration',
    'reset',
    'v1_migration',
    'manual',
    'conflict',
  ]),
  blob: z.unknown(),
});

export async function GET(request: Request) {
  const ip = getClientIpFromHeaders(request.headers);
  const ipRl = await enforceRateLimit(`vault:read:ip:${ip}`, RATE_LIMIT_TIERS.vaultRead);
  if (!ipRl.allowed) {
    return NextResponse.json({ error: 'Rate limit exceeded.' }, { status: 429, headers: NO_STORE });
  }

  const supabase = await createSupabaseServerClient();
  const authz = await authorizeVaultAccess(supabase, { requireMfa: true });
  if (!authz.authorized || !supabase) {
    return NextResponse.json(
      { error: authz.authorized ? 'Unavailable.' : authz.error },
      { status: authz.authorized ? 503 : authz.status, headers: NO_STORE }
    );
  }

  const userRl = await enforceRateLimit(
    `vault:read:user:${authz.user.id}`,
    RATE_LIMIT_TIERS.vaultRead
  );
  if (!userRl.allowed) {
    return NextResponse.json({ error: 'Rate limit exceeded.' }, { status: 429, headers: NO_STORE });
  }

  const { data, error } = await supabase
    .from('vault_snapshots')
    .select('id, reason, format_version, revision, envelope, created_at')
    .eq('user_id', authz.user.id)
    .order('created_at', { ascending: false })
    .limit(10);

  if (error) {
    return NextResponse.json(
      { error: 'Failed to load recovery snapshots.' },
      { status: 500, headers: NO_STORE }
    );
  }

  return NextResponse.json({ snapshots: data ?? [] }, { headers: NO_STORE });
}

export async function POST(request: Request) {
  const csrf = verifySameOriginRequest(request);
  if (!csrf.ok) {
    return NextResponse.json({ error: csrf.reason }, { status: 403, headers: NO_STORE });
  }

  const ip = getClientIpFromHeaders(request.headers);
  const ipRl = await enforceRateLimit(`vault:write:ip:${ip}`, RATE_LIMIT_TIERS.vaultWrite);
  if (!ipRl.allowed) {
    return NextResponse.json({ error: 'Rate limit exceeded.' }, { status: 429, headers: NO_STORE });
  }

  const supabase = await createSupabaseServerClient();
  const authz = await authorizeVaultAccess(supabase, { requireMfa: true });
  if (!authz.authorized || !supabase) {
    return NextResponse.json(
      { error: authz.authorized ? 'Unavailable.' : authz.error },
      { status: authz.authorized ? 503 : authz.status, headers: NO_STORE }
    );
  }

  const userRl = await enforceRateLimit(
    `vault:write:user:${authz.user.id}`,
    RATE_LIMIT_TIERS.vaultWrite
  );
  if (!userRl.allowed) {
    return NextResponse.json({ error: 'Rate limit exceeded.' }, { status: 429, headers: NO_STORE });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.' }, { status: 400, headers: NO_STORE });
  }

  const parsed = SnapshotSchema.safeParse(body);
  if (!parsed.success || !validateBlobStructure(parsed.data.blob)) {
    return NextResponse.json(
      { error: 'Invalid encrypted snapshot payload.' },
      { status: 400, headers: NO_STORE }
    );
  }

  const blob = parsed.data.blob;
  const { error } = await supabase.from('vault_snapshots').insert({
    user_id: authz.user.id,
    reason: parsed.data.reason,
    format_version: blob.version,
    revision: getBlobRevision(blob),
    envelope: blob,
  });

  if (error) {
    return NextResponse.json(
      { error: 'Failed to store recovery snapshot.' },
      { status: 500, headers: NO_STORE }
    );
  }

  return NextResponse.json({ saved: true }, { status: 201, headers: NO_STORE });
}
