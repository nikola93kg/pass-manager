// ============================================================
// /api/vault — Encrypted Vault Cloud Sync Endpoint
// - Strictly enforces: Auth + Single-Admin Allowlist + MFA (aal2)
// - Stores and returns ONLY encrypted vault envelopes (zero plaintext)
// - Optimistic concurrency control via atomic PostgreSQL RPC (409 on stale revision)
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
import { validateBlobStructure } from '@/lib/crypto';
import type { EncryptedVaultBlobV2 } from '@/lib/types';

export const dynamic = 'force-dynamic';
const NO_STORE = { 'Cache-Control': 'no-store' };

const PutVaultSchema = z.object({
  expectedRevision: z.number().int().min(0),
  blob: z.unknown(),
});

interface VaultRow {
  format_version: number;
  kdf_algorithm: 'argon2id';
  kdf_memory: number;
  kdf_iterations: number;
  kdf_parallelism: number;
  kdf_salt: string;
  encryption_algorithm: 'AES-256-GCM';
  encryption_iv: string;
  aad_version: number;
  ciphertext: string;
  revision: number;
  updated_by_device: string | null;
  updated_at: string;
}

function rowToBlobV2(row: VaultRow): EncryptedVaultBlobV2 {
  return {
    version: 2,
    revision: Number(row.revision),
    updatedAt: row.updated_at,
    ...(row.updated_by_device ? { updatedByDevice: row.updated_by_device } : {}),
    kdf: {
      algorithm: row.kdf_algorithm,
      memory: row.kdf_memory,
      iterations: row.kdf_iterations,
      parallelism: row.kdf_parallelism,
      salt: row.kdf_salt,
    },
    encryption: {
      algorithm: row.encryption_algorithm,
      iv: row.encryption_iv,
      aadVersion: 1,
    },
    ciphertext: row.ciphertext,
  };
}

export async function GET(request: Request) {
  const ip = getClientIpFromHeaders(request.headers);
  const rl = checkRateLimit(`vault:read:${ip}`, RATE_LIMIT_TIERS.vaultRead);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Rate limit exceeded.' },
      { status: 429, headers: NO_STORE }
    );
  }

  const supabase = await createSupabaseServerClient();
  const authz = await authorizeVaultAccess(supabase, { requireMfa: true });
  if (!authz.authorized || !supabase) {
    return NextResponse.json(
      { error: authz.authorized ? 'Unavailable.' : authz.error, code: authz.authorized ? undefined : authz.code },
      { status: authz.authorized ? 503 : authz.status, headers: NO_STORE }
    );
  }

  const { data, error } = await supabase
    .from('vaults')
    .select(
      'format_version, kdf_algorithm, kdf_memory, kdf_iterations, kdf_parallelism, kdf_salt, encryption_algorithm, encryption_iv, aad_version, ciphertext, revision, updated_by_device, updated_at'
    )
    .eq('user_id', authz.user.id)
    .maybeSingle();

  if (error) {
    return NextResponse.json(
      { error: 'Failed to retrieve encrypted vault.' },
      { status: 500, headers: NO_STORE }
    );
  }

  if (!data) {
    return NextResponse.json(
      { exists: false, blob: null, revision: 0, updatedAt: null },
      { headers: NO_STORE }
    );
  }

  const blob = rowToBlobV2(data as VaultRow);
  return NextResponse.json(
    {
      exists: true,
      blob,
      revision: blob.revision,
      updatedAt: blob.updatedAt,
    },
    { headers: NO_STORE }
  );
}

export async function PUT(request: Request) {
  const csrf = verifySameOriginRequest(request);
  if (!csrf.ok) {
    return NextResponse.json({ error: csrf.reason }, { status: 403, headers: NO_STORE });
  }

  const ip = getClientIpFromHeaders(request.headers);
  const rl = checkRateLimit(`vault:write:${ip}`, RATE_LIMIT_TIERS.vaultWrite);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: 'Rate limit exceeded.' },
      { status: 429, headers: NO_STORE }
    );
  }

  const supabase = await createSupabaseServerClient();
  const authz = await authorizeVaultAccess(supabase, { requireMfa: true });
  if (!authz.authorized || !supabase) {
    return NextResponse.json(
      { error: authz.authorized ? 'Unavailable.' : authz.error, code: authz.authorized ? undefined : authz.code },
      { status: authz.authorized ? 503 : authz.status, headers: NO_STORE }
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON payload.' }, { status: 400, headers: NO_STORE });
  }

  const parsed = PutVaultSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Invalid sync payload.' },
      { status: 400, headers: NO_STORE }
    );
  }

  if (!validateBlobStructure(parsed.data.blob) || parsed.data.blob.version !== 2) {
    return NextResponse.json(
      { error: 'Encrypted vault blob failed v2 format or cryptographic parameter validation.' },
      { status: 400, headers: NO_STORE }
    );
  }

  const blob: EncryptedVaultBlobV2 = parsed.data.blob;
  if (blob.revision <= parsed.data.expectedRevision) {
    return NextResponse.json(
      { error: 'New revision must be strictly greater than expectedRevision.' },
      { status: 400, headers: NO_STORE }
    );
  }

  const { data: rpcData, error: rpcError } = await supabase.rpc('upsert_encrypted_vault', {
    p_expected_revision: parsed.data.expectedRevision,
    p_new_revision: blob.revision,
    p_format_version: blob.version,
    p_kdf_algorithm: blob.kdf.algorithm,
    p_kdf_memory: blob.kdf.memory,
    p_kdf_iterations: blob.kdf.iterations,
    p_kdf_parallelism: blob.kdf.parallelism,
    p_kdf_salt: blob.kdf.salt,
    p_encryption_algorithm: blob.encryption.algorithm,
    p_encryption_iv: blob.encryption.iv,
    p_aad_version: blob.encryption.aadVersion,
    p_ciphertext: blob.ciphertext,
    p_updated_by_device: blob.updatedByDevice ?? null,
  });

  if (rpcError || !rpcData) {
    return NextResponse.json(
      { error: 'Failed to store encrypted vault.' },
      { status: 500, headers: NO_STORE }
    );
  }

  const result = rpcData as {
    status: 'OK' | 'CONFLICT';
    revision?: number;
    updatedAt?: string;
    remoteRevision?: number;
    remoteVault?: EncryptedVaultBlobV2 | null;
  };

  if (result.status === 'CONFLICT') {
    return NextResponse.json(
      {
        error: 'Sync conflict: remote vault has a newer revision.',
        remoteRevision: result.remoteRevision ?? 0,
        remoteBlob: result.remoteVault ?? null,
      },
      { status: 409, headers: NO_STORE }
    );
  }

  return NextResponse.json(
    {
      revision: result.revision ?? blob.revision,
      updatedAt: result.updatedAt ?? blob.updatedAt,
    },
    { headers: NO_STORE }
  );
}
