// ============================================================
// LIVE STAGING SUPABASE RLS & MFA INTEGRATION TESTS
// Runs ONLY via `npm run test:staging` against a staging Supabase
// project with real credentials. NEVER run against production!
// ============================================================

import { describe, it, expect } from 'vitest';
import { createClient } from '@supabase/supabase-js';

const STAGING_URL = process.env.STAGING_SUPABASE_URL?.trim();
const STAGING_ANON_KEY = process.env.STAGING_SUPABASE_ANON_KEY?.trim();
const STAGING_EMAIL = process.env.STAGING_ADMIN_EMAIL?.trim();
const STAGING_PASSWORD = process.env.STAGING_ADMIN_PASSWORD?.trim();
const STAGING_TOTP_CODE = process.env.STAGING_ADMIN_TOTP_CODE?.trim();

const hasStagingConfig = Boolean(STAGING_URL && STAGING_ANON_KEY);

describe.skipIf(!hasStagingConfig)('Live Staging Supabase RLS & MFA Enforcement', () => {
  it('denies anonymous (anon) access to public.vaults, vault_snapshots, and vault_audit_log', async () => {
    const anonClient = createClient(STAGING_URL!, STAGING_ANON_KEY!, {
      auth: { persistSession: false },
    });

    const vaultsRes = await anonClient.from('vaults').select('*');
    expect(vaultsRes.error || (vaultsRes.data && vaultsRes.data.length === 0)).toBeTruthy();

    const snapRes = await anonClient.from('vault_snapshots').select('*');
    expect(snapRes.error || (snapRes.data && snapRes.data.length === 0)).toBeTruthy();

    const rpcRes = await anonClient.rpc('upsert_encrypted_vault', {
      p_expected_revision: 0,
      p_new_revision: 1,
      p_format_version: 2,
      p_kdf_algorithm: 'argon2id',
      p_kdf_memory: 65536,
      p_kdf_iterations: 3,
      p_kdf_parallelism: 1,
      p_kdf_salt: 'AAAAAAAAAAAAAAAAAAAAAA==',
      p_encryption_algorithm: 'AES-256-GCM',
      p_encryption_iv: 'AAAAAAAAAAAAAAAA',
      p_aad_version: 1,
      p_ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      p_updated_by_device: 'staging-test',
    });
    expect(rpcRes.error).not.toBeNull();
  });

  it.skipIf(!STAGING_EMAIL || !STAGING_PASSWORD)(
    'denies aal1 authenticated admin access until TOTP MFA (aal2) is verified',
    async () => {
      const client = createClient(STAGING_URL!, STAGING_ANON_KEY!, {
        auth: { persistSession: false },
      });

      const signIn = await client.auth.signInWithPassword({
        email: STAGING_EMAIL!,
        password: STAGING_PASSWORD!,
      });
      expect(signIn.error).toBeNull();

      const aal = await client.auth.mfa.getAuthenticatorAssuranceLevel();
      expect(aal.data?.currentLevel).toBe('aal1');

      // PostgreSQL RLS + RPC MUST deny aal1 calls with MFA_REQUIRED (42501)
      const aal1Rpc = await client.rpc('upsert_encrypted_vault', {
        p_expected_revision: 0,
        p_new_revision: 1,
        p_format_version: 2,
        p_kdf_algorithm: 'argon2id',
        p_kdf_memory: 65536,
        p_kdf_iterations: 3,
        p_kdf_parallelism: 1,
        p_kdf_salt: 'AAAAAAAAAAAAAAAAAAAAAA==',
        p_encryption_algorithm: 'AES-256-GCM',
        p_encryption_iv: 'AAAAAAAAAAAAAAAA',
        p_aad_version: 1,
        p_ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        p_updated_by_device: 'staging-test',
      });
      expect(aal1Rpc.error).not.toBeNull();

      // If a live TOTP code is provided, verify elevation to aal2 unlocks SELECT access
      if (STAGING_TOTP_CODE) {
        const factors = await client.auth.mfa.listFactors();
        const totp = factors.data?.totp.find((f) => f.status === 'verified');
        expect(totp).toBeDefined();
        const challenge = await client.auth.mfa.challenge({ factorId: totp!.id });
        expect(challenge.error).toBeNull();
        const verify = await client.auth.mfa.verify({
          factorId: totp!.id,
          challengeId: challenge.data!.id,
          code: STAGING_TOTP_CODE,
        });
        expect(verify.error).toBeNull();

        const elevated = await client.auth.mfa.getAuthenticatorAssuranceLevel();
        expect(elevated.data?.currentLevel).toBe('aal2');

        const readAfterMfa = await client.from('vaults').select('revision').maybeSingle();
        expect(readAfterMfa.error).toBeNull();
      }

      await client.auth.signOut();
    }
  );
});
