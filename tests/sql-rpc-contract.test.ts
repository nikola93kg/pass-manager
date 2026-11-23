import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

describe('Finding 3 Regression — PostgreSQL Schema, RLS & Atomic Concurrent Insert RPC Contract', () => {
  const migration001 = readFileSync(
    path.resolve(process.cwd(), 'supabase/migrations/001_init_vault.sql'),
    'utf8'
  );
  const migration002 = readFileSync(
    path.resolve(process.cwd(), 'supabase/migrations/002_harden_upsert_rpc.sql'),
    'utf8'
  );

  it('enforces FORCE ROW LEVEL SECURITY, owner+aal2 policies, and revoked anon grants in migration 001', () => {
    expect(migration001).toContain('revoke all on table public.vaults from anon, public');
    expect(migration001).toContain('alter table public.vaults force row level security');
    expect(migration001).toContain('alter table public.vault_snapshots force row level security');
    expect(migration001).toContain('alter table public.vault_audit_log force row level security');
    expect(migration001).toContain("and (auth.jwt() ->> 'aal') = 'aal2'");
  });

  it('hardens upsert_encrypted_vault against concurrent initial inserts and invalid revisions in migration 002', () => {
    // Per-user transaction advisory lock serializes first-time inserts before any row exists
    expect(migration002).toContain('pg_advisory_xact_lock');
    // ON CONFLICT DO NOTHING avoids unhandled 23505 unique_violation on concurrent initial inserts
    expect(migration002).toContain('on conflict (user_id) do nothing');
    // Strict non-negative expectedRevision & v2 envelope checks
    expect(migration002).toContain('p_expected_revision < 0');
    expect(migration002).toContain('p_new_revision <= p_expected_revision');
    expect(migration002).toContain('p_format_version <> 2 or p_aad_version <> 1');
    // Conditional UPDATE predicate + ROW_COUNT check
    expect(migration002).toContain('and revision = p_expected_revision');
    expect(migration002).toContain('get diagnostics v_updated_rows = row_count');
    // Runs SECURITY INVOKER with anon execution revoked
    expect(migration002).toContain('security invoker');
    expect(migration002).toContain('from anon, public');
  });
});
