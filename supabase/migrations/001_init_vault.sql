-- ============================================================
-- NMark Pass Vault v2 — Supabase PostgreSQL Schema & RLS
--
-- Security Invariants:
-- 1. Zero-knowledge: ONLY encrypted ciphertext & public KDF/IV
--    metadata are stored. Plaintext credentials and master
--    passwords NEVER reach PostgreSQL.
-- 2. Strict RLS + FORCE ROW LEVEL SECURITY on all tables.
-- 3. All anonymous (`anon`) access is explicitly revoked.
-- 4. Every policy enforces BOTH:
--      - auth.uid() = user_id
--      - (auth.jwt() ->> 'aal') = 'aal2'  (Mandatory MFA at DB layer)
-- 5. Optimistic concurrency control via atomic `upsert_encrypted_vault`
--    RPC prevents stale devices from silently overwriting newer vaults.
-- ============================================================

-- 1. Encrypted Vault Table (1 row per authenticated admin user)
create table if not exists public.vaults (
  user_id uuid primary key references auth.users(id) on delete cascade,
  format_version smallint not null check (format_version in (1, 2)),
  kdf_algorithm text not null check (kdf_algorithm = 'argon2id'),
  kdf_memory integer not null check (kdf_memory between 16384 and 262144),
  kdf_iterations integer not null check (kdf_iterations between 1 and 20),
  kdf_parallelism smallint not null check (kdf_parallelism between 1 and 8),
  kdf_salt text not null check (char_length(kdf_salt) between 20 and 128),
  encryption_algorithm text not null check (encryption_algorithm = 'AES-256-GCM'),
  encryption_iv text not null check (char_length(encryption_iv) between 16 and 32),
  aad_version smallint not null default 1 check (aad_version in (0, 1)),
  ciphertext text not null check (char_length(ciphertext) between 20 and 6000000),
  revision bigint not null default 1 check (revision >= 0),
  updated_by_device text check (updated_by_device is null or char_length(updated_by_device) <= 128),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

comment on table public.vaults is
  'Zero-knowledge encrypted vault envelopes. Never stores plaintext credentials or master passwords.';

-- 2. Encrypted Recovery Snapshots Table (bounded backup points)
create table if not exists public.vault_snapshots (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  reason text not null check (reason in ('import', 'password_change', 'cloud_migration', 'reset', 'v1_migration', 'manual', 'conflict')),
  format_version smallint not null check (format_version in (1, 2)),
  revision bigint not null check (revision >= 0),
  envelope jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_vault_snapshots_user_created
  on public.vault_snapshots (user_id, created_at desc);

-- 3. Metadata-Only Audit Log (never stores secrets, passwords, or usernames)
create table if not exists public.vault_audit_log (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  event_type text not null check (event_type in ('vault_created', 'vault_updated', 'vault_conflict', 'snapshot_created')),
  revision bigint not null check (revision >= 0),
  device_id text check (device_id is null or char_length(device_id) <= 128),
  created_at timestamptz not null default now()
);

create index if not exists idx_vault_audit_log_user_created
  on public.vault_audit_log (user_id, created_at desc);

-- ============================================================
-- Revoke ALL privileges from anon & public roles
-- ============================================================
revoke all on table public.vaults from anon, public;
revoke all on table public.vault_snapshots from anon, public;
revoke all on table public.vault_audit_log from anon, public;

grant select, insert, update on table public.vaults to authenticated;
grant select, insert, delete on table public.vault_snapshots to authenticated;
grant select, insert on table public.vault_audit_log to authenticated;

-- ============================================================
-- Enable & FORCE Row Level Security (RLS)
-- ============================================================
alter table public.vaults enable row level security;
alter table public.vaults force row level security;

alter table public.vault_snapshots enable row level security;
alter table public.vault_snapshots force row level security;

alter table public.vault_audit_log enable row level security;
alter table public.vault_audit_log force row level security;

-- Helper check: authenticated owner AND MFA aal2 verified
drop policy if exists "vaults_select_owner_aal2" on public.vaults;
create policy "vaults_select_owner_aal2"
  on public.vaults
  for select
  to authenticated
  using (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

drop policy if exists "vaults_insert_owner_aal2" on public.vaults;
create policy "vaults_insert_owner_aal2"
  on public.vaults
  for insert
  to authenticated
  with check (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

drop policy if exists "vaults_update_owner_aal2" on public.vaults;
create policy "vaults_update_owner_aal2"
  on public.vaults
  for update
  to authenticated
  using (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  )
  with check (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

-- Snapshots RLS (owner + aal2)
drop policy if exists "snapshots_select_owner_aal2" on public.vault_snapshots;
create policy "snapshots_select_owner_aal2"
  on public.vault_snapshots
  for select
  to authenticated
  using (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

drop policy if exists "snapshots_insert_owner_aal2" on public.vault_snapshots;
create policy "snapshots_insert_owner_aal2"
  on public.vault_snapshots
  for insert
  to authenticated
  with check (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

drop policy if exists "snapshots_delete_owner_aal2" on public.vault_snapshots;
create policy "snapshots_delete_owner_aal2"
  on public.vault_snapshots
  for delete
  to authenticated
  using (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

-- Audit log RLS (append-only for owner + aal2; no update/delete granted)
drop policy if exists "audit_select_owner_aal2" on public.vault_audit_log;
create policy "audit_select_owner_aal2"
  on public.vault_audit_log
  for select
  to authenticated
  using (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

drop policy if exists "audit_insert_owner_aal2" on public.vault_audit_log;
create policy "audit_insert_owner_aal2"
  on public.vault_audit_log
  for insert
  to authenticated
  with check (
    auth.uid() = user_id
    and (auth.jwt() ->> 'aal') = 'aal2'
  );

-- ============================================================
-- Atomic Optimistic-Concurrency Upsert RPC (SECURITY INVOKER)
-- Runs with caller's JWT so RLS (owner + aal2) is fully enforced.
-- Prevents stale devices from overwriting newer encrypted vaults.
-- ============================================================
create or replace function public.upsert_encrypted_vault(
  p_expected_revision bigint,
  p_new_revision bigint,
  p_format_version smallint,
  p_kdf_algorithm text,
  p_kdf_memory integer,
  p_kdf_iterations integer,
  p_kdf_parallelism smallint,
  p_kdf_salt text,
  p_encryption_algorithm text,
  p_encryption_iv text,
  p_aad_version smallint,
  p_ciphertext text,
  p_updated_by_device text default null
)
returns jsonb
language plpgsql
security invoker
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_aal text := coalesce(auth.jwt() ->> 'aal', '');
  v_existing public.vaults%rowtype;
  v_now timestamptz := now();
begin
  if v_uid is null or v_aal <> 'aal2' then
    raise exception 'MFA_REQUIRED' using errcode = '42501';
  end if;

  if p_new_revision <= p_expected_revision then
    raise exception 'INVALID_REVISION' using errcode = '22023';
  end if;

  -- Lock existing row (if any) for this user
  select * into v_existing
  from public.vaults
  where user_id = v_uid
  for update;

  if not found then
    if p_expected_revision <> 0 then
      return jsonb_build_object(
        'status', 'CONFLICT',
        'remoteRevision', 0,
        'remoteVault', null
      );
    end if;

    insert into public.vaults (
      user_id, format_version, kdf_algorithm, kdf_memory, kdf_iterations,
      kdf_parallelism, kdf_salt, encryption_algorithm, encryption_iv,
      aad_version, ciphertext, revision, updated_by_device, created_at, updated_at
    ) values (
      v_uid, p_format_version, p_kdf_algorithm, p_kdf_memory, p_kdf_iterations,
      p_kdf_parallelism, p_kdf_salt, p_encryption_algorithm, p_encryption_iv,
      p_aad_version, p_ciphertext, p_new_revision, p_updated_by_device, v_now, v_now
    );

    insert into public.vault_audit_log (user_id, event_type, revision, device_id)
    values (v_uid, 'vault_created', p_new_revision, p_updated_by_device);

    return jsonb_build_object(
      'status', 'OK',
      'revision', p_new_revision,
      'updatedAt', v_now
    );
  end if;

  -- Check optimistic concurrency revision
  if v_existing.revision <> p_expected_revision then
    insert into public.vault_audit_log (user_id, event_type, revision, device_id)
    values (v_uid, 'vault_conflict', v_existing.revision, p_updated_by_device);

    return jsonb_build_object(
      'status', 'CONFLICT',
      'remoteRevision', v_existing.revision,
      'remoteVault', jsonb_build_object(
        'version', v_existing.format_version,
        'revision', v_existing.revision,
        'updatedAt', v_existing.updated_at,
        'updatedByDevice', v_existing.updated_by_device,
        'kdf', jsonb_build_object(
          'algorithm', v_existing.kdf_algorithm,
          'memory', v_existing.kdf_memory,
          'iterations', v_existing.kdf_iterations,
          'parallelism', v_existing.kdf_parallelism,
          'salt', v_existing.kdf_salt
        ),
        'encryption', jsonb_build_object(
          'algorithm', v_existing.encryption_algorithm,
          'iv', v_existing.encryption_iv,
          'aadVersion', v_existing.aad_version
        ),
        'ciphertext', v_existing.ciphertext
      )
    );
  end if;

  update public.vaults
  set
    format_version = p_format_version,
    kdf_algorithm = p_kdf_algorithm,
    kdf_memory = p_kdf_memory,
    kdf_iterations = p_kdf_iterations,
    kdf_parallelism = p_kdf_parallelism,
    kdf_salt = p_kdf_salt,
    encryption_algorithm = p_encryption_algorithm,
    encryption_iv = p_encryption_iv,
    aad_version = p_aad_version,
    ciphertext = p_ciphertext,
    revision = p_new_revision,
    updated_by_device = p_updated_by_device,
    updated_at = v_now
  where user_id = v_uid;

  insert into public.vault_audit_log (user_id, event_type, revision, device_id)
  values (v_uid, 'vault_updated', p_new_revision, p_updated_by_device);

  return jsonb_build_object(
    'status', 'OK',
    'revision', p_new_revision,
    'updatedAt', v_now
  );
end;
$$;

revoke all on function public.upsert_encrypted_vault(
  bigint, bigint, smallint, text, integer, integer, smallint, text, text, text, smallint, text, text
) from anon, public;

grant execute on function public.upsert_encrypted_vault(
  bigint, bigint, smallint, text, integer, integer, smallint, text, text, text, smallint, text, text
) to authenticated;
