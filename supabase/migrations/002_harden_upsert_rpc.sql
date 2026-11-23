-- ============================================================
-- NMark Pass Vault v2 — Migration 002
-- Hardens `public.upsert_encrypted_vault` against:
-- 1. Concurrent first-time inserts (p_expected_revision = 0)
--    via per-user transaction advisory lock + ON CONFLICT DO NOTHING
--    returning atomic CONFLICT instead of 23505 unique_violation.
-- 2. Strict revision & envelope validation (p_expected_revision >= 0,
--    p_new_revision > p_expected_revision, v2 + aadVersion = 1).
-- 3. Conditional UPDATE with ROW_COUNT verification.
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
  v_inserted_uid uuid;
  v_updated_rows integer := 0;
  v_now timestamptz := now();
begin
  -- Gate 1: Authenticated user + Mandatory MFA (aal2)
  if v_uid is null or v_aal <> 'aal2' then
    raise exception 'MFA_REQUIRED' using errcode = '42501';
  end if;

  -- Gate 2: Strict revision and v2 envelope validation
  if p_expected_revision is null or p_expected_revision < 0 then
    raise exception 'INVALID_REVISION' using errcode = '22023';
  end if;

  if p_new_revision is null or p_new_revision <= p_expected_revision then
    raise exception 'INVALID_REVISION' using errcode = '22023';
  end if;

  if p_format_version <> 2 or p_aad_version <> 1 then
    raise exception 'INVALID_ENVELOPE' using errcode = '22023';
  end if;

  -- Serialize ALL concurrent writes (including first-time inserts where no row exists yet)
  -- for this user_id. Released automatically when the transaction commits or rolls back.
  perform pg_advisory_xact_lock(hashtextextended('nmark_vault:' || v_uid::text, 0));

  -- Lock existing row (if any)
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

    -- Defense-in-depth ON CONFLICT DO NOTHING handles any concurrent insert race cleanly
    insert into public.vaults (
      user_id, format_version, kdf_algorithm, kdf_memory, kdf_iterations,
      kdf_parallelism, kdf_salt, encryption_algorithm, encryption_iv,
      aad_version, ciphertext, revision, updated_by_device, created_at, updated_at
    ) values (
      v_uid, p_format_version, p_kdf_algorithm, p_kdf_memory, p_kdf_iterations,
      p_kdf_parallelism, p_kdf_salt, p_encryption_algorithm, p_encryption_iv,
      p_aad_version, p_ciphertext, p_new_revision, p_updated_by_device, v_now, v_now
    )
    on conflict (user_id) do nothing
    returning user_id into v_inserted_uid;

    if v_inserted_uid is not null then
      insert into public.vault_audit_log (user_id, event_type, revision, device_id)
      values (v_uid, 'vault_created', p_new_revision, p_updated_by_device);

      return jsonb_build_object(
        'status', 'OK',
        'revision', p_new_revision,
        'updatedAt', v_now
      );
    end if;

    -- Another concurrent first-time insert won the race: re-read and return atomic CONFLICT
    select * into v_existing
    from public.vaults
    where user_id = v_uid;

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

  -- Optimistic concurrency revision check on existing vault
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

  -- Conditional UPDATE enforces expected revision at the SQL predicate level too
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
  where user_id = v_uid
    and revision = p_expected_revision;

  get diagnostics v_updated_rows = row_count;

  if v_updated_rows <> 1 then
    select * into v_existing
    from public.vaults
    where user_id = v_uid;

    insert into public.vault_audit_log (user_id, event_type, revision, device_id)
    values (v_uid, 'vault_conflict', coalesce(v_existing.revision, 0), p_updated_by_device);

    return jsonb_build_object(
      'status', 'CONFLICT',
      'remoteRevision', coalesce(v_existing.revision, 0),
      'remoteVault', case
        when v_existing.user_id is null then null
        else jsonb_build_object(
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
      end
    );
  end if;

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
