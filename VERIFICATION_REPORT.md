# Final Verification Report — NMark Pass Vault v2 (Security Follow-Up)

**Date:** 2026-11-23  
**Target Domain:** `https://vault.nmarkdesigns.com`

---

## 1. Automated Verification Summary

| Check | Command | Test Type | Result | Details |
|---|---|---|---|---|
| TypeScript | `npm run typecheck` | Static Analysis | **PASS** | `tsc --noEmit` exited with code 0 (0 errors) |
| Linting | `npm run lint` | Static Analysis | **PASS** | `next lint` exited with code 0 (`✔ No ESLint warnings or errors`) |
| Unit / Component / Route Regression Suite | `npm test` | **Mocked** (`argon2-browser` & network/Supabase mocks; real Node WebCrypto AES-256-GCM + SHA-256) | **PASS** | **10 test files, 53 / 53 tests passed** (Vitest 5.1.1) |
| Live Staging Supabase RLS & MFA Suite | `npm run test:staging` | **Real Integration** (no mocks) | **SKIPPED (2/2)** | Skipped cleanly because `STAGING_SUPABASE_URL` / `STAGING_SUPABASE_ANON_KEY` are not provisioned in this environment |
| Production Build | `npm run build` | Build Verification | **PASS** | Next.js `15.5.29` compiled all routes, APIs, `/item/[id]`, `/robots.txt`, and `middleware.ts` |

---

## 2. Automated Test Coverage Matrix (Mocked Suite — `npm test`, 53/53 Passed)

> **Important Distinction:** Tests under `npm test` execute real Web Crypto (`AES-256-GCM`, `SHA-256`, `crypto.getRandomValues`, `crypto.randomUUID`), real React/DOM flows, and real Next.js Route Handler logic, while mocking `argon2-browser` WASM, `fetch`, and the Supabase client factory. They do **not** hit a live PostgreSQL instance or live Upstash Redis server.

| Test Suite | Tests | Verified Behavior |
|---|---|---|
| [`tests/cloud-fail-closed.test.tsx`](./tests/cloud-fail-closed.test.tsx) | 4 | Network error and HTTP `503`/`500` on `/api/auth/session` fail closed with Retry screen (never fall open to local-only); explicit `200 local_only` preserved; server `GET /api/auth/session` returns `503` in production when Supabase is unconfigured unless `ALLOW_LOCAL_ONLY_MODE=true` |
| [`tests/sync-integrity.test.tsx`](./tests/sync-integrity.test.tsx) | 5 | Equal-revision diverged ciphertext (`localRev === cloudRev`, different fingerprint) flagged as conflict without overwriting localStorage; unsynced local changes preserved even when `cloudRev > localRev`; local-ahead conflict detected; clean fast-forward allowed only when local matches `lastSyncedFingerprint`; end-to-end `VaultApp` → `UnlockPage` → `ConflictModal` local preservation & monotonic conflict resolution |
| [`tests/rate-limit-and-proxy.test.ts`](./tests/rate-limit-and-proxy.test.ts) | 7 | Default `TRUSTED_PROXY_PROVIDER=none` ignores spoofed `X-Forwarded-For`/`X-Real-Ip`; `cloudflare` trusts only `cf-connecting-ip`; `vercel` trusts `x-vercel-forwarded-for`; `custom` uses rightmost trusted hop count; Upstash Redis REST pipeline rate limits & blocks above threshold; auth/MFA tiers fail closed (`redis_error_closed`) on Redis outage; deterministic SHA-256 account key hashing |
| [`tests/sql-rpc-contract.test.ts`](./tests/sql-rpc-contract.test.ts) | 2 | Static contract checks on `001_init_vault.sql` & `002_harden_upsert_rpc.sql`: `FORCE ROW LEVEL SECURITY`, `aal2` policies, revoked `anon` grants, `pg_advisory_xact_lock`, `ON CONFLICT (user_id) DO NOTHING`, `p_expected_revision < 0`, v2 envelope enforcement, and conditional `UPDATE` `ROW_COUNT` check |
| [`tests/crypto.test.ts`](./tests/crypto.test.ts) | 8 | v2 AES-256-GCM + AAD round trips, wrong password, tampered ciphertext, tampered envelope metadata, v1 legacy decryption + normalization, pre-KDF invalid parameter/base64/IV/size rejection, unique 96-bit IVs, CSPRNG password generator |
| [`tests/persistence-concurrency.test.ts`](./tests/persistence-concurrency.test.ts) | 4 | 6 rapid concurrent mutations serialized via FIFO write queue, `QuotaExceededError` rollback & recovery, multi-tab optimistic concurrency conflict, cloud 409 conflict & recovery |
| [`tests/backup-migration.test.ts`](./tests/backup-migration.test.ts) | 5 | Encrypted-only export, corrupted/incompatible/wrong-password imports never destroy valid vault, verified restore + recovery snapshots, transparent v1 → v2 migration, safe reset |
| [`tests/security-auth-mfa.test.ts`](./tests/security-auth-mfa.test.ts) | 9 | Auth 401, non-admin 403, fail-closed missing allowlist 403, `aal1` MFA required 403, `aal2` authorized, sliding-window limiter, CSRF same-origin check, production CSP nonce + `'wasm-unsafe-eval'`, URL/redirect/QR/Client Hub item-ID validation |
| [`tests/api-routes.test.ts`](./tests/api-routes.test.ts) | 5 | Direct `/api/vault` route handler checks (401, 403 `MFA_REQUIRED`, 400 invalid blob, 409 OCC conflict with `remoteBlob`, 200 OK) |
| [`tests/hooks-and-deeplink.test.tsx`](./tests/hooks-and-deeplink.test.tsx) | 4 | Auto-lock inactivity timer, optional `lockOnBlur`, safe clipboard clear preserving newer clipboard values, Client Hub `/item/{id}` gating behind auth + local unlock |

---

## 3. What Remains Unverified (Requires Live Staging / Real Browser Environment)

1. **Live Supabase PostgreSQL RLS, `002_harden_upsert_rpc.sql` Concurrency & Real TOTP MFA (`npm run test:staging`):**
   - Not executed because no staging Supabase credentials were supplied in this environment.
   - Before production deployment, run `001_init_vault.sql` and `002_harden_upsert_rpc.sql` on a staging Supabase project and execute `npm run test:staging` with `STAGING_SUPABASE_URL`, `STAGING_SUPABASE_ANON_KEY`, `STAGING_ADMIN_EMAIL`, `STAGING_ADMIN_PASSWORD`, and `STAGING_ADMIN_TOTP_CODE`. Also run two simultaneous `upsert_encrypted_vault(p_expected_revision := 0, ...)` transactions against staging PostgreSQL to empirically confirm one returns `OK` and the second returns atomic `CONFLICT`.
2. **Live Upstash Redis Distributed Rate Limiting:**
   - Verified with mocked Upstash REST responses; verify against a live staging Upstash Redis instance (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`) and confirm `GET /api/health` reports `distributedRateLimitConfigured: true`.
3. **Real Browser Argon2id WASM + Production CSP Execution:**
   - Verify full setup, unlock, backup export/verified import, and conflict resolution in real Chrome, Safari (macOS/iOS), and Firefox against a production build (`NODE_ENV=production`) served over HTTPS to confirm `'wasm-unsafe-eval'` and per-request CSP nonces behave cleanly on all target devices.
4. **Production Proxy & TLS Configuration (`vault.nmarkdesigns.com`):**
   - Confirm Cloudflare/Vercel sets the exact header expected by `TRUSTED_PROXY_PROVIDER` (`cloudflare` → `cf-connecting-ip`, `vercel` → `x-vercel-forwarded-for`), HTTPS redirect & Full (Strict) TLS are active, and preview deployments are protected behind auth with staging-only credentials.
