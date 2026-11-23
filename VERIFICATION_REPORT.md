# Final Verification Report — NMark Pass Vault v2

**Date:** 2026-11-23  
**Target Domain:** `https://vault.nmarkdesigns.com`

---

## 1. Automated Verification Results

| Check | Command | Result | Details |
|---|---|---|---|
| TypeScript | `npm run typecheck` | **PASS** | `tsc --noEmit` exited with code 0 (zero type errors) |
| Linting | `npm run lint` | **PASS** | `next lint` exited with code 0 (`✔ No ESLint warnings or errors`) |
| Automated Tests | `npm test` | **PASS** | **6 test files, 35 / 35 tests passed** (Vitest 5.1.1) |
| Production Build | `npm run build` | **PASS** | Next.js `15.5.29` compiled all App Router pages, API routes, `/item/[id]`, `/robots.txt`, and `middleware.ts` |
| Dependency Audit | `npm audit` | **IMPROVED** | Reduced from **19 advisories (1 critical, 10 high, 8 moderate)** to **3 build/dev-only advisories (0 critical, 2 high, 1 moderate)** (`postcss` bundled in Next.js 15 build pipeline, `brace-expansion` dev dep) |
| Live Server Smoke Test | `npm run start` + `curl` | **PASS** | Verified `HTTP 200` on `/` and `/item/{id}`, `Disallow: /` on `/robots.txt`, `HTTP 503` fail-closed on unconfigured `/api/vault`, and production CSP nonce + HSTS + `X-Frame-Options: DENY` + `Referrer-Policy: no-referrer` + `X-Robots-Tag: noindex, nofollow, noarchive` |

---

## 2. Automated Test Coverage Matrix

| Test Suite | Covered Requirements |
|---|---|
| [`tests/crypto.test.ts`](./tests/crypto.test.ts) (8 tests) | v2 AES-256-GCM + AAD round trip, wrong master password, tampered ciphertext, tampered envelope metadata (`revision`, `kdf.iterations`), v1 legacy decryption + field normalization, pre-KDF invalid parameter/base64/IV/size rejection, unique 96-bit IV generation (40/40), CSPRNG password generator |
| [`tests/persistence-concurrency.test.ts`](./tests/persistence-concurrency.test.ts) (4 tests) | 6 rapid concurrent mutations serialized cleanly via FIFO write queue (0 lost writes), failed write (`QuotaExceededError`) rollback + recovery, multi-tab optimistic concurrency conflict (`VaultRevisionConflictError`) + snapshot preservation, cloud HTTP 409 conflict detection + recovery |
| [`tests/backup-migration.test.ts`](./tests/backup-migration.test.ts) (5 tests) | Encrypted-only export (zero plaintext), corrupted/incompatible/wrong-password imports never overwrite existing valid vault, verified backup restore + automatic recovery snapshot, transparent v1 → v2 migration on unlock with v1 snapshot preservation, safe reset snapshot |
| [`tests/security-auth-mfa.test.ts`](./tests/security-auth-mfa.test.ts) (9 tests) | Unauthenticated 401, non-admin 403, fail-closed missing allowlist 403, `aal1` MFA required 403, `aal2` admin authorized, sliding-window rate limiter + reset, CSRF same-origin enforcement, restrictive production CSP (nonce + `'wasm-unsafe-eval'`, no unsafe script directives), URL / redirect / QR URI / Client Hub item-ID safety |
| [`tests/api-routes.test.ts`](./tests/api-routes.test.ts) (5 tests) | Direct route handler integration tests for `GET/PUT /api/vault` (401, 403 `MFA_REQUIRED`, 400 invalid blob, 409 OCC conflict with `remoteBlob`, 200 OK valid v2 write) |
| [`tests/hooks-and-deeplink.test.tsx`](./tests/hooks-and-deeplink.test.tsx) (4 tests) | Inactivity auto-lock, optional `lockOnBlur` behavior, safe clipboard clear preserving newer copied clipboard values, Client Hub `/item/{id}` gating behind Cloud Auth + Local Unlock before opening referenced entry |

---

## 3. Checks Not Executed & Remaining Risks (Honest Assessment)

Passing unit, integration, lint, and build checks does **not** by itself certify production security. The following items require verification during live staging/production rollout:

1. **Live Supabase PostgreSQL RLS & TOTP MFA End-to-End Verification:**
   - No live Supabase project credentials were provisioned in this workspace; `supabase/migrations/001_init_vault.sql` and live Supabase Auth TOTP flows must be executed and verified against a staging Supabase project before pointing to production.
   - Specifically verify with a staging token: (a) `anon` key alone returns 0 rows / permission denied, (b) an `aal1` JWT without TOTP is denied by PostgreSQL RLS, (c) a second user account cannot read/write the admin's row, and (d) simultaneous writes from two devices trigger HTTP `409 Conflict`.
2. **Real Browser WASM Argon2id E2E Verification:**
   - Unit tests mock `argon2-browser` in jsdom (while testing real WebCrypto AES-256-GCM + AAD). Before production cutover, perform an end-to-end unlock/encrypt/backup-restore test in real Chrome, Safari (macOS/iOS), and Firefox with production CSP headers enabled to confirm `'wasm-unsafe-eval'` permits Argon2id WASM execution cleanly across all target browsers.
3. **Distributed Rate Limiting:**
   - The in-memory sliding-window limiter (`lib/security/rateLimit.ts`) protects single-instance Node processes, but serverless cold starts / multi-region instances do not share memory. Pair with Cloudflare WAF or Vercel Edge rate limiting before exposing `vault.nmarkdesigns.com` publicly (see `DEPLOYMENT.md`).
4. **Remaining Dev/Build Advisories (`npm audit`):**
   - 3 advisories remain in dev/build transitive tooling (`postcss` inside `next@15.5.29` and `brace-expansion` in ESLint/tooling). Neither executes on user input at runtime; upgrading to Next.js 16 (major breaking change) can be scheduled once `argon2-browser` Turbopack compatibility is validated.
5. **Client-Side Security Realities:**
   - Same-origin XSS during an unlocked session or a malicious browser extension can still inspect decrypted in-memory credentials. Use a dedicated, minimal-extension browser profile and full-disk device encryption.
