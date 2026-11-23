# Pass Vault — Initial Security & Architecture Audit Report

**Audit Date:** 2026-11-23  
**Repository:** `https://github.com/nikola93kg/pass-manager`  
**Target Domain:** `https://vault.nmarkdesigns.com`  
**Baseline Reviewed:** Commit `068c27d` (Next.js `14.2.35`, React 18, TypeScript 5, Zustand 5, `argon2-browser` 1.18, Web Crypto API)

---

## Executive Summary

Pass Vault v1 establishes a clean client-side cryptographic foundation (Argon2id 64 MiB / 3 iterations + AES-256-GCM with 96-bit random IVs and CSPRNG password generation). However, as a single-user production password manager storing real client credentials across multiple devices, the baseline codebase has **critical security, data-integrity, concurrency, and operational gaps** that must be remediated before production use.

In particular:
1. **Unauthenticated envelope metadata** allows tampering with KDF parameters or revision metadata without AES-GCM detection.
2. **Unsynchronized asynchronous writes and lack of multi-tab revision checks** create real data-loss race conditions in `localStorage`.
3. **Destructive backup import** overwrites a valid vault *before* verifying that the imported backup can actually be decrypted.
4. **No HTTP security headers / CSP**, **critical CVEs in `next@14.2.35`**, **no authentication/MFA/cloud sync**, and **zero automated test coverage**.

---

## Prioritized Findings

Each finding is classified as either a **Confirmed Code Defect** (directly observed in the baseline code) or a **Theoretical Risk / Architectural Gap** (threat-model or production-readiness gap).

### CRITICAL

#### C-01 · Confirmed Code Defect — Next.js `14.2.35` Has Critical/High Security Advisories
- **Location:** `package.json`, `package-lock.json`
- **Evidence:** `npm audit` reports **19 vulnerabilities (1 critical, 10 high, 8 moderate)**, including critical advisories in `next@14.2.35` (SSRF, cache poisoning, RSC DoS, middleware/header issues) and high advisories in `postcss`, `eslint-config-next`, `glob`, `flatted`, `js-yaml`, `nanoid`.
- **Impact:** Moving to a server-rendered deployment with API routes and middleware on `next@14.2.35` would expose the application to known critical framework vulnerabilities.
- **Remediation:** Upgrade `next` and `eslint-config-next` to a patched release (`15.5.x`), resolve fixable transitive advisories, and document any remaining dev-only advisories.

#### C-02 · Confirmed Code Defect — Import Overwrites Valid Vault Without Verifying Decryptability or Creating a Recovery Snapshot
- **Location:** `lib/vaultService.ts` (`importVault`), `components/vault/SettingsPanel.tsx` (`handleImportFile`)
- **Evidence:** `importVault()` only runs `validateBlobStructure()` (JSON shape check) and immediately executes `localStorage.setItem(VAULT_STORAGE_KEY, ...)`. It never verifies that the ciphertext can be decrypted with a valid master password, nor does it save a recovery snapshot of the previous vault.
- **Impact:** Importing a corrupted backup, a file encrypted with an unknown password, or a truncated ciphertext permanently destroys the user's existing working vault.
- **Remediation:** Require the user to supply the backup's master password and verify decryption *in memory* before writing to storage; automatically create an encrypted recovery snapshot before any destructive operation (import, reset, migration, master password rotation).

#### C-03 · Confirmed Code Defect — Static Export Architecture Prevents Server-Side Auth, MFA Enforcement, Rate Limiting & HTTP Security Headers
- **Location:** `next.config.js` (`output: 'export'`)
- **Evidence:** The app is configured as a static SPA with no server runtime, no middleware, no API routes, no CSP, no HSTS, no `X-Frame-Options`, and no server-side session/MFA validation.
- **Impact:** Cannot enforce HTTP security headers, cannot authenticate or authorize cloud sync with server-side MFA (`aal2`), cannot enforce single-admin allowlisting or rate limiting, and cannot safely support dynamic deep links (`/item/[id]`).
- **Remediation:** Transition to a full Next.js server build with `middleware.ts`, strict security headers/CSP, server-side Supabase Auth + MFA (`aal2`) API routes, and PostgreSQL RLS.

---

### HIGH

#### H-01 · Confirmed Code Defect — Unserialized Async Vault Writes Cause Race Conditions and Stale Rollbacks
- **Location:** `store/vaultStore.ts` (`addVaultItem`, `updateVaultItem`, `deleteVaultItem`, `saveSettings`), `lib/vaultService.ts` (`saveVault`)
- **Evidence:** Each mutation immediately fires an unqueued `await saveVault(updated, cryptoKey, salt)`. Because `crypto.subtle.encrypt` is asynchronous, two rapid mutations can finish out of order so an older ciphertext overwrites a newer one in `localStorage`. Furthermore, if mutation #1 fails after mutation #2 begins, rolling back to `previous` clobbers mutation #2.
- **Impact:** Silent credential loss or stale state overwrites during rapid editing.
- **Remediation:** Implement a serialized write queue with monotonic revision numbers, atomic state transitions, unsaved-change tracking, and safe error recovery.

#### H-02 · Confirmed Code Defect — Multi-Tab Concurrent Edits Silently Overwrite Newer Vault Data
- **Location:** `lib/vaultService.ts`, `store/vaultStore.ts`
- **Evidence:** No revision counter exists on `EncryptedVaultBlob`, no `storage` event listener detects external writes from another tab, and `persistBlob()` unconditionally overwrites `localStorage['secure_vault_blob']`.
- **Impact:** Editing in Tab A and then saving in Tab B permanently erases Tab A's credentials.
- **Remediation:** Add monotonic `revision` tracking to the vault envelope, verify expected revision before every `localStorage` write (optimistic concurrency), listen to `window` `storage` events and `BroadcastChannel`, surface conflict resolution UI, and propagate lock events across tabs.

#### H-03 · Confirmed Code Defect — Envelope Metadata Not Authenticated via AES-GCM AAD; Insufficient Blob & KDF Validation
- **Location:** `lib/crypto.ts` (`encryptVault`, `decryptVault`, `validateBlobStructure`, `base64ToBuf`)
- **Evidence:**
  1. `crypto.subtle.encrypt` / `decrypt` do not pass `additionalData` (AAD). Envelope fields (`version`, `kdf.*`, `encryption.*`, `revision`) are unauthenticated.
  2. `validateBlobStructure` does not validate base64 decoding, exact byte lengths (`iv` must be 12 bytes; `salt` 16–64 bytes; `ciphertext` >= 16 bytes for GCM tag), or a maximum payload size limit (DoS/memory exhaustion vector on malicious import).
  3. `keyMaterial = hashBytes.slice().buffer` creates a second buffer of raw derived key bytes that is never zeroed, and `hashBytes` is not zeroed inside a `finally` block if `importKey` fails.
- **Impact:** Tampered KDF/envelope metadata goes undetected; malformed or giant blobs can crash the browser tab or trigger excessive Argon2id work.
- **Remediation:** Define **Vault Envelope Format v2** authenticating canonical envelope metadata via AES-GCM AAD while preserving full backward-compatible decryption and transparent migration for **v1** blobs. Enforce strict base64, byte-length, KDF parameter bounds, and max payload size validation before running Argon2id.

#### H-04 · Architectural Gap — No Encrypted Cloud Sync, No Authentication, No Mandatory MFA
- **Location:** Application-wide
- **Evidence:** Data exists only in a single browser's `localStorage`; there is no authentication layer, no MFA, and no multi-device sync.
- **Impact:** Browser storage eviction causes total credential loss; no secure multi-device access across Windows, macOS, and mobile.
- **Remediation:** Implement Supabase Auth (invite-only single-admin allowlist, mandatory TOTP MFA with `aal2` enforcement at both API and PostgreSQL RLS layers) + encrypted-only PostgreSQL storage with optimistic concurrency control (`expected_revision`) and conflict resolution UI.

#### H-05 · Confirmed Code Defect — Missing Automated Tests & Unconfigured ESLint
- **Location:** `package.json`, repository root
- **Evidence:** No test framework or test files exist. Running `npm run lint` exits with code 1 prompting for interactive ESLint setup because `.eslintrc.json` is missing.
- **Impact:** Regressions in cryptography, concurrency, auth/MFA, or backup/migration logic cannot be caught before deployment.
- **Remediation:** Configure ESLint (`.eslintrc.json`) and implement comprehensive automated tests with Vitest + React Testing Library covering crypto, concurrency, multi-tab sync, conflicts, backup/recovery, auto-lock, auth/MFA guards, and Client Hub deep links.

---

### MEDIUM

#### M-01 · Confirmed Code Defect — Auto-Lock Timer Uses `setTimeout` Only (Vulnerable to OS Sleep/Suspend Drift)
- **Location:** `hooks/useInactivityLock.ts`
- **Evidence:** Inactivity locking relies exclusively on `setTimeout`. When a laptop sleeps or a mobile browser suspends a tab, `setTimeout` is paused by the OS/browser and may not fire immediately on wake. Also, `mousemove` fires hundreds of times per second without throttling, resetting timers continuously.
- **Impact:** A vault left unlocked before closing a laptop lid may remain unlocked briefly or longer upon waking.
- **Remediation:** Track wall-clock `lastActivityAt` (`Date.now()`), check elapsed time on wake (`visibilitychange`, `focus`, periodic heartbeat), and throttle activity event resets.

#### M-02 · Confirmed Code Defect — Clipboard Clearing Unconditionally Overwrites Newer Clipboard Content
- **Location:** `hooks/useClipboard.ts`
- **Evidence:** The timeout unconditionally calls `navigator.clipboard.writeText('')`, even if the user copied something else during the countdown window. Also, locking the vault does not clear a pending copied password.
- **Impact:** Disrupts user workflow by wiping unrelated clipboard content; leaves copied password in clipboard if vault locks early.
- **Remediation:** Compare `navigator.clipboard.readText()` (when permitted) against the last copied secret before clearing, only clearing when it still matches (falling back gracefully when `readText` is unavailable/denied), and clear on vault lock.

#### M-03 · Confirmed Code Defect — Revealed Passwords Never Auto-Hide & No Safe URL Launcher
- **Location:** `components/vault/ItemList.tsx`, `components/vault/EntryModal.tsx`
- **Evidence:** Toggling password visibility leaves plaintext passwords rendered in the DOM indefinitely until manually hidden or vault lock. Entry URLs are plain text with no safe launcher (and future href additions risk `javascript:` XSS if unvalidated).
- **Impact:** Increased shoulder-surfing exposure; potential XSS vector if URLs are turned into links without protocol allowlisting.
- **Remediation:** Auto-hide revealed passwords after a short timeout (e.g., 30s) and add a strict `https:`/`http:` URL validator (`lib/urlSafety.ts`) for launching external login URLs with `rel="noopener noreferrer"`.

#### M-04 · Confirmed Code Defect — Conflicting CSS Variables & Search Engine Indexing Not Blocked
- **Location:** `app/globals.css`, `app/layout.tsx`
- **Evidence:** `globals.css` declares conflicting `:root` light-mode styles (`--background: #ffffff`, `font-family: Arial`) below the dark-mode rules. No `robots.txt` or `robots: { index: false, follow: false }` metadata exists.
- **Impact:** Visual inconsistency; private vault domain could be indexed by search crawlers.
- **Remediation:** Clean up `globals.css` with NMark Pass Vault dark purple theme tokens (`#110024`, `#ab7eff`, `#f2ebff`) and add `app/robots.ts` + `X-Robots-Tag: noindex, nofollow`.

#### M-05 · Theoretical Risk — Unrealistic Memory Zeroization Claims in Comments/Docs
- **Location:** `lib/crypto.ts`, `DOCUMENTATION.md`
- **Evidence:** Comments imply master passwords and plaintext are completely wiped from RAM via `zeroMemory()`. In JavaScript/V8, strings (`masterPassword`, `jsonStr`, React state) and WebCrypto `CryptoKey` handles are immutable/GC-managed and cannot be guaranteed zeroized.
- **Impact:** Misleading security documentation can give false assurance against memory-dump or same-origin XSS threats.
- **Remediation:** Keep `Uint8Array` zeroing as best-effort defense-in-depth (fixing `finally` coverage), and document JavaScript memory & XSS threat-model realities honestly in code comments and `SECURITY.md`.

---

### LOW

#### L-01 · Confirmed Code Defect — Unused `uuid` v3/v5/v6 Dependency & Missing Entry Metadata (Tags, Deep Links)
- **Location:** `package.json`, `lib/types.ts`, `components/vault/ItemList.tsx`
- **Evidence:** `uuid@13.0.0` carries a moderate advisory (`uuid` v3/v5/v6 buffer bounds), while modern browsers and Node 22 natively provide `crypto.randomUUID()` (CSPRNG UUIDv4). Also, `VaultItem` lacks `tags` and Client Hub deep-link support (`/item/{id}`).
- **Remediation:** Replace `uuid` with native `crypto.randomUUID()` (with a `crypto.getRandomValues` fallback), eliminating the dependency completely, and add `tags` + `/item/[id]` deep linking.

#### L-02 · Confirmed Code Defect — No `.env.example` or Runtime Environment Validation
- **Location:** Repository root
- **Evidence:** No environment validation module or `.env.example` template exists for Supabase / admin allowlist configuration.
- **Remediation:** Add `lib/env.ts` (strict Zod/typed validation separating public vs. server-only secrets) and `.env.example`.

---

## Prioritized Implementation Plan

| Phase | Scope | Key Deliverables |
|---|---|---|
| **Phase 1** | **Cryptography & Input Hardening** | Envelope Format v2 (AES-GCM AAD + revision) with full v1 backward-compatible decryption & migration; strict base64/length/KDF/size guards; proper `finally` buffer zeroing; `lib/urlSafety.ts`; native `crypto.randomUUID()`. |
| **Phase 2** | **Concurrency, Multi-Tab Sync, Backup/Recovery & Hooks** | Serialized write queue in `store/vaultStore.ts`; optimistic revision locking in `lib/vaultService.ts`; `storage` + `BroadcastChannel` multi-tab sync & conflict detection; verified-decryption import flow + automatic encrypted recovery snapshots; wall-clock `useInactivityLock`; safe `useClipboard`; auto-hide password reveal. |
| **Phase 3** | **Supabase Auth, Mandatory MFA & Encrypted Cloud Sync** | SQL migration `supabase/migrations/001_init_vault.sql` (`vaults`, `vault_snapshots`, `vault_audit_log`, strict RLS requiring `auth.uid() = user_id` AND `aal = 'aal2'`, atomic `upsert_encrypted_vault` RPC); server-side auth/MFA/allowlist guards; rate limiter; CSRF origin verification; `/api/vault`, `/api/vault/snapshots`, `/api/auth/*` routes; first-time local-to-cloud migration & conflict resolution UI. |
| **Phase 4** | **Framework Upgrade, CSP & Security Headers** | Upgrade Next.js & ESLint config to `15.5.x`; remove `output: 'export'`; add `middleware.ts` + strict CSP (documenting `'wasm-unsafe-eval'`), HSTS, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `robots.ts`; configure `.eslintrc.json`. |
| **Phase 5** | **Client Hub Deep-Link Boundary (`/item/[id]`)** | Dynamic `/item/[id]` route preserving intent through Auth → MFA → Vault Unlock; strict item-ID validation; copyable deep-link button; zero secrets in URLs/API. |
| **Phase 6** | **UI/UX Overhaul (NMark Pass Vault)** | Dark purple palette (`#110024`, `#ab7eff`, `#f2ebff`), tags & search/filter, sync status & unsaved indicators, conflict resolution modal, verified import modal, TOTP MFA enrollment/challenge screens, recovery/reset controls. |
| **Phase 7** | **Comprehensive Automated Tests** | Vitest + jsdom + Testing Library test suite covering all 15 required security, concurrency, sync, auth/MFA, backup, and deep-link scenarios. |
| **Phase 8** | **Documentation & Production Verification** | `README.md`, `SECURITY.md`, `ARCHITECTURE.md`, `DEPLOYMENT.md`, `CLIENT_HUB_INTEGRATION.md`, `VERIFICATION_REPORT.md`; run typecheck, lint, tests, build, and live server verification. |
