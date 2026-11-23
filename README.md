# NMark Pass Vault (v2)

A private, single-user, **zero-knowledge** password vault built with Next.js 15, React 18, TypeScript, Zustand, Web Crypto API (`AES-256-GCM`), Argon2id (`argon2-browser` WASM), and optional encrypted Supabase cloud synchronization.

Production target: `https://vault.nmarkdesigns.com`

---

## Key Security & Engineering Features

- **Zero-Knowledge Client-Side Cryptography (Envelope Format v2)**
  - **KDF:** Argon2id (64 MiB memory, 3 iterations, parallelism 1, 256-bit key)
  - **Cipher:** Web Crypto `AES-256-GCM` with fresh 96-bit CSPRNG IV per write
  - **Authenticated Metadata (AAD):** Binds format version, revision, KDF parameters, salt, algorithm, and IV into the GCM authentication tag
  - **Backward Compatibility:** Transparently decrypts v1 vaults/backups and upgrades them safely to v2 after saving an encrypted recovery snapshot
- **Concurrency & Multi-Tab Integrity**
  - Serialized FIFO async write queue prevents overlapping saves and stale rollbacks
  - Monotonic revision numbers with optimistic concurrency control (`localStorage` + PostgreSQL)
  - `BroadcastChannel` + `storage` listener propagates locks across tabs and surfaces safe conflict resolution UI
- **Single-Admin Cloud Sync & Mandatory MFA (Supabase PostgreSQL)**
  - Separate security boundaries: **(1) Account Sign-In → (2) Mandatory TOTP MFA (`aal2`) → (3) Local Master Password Decryption**
  - Fail-closed single-admin allowlist (`ALLOWED_ADMIN_EMAIL` / `ALLOWED_ADMIN_USER_ID`), zero public sign-up
  - Strict PostgreSQL RLS enforcing `auth.uid() = user_id AND (auth.jwt() ->> 'aal') = 'aal2'` with all `anon` access revoked
  - Atomic `upsert_encrypted_vault` RPC returning HTTP `409 Conflict` on stale writes
  - Dual-mode: runs seamlessly in **Local-Only Mode** when Supabase env vars are unset
- **Verified Backup & Recovery**
  - Exports encrypted JSON envelopes only
  - Imports require password verification & in-memory decryption *before* touching the active vault
  - Automatic encrypted recovery snapshots before imports, migrations, password rotations, conflict resolutions, and resets
- **Client Hub Integration Ready**
  - Stable entry IDs and deep links (`/item/{vaultItemId}`) strictly gated behind Auth + MFA + local Master Password unlock
- **Hardened HTTP Headers & CSP**
  - Per-request CSP nonces, `'wasm-unsafe-eval'` (for Argon2 WASM only), HSTS, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `robots.txt` disallowing all crawlers

---

## Getting Started (Local Development)

```bash
npm install
cp .env.example .env.local
npm run dev
```

Leave `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY` empty in `.env.local` to run in **Local-Only Mode**, or populate them (along with `ALLOWED_ADMIN_EMAIL` / `ALLOWED_ADMIN_USER_ID`) and apply [`supabase/migrations/001_init_vault.sql`](./supabase/migrations/001_init_vault.sql) to enable **Encrypted Cloud Sync**.

---

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Start Next.js 15 development server |
| `npm run typecheck` | Run strict TypeScript checking (`tsc --noEmit`) |
| `npm run lint` | Run ESLint (`next/core-web-vitals` + `next/typescript`) |
| `npm test` | Run automated Vitest test suite |
| `npm run build` | Build production Next.js server bundle |
| `npm run start` | Run production Next.js server |

---

## Documentation

- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — Initial baseline security audit and prioritized remediation plan
- [`SECURITY.md`](./SECURITY.md) — Cryptographic model, threat model, CSP decisions, and memory-safety realities
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — System architecture, envelope format v1/v2, concurrency & sync design
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — Production deployment checklist for `vault.nmarkdesigns.com`, Supabase setup, DNS, and rollback plan
- [`CLIENT_HUB_INTEGRATION.md`](./CLIENT_HUB_INTEGRATION.md) — Safe integration boundary for NMark Client Hub deep links
