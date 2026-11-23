# Production Deployment Guide — `vault.nmarkdesigns.com`

> **Safety Rule:** Never commit `.env.local` or real credentials to Git. Never run production migrations or DNS changes without an offline encrypted vault backup first.

---

## 1. Recommended Hosting Architecture

Because Pass Vault v2 uses Next.js Middleware (per-request CSP nonces + security headers), server-side Auth/MFA API routes, and dynamic `/item/[id]` routes, deploy on a **Node.js / Next.js server runtime** (e.g., **Vercel** or a hardened Node 22 container behind Cloudflare/Nginx) rather than static-only hosting (`output: 'export'` has been removed).

| Layer | Recommended Service |
|---|---|
| Web App + API | Vercel (Next.js 15) or Docker/Node 22 VPS |
| Auth + Database | Supabase (PostgreSQL + Auth with TOTP MFA) |
| DNS + TLS + Edge WAF | Cloudflare (Full Strict TLS, HSTS, Edge Rate Limiting) |
| Production Domain | `https://vault.nmarkdesigns.com` |

---

## 2. Supabase Production Configuration

1. **Create a dedicated Supabase project** (do not share tables or auth users with untrusted public apps).
2. **Disable Public Sign-Ups:**
   - In Supabase Dashboard → **Authentication → Providers → Email**:
     - Disable **Enable Sign Ups** (or enable **Invite Only**).
     - Enable **Confirm Email**.
3. **Enable TOTP MFA:**
   - In Supabase Dashboard → **Authentication → Multi-Factor Authentication**:
     - Enable **TOTP (App Authenticator)**.
4. **Create Your Sole Admin Account:**
   - In Supabase Dashboard → **Authentication → Users → Invite User** (or Add User) with your admin email.
   - Copy the generated **User UUID** (`ALLOWED_ADMIN_USER_ID`).
5. **Apply Database Schema, RLS Policies & Hardened RPC:**
   - Run [`supabase/migrations/001_init_vault.sql`](./supabase/migrations/001_init_vault.sql) followed by [`supabase/migrations/002_harden_upsert_rpc.sql`](./supabase/migrations/002_harden_upsert_rpc.sql) via Supabase SQL Editor or `supabase db push`.
   - Verify RLS is enabled and forced on `public.vaults`, `public.vault_snapshots`, and `public.vault_audit_log`, and that `anon` has zero table/function grants.
6. **Configure Auth URLs:**
   - Site URL: `https://vault.nmarkdesigns.com`
   - Redirect URLs: `https://vault.nmarkdesigns.com/**` (do not add wildcards for untrusted domains).

---

## 3. Environment Variables

Configure these variables in your hosting provider's encrypted secrets store (e.g., Vercel Production Environment Variables):

| Variable | Scope | Value |
|---|---|---|
| `NEXT_PUBLIC_APP_URL` | Public | `https://vault.nmarkdesigns.com` |
| `NEXT_PUBLIC_SUPABASE_URL` | Public | `https://<project-ref>.supabase.co` |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Public | Supabase project `anon` key (safe because RLS enforces `owner + aal2`) |
| `ALLOWED_ADMIN_EMAIL` | **Server-only** | Your sole admin email address |
| `ALLOWED_ADMIN_USER_ID` | **Server-only** | Your Supabase Auth admin User UUID |
| `UPSTASH_REDIS_REST_URL` | **Server-only** | Upstash Redis REST URL for distributed multi-instance rate limiting |
| `UPSTASH_REDIS_REST_TOKEN` | **Server-only** | Upstash Redis REST token |
| `TRUSTED_PROXY_PROVIDER` | **Server-only** | `cloudflare`, `vercel`, `custom`, or `none` (default `none` ignores spoofable forwarded IP headers) |
| `TRUSTED_PROXY_HOP_COUNT` | **Server-only** | Required only when `TRUSTED_PROXY_PROVIDER=custom` (default `1`) |
| `ALLOW_LOCAL_ONLY_MODE` | **Server-only** | Keep `false` (default) in production so missing Supabase config fails closed (`503`). Set `true` only for an intentional local-only installation. |
| `RATE_LIMIT_ALLOW_IN_MEMORY` | **Server-only** | Keep `false` on serverless; set `true` only on a single-node VPS without Redis |

- **Never** set `SUPABASE_SERVICE_ROLE_KEY` in the app environment — the app intentionally does not use it so PostgreSQL RLS is never bypassed.
- Check `GET https://vault.nmarkdesigns.com/api/health` after deployment to confirm `cloudSyncConfigured: true`, `distributedRateLimitConfigured: true`, and your expected `trustedProxyProvider`.

---

## 4. DNS, TLS & Edge Hardening (`vault.nmarkdesigns.com`)

1. **DNS Record:** Create a `CNAME` (or `A`) record for `vault.nmarkdesigns.com` pointing to your hosting target (e.g., `cname.vercel-dns.com`).
2. **HTTPS Only:**
   - Enforce automatic HTTP → HTTPS redirect at DNS/edge.
   - Set Cloudflare SSL/TLS mode to **Full (Strict)**.
   - Enable HSTS (already emitted by `middleware.ts`: `max-age=63072000; includeSubDomains; preload`).
   - If proxied through Cloudflare, set `TRUSTED_PROXY_PROVIDER=cloudflare`; if deployed directly on Vercel without Cloudflare proxy, set `TRUSTED_PROXY_PROVIDER=vercel`.
3. **Edge Rate Limiting (Defense-in-Depth alongside Upstash Redis):**
   - Add a WAF rate-limit rule on `vault.nmarkdesigns.com/api/auth/*`: max 10 requests per 15 minutes per IP.
   - Add a WAF rule on `vault.nmarkdesigns.com/api/vault*`: max 60 requests per 5 minutes per IP.
4. **Protected Preview Deployments & Staging Verification:**
   - Enable **Vercel Deployment Protection** (or equivalent auth gate) for all Preview branches.
   - Use a separate staging Supabase project for Preview deployments — never point Preview branches at the production vault database!
   - Run `npm run test:staging` against your staging Supabase project before promoting to production.

---

## 5. Safe Migration from Legacy Hostinger Static Deployment

When moving from `https://darkgoldenrod-crane-455058.hostingersite.com/` to `https://vault.nmarkdesigns.com`:

1. Open the legacy deployment, unlock your vault, and click **Export Backup** to save your encrypted `.json` file locally (keep a second offline copy).
2. Open `https://vault.nmarkdesigns.com`, sign in with your admin email/password, enroll TOTP MFA, and verify `aal2`.
3. On the vault initialization screen, switch to **Restore Encrypted Backup**, upload the exported `.json` file, and enter your existing master password.
4. The app will verify decryptability in memory, upgrade the envelope safely from Format v1 to Format v2 (with AES-GCM AAD), and sync the encrypted blob to Supabase.
5. Verify all credentials on `vault.nmarkdesigns.com` and test unlocking from a second device before retiring the old Hostinger static site.

---

## 6. Build & Verification Checklist

Run before every release:

```bash
npm run typecheck
npm run lint
npm test
npm run build
```

After deployment, verify with `curl -I https://vault.nmarkdesigns.com`:
- `content-security-policy` contains `'nonce-...'` and `'wasm-unsafe-eval'` (no `'unsafe-inline'` in `script-src`)
- `strict-transport-security`, `x-frame-options: DENY`, `x-content-type-options: nosniff`, `referrer-policy: no-referrer`, `x-robots-tag: noindex, nofollow, noarchive` are present
- `GET /api/vault` without cookies returns `401 Unauthorized`
- `GET /robots.txt` returns `Disallow: /`

---

## 7. Rollback Strategy

1. **Application Rollback:** Redeploy / promote the previous known-good deployment release in Vercel (or previous container image tag). Because Format v2 decryption is backward-compatible with Format v1, data integrity is preserved across patch rollbacks.
2. **Database Rollback:**
   - Enable **Supabase Point-in-Time Recovery (PITR)** / daily automated encrypted backups on the production project.
   - Encrypted recovery snapshots are also stored in `public.vault_snapshots` and browser `localStorage['secure_vault_recovery_snapshots']`, plus your offline exported encrypted `.json` backups.
   - Never run destructive `DROP TABLE` migrations on `public.vaults` in production; use additive migrations only.
