# Security Architecture & Threat Model — NMark Pass Vault v2

## 1. Zero-Knowledge Boundary

NMark Pass Vault enforces **two completely independent security boundaries**:

1. **Application Access Boundary (Supabase Auth + Mandatory TOTP MFA `aal2` + Single-Admin Allowlist)**
   - Protects who can fetch or update the encrypted vault blob on the server.
   - Enforced server-side in Next.js API routes **and** in PostgreSQL Row Level Security (`(auth.jwt() ->> 'aal') = 'aal2'`).
   - Public sign-up is disabled; non-allowlisted accounts are rejected fail-closed (`403`) and immediately signed out.
2. **Cryptographic Decryption Boundary (Master Password + Argon2id + AES-256-GCM)**
   - Exists **exclusively inside the user's browser**.
   - The master password is never sent over the network, never logged, and never persisted.
   - A valid authenticated `aal2` session **never** exposes plaintext credentials without locally deriving the decryption key from the master password.
   - Losing the master password renders the encrypted vault permanently unrecoverable by design.

---

## 2. Cryptographic Specification

| Component | Standard | Parameters / Guarantees |
|---|---|---|
| Key Derivation | Argon2id (`argon2-browser` WASM) | 64 MiB (`65536` KiB), 3 iterations, parallelism 1, 32-byte key output |
| Salt | CSPRNG (`crypto.getRandomValues`) | 16 random bytes (128-bit); rotated on every master password change |
| Symmetric Cipher | Web Crypto `AES-256-GCM` | 256-bit non-extractable `CryptoKey`, 128-bit authentication tag |
| Nonce / IV | CSPRNG (`crypto.getRandomValues`) | Fresh random 12-byte (96-bit) IV generated for every single encryption |
| Authenticated Metadata (v2 AAD) | AES-GCM `additionalData` | Canonical UTF-8 binding: `nmark-pass-vault:v2:aad1\|rev=<rev>\|kdf=<alg>:<mem>:<iter>:<p>:<salt>\|enc=AES-256-GCM:<iv>` |
| Password Generator | `crypto.getRandomValues` | Rejection sampling (zero modulo bias) + Fisher-Yates CSPRNG shuffle |
| Entry Identifiers | `crypto.randomUUID()` | RFC 4122 CSPRNG UUIDv4 |

### Pre-KDF Resource Exhaustion & Validation Guards
Before executing Argon2id (64 MiB WASM), `validateBlobStructure()` and `parseEncryptedBlobJson()` enforce:
- Raw JSON payload <= **5 MiB**, decoded ciphertext <= **4 MiB** and >= **16 bytes** (GCM tag)
- `kdf.algorithm === 'argon2id'`
- `kdf.memory`: integer **16,384 – 262,144 KiB** (16 MiB floor, 256 MiB DoS cap)
- `kdf.iterations`: integer **1 – 20**
- `kdf.parallelism`: integer **1 – 8**
- `kdf.salt`: valid base64 decoding to **16 – 64 bytes**
- `encryption.iv`: valid base64 decoding to **exactly 12 bytes**
- `version`: strictly `1` (legacy) or `2` (current with `aadVersion: 1`)

### IV / Nonce Reuse Limits
Random 96-bit AES-GCM IVs remain well within NIST SP 800-38D collision bounds up to $2^{32}$ encryptions under a single key. Rotating the master password generates a fresh salt and a completely new AES-256 key.

---

## 3. Realistic Browser Memory & XSS Threat Model

- **What client-side encryption protects against:**
  - Server database compromise, SQL dump leakage, hosting provider access, backup theft, MITM inspection of stored blobs, and unauthorized Supabase API reads.
- **What client-side encryption CANNOT fully protect against:**
  - **Same-origin XSS during an active unlocked session:** Malicious JavaScript executing in the same origin while the vault is unlocked can read decrypted state from Zustand/DOM or capture keystrokes on the unlock screen. Because of this, strict CSP, zero unsafe HTML rendering, strict URL validation, and dependency hygiene are critical primary defenses.
  - **JavaScript / V8 memory retention:** Although `lib/crypto.ts` zeroes temporary `Uint8Array` buffers (`passwordBytes`, `hashBytes`, `keyMaterial`, `plaintext`, `salt`) inside `finally` blocks as best-effort defense-in-depth, JavaScript strings (`masterPassword`, serialized JSON, React input state) and WebCrypto `CryptoKey` objects are immutable/garbage-collected and **cannot be guaranteed zeroized in RAM** from JavaScript. Full-disk encryption and OS screen lock remain essential device controls.
  - **Compromised browser extensions or local malware/keyloggers:** Any privileged browser extension with access to `vault.nmarkdesigns.com` can inspect DOM/network state. Run the vault in a clean, minimal-extension browser profile.

---

## 4. Content Security Policy (CSP) & HTTP Headers

Enforced on every response via `middleware.ts` (`lib/security/csp.ts`):

- **Production `script-src`:** `'self' 'nonce-<per-request-csprng>' 'wasm-unsafe-eval'`
  - **No `'unsafe-inline'`** and **no `'unsafe-eval'`** for JavaScript in production.
  - **`'wasm-unsafe-eval'` justification:** Required exclusively so `argon2-browser` can instantiate its embedded Argon2id WebAssembly module (`WebAssembly.instantiate`). Unlike `'unsafe-eval'`, `'wasm-unsafe-eval'` does **not** allow JavaScript `eval()` or `new Function()`.
  - **Development only:** Next.js Fast Refresh requires `'unsafe-inline'`/`'unsafe-eval'`; these are never enabled when `NODE_ENV === 'production'`.
- **`style-src`:** `'self' 'unsafe-inline'` (scoped strictly to CSS; cannot execute scripts).
- **`img-src`:** `'self' data: blob:` (`data:` is required for Supabase TOTP QR SVG data URIs, which are explicitly validated to start with `data:image/svg+xml;`).
- **`connect-src`:** `'self'` plus the configured `NEXT_PUBLIC_SUPABASE_URL` origin only.
- **`object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, `frame-ancestors 'none'`, `upgrade-insecure-requests`**
- **Additional headers:** `Strict-Transport-Security` (2 years, `includeSubDomains; preload`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `X-Robots-Tag: noindex, nofollow, noarchive`.

---

## 5. Server-Side Controls, Fail-Closed Auth, Rate Limiting & Proxy Trust

- **Fail-Closed Authentication (`components/VaultApp.tsx`, `app/api/auth/session/route.ts`):**
  - If `/api/auth/session` fails due to a network error, HTTP `5xx`, or malformed response, the client **never** falls back to local-only mode; it renders a retryable fail-closed error screen instead of bypassing cloud auth or MFA.
  - In production (`NODE_ENV === 'production'`), `/api/auth/session` returns HTTP `503` if Supabase is unconfigured unless `ALLOW_LOCAL_ONLY_MODE=true` is explicitly set for an intentional local-only deployment.
- **Unsynced Local Data Protection (`lib/syncReconcile.ts`, `lib/vaultService.ts`, `store/vaultStore.ts`):**
  - Persists non-sensitive sync metadata (`localStorage['secure_vault_sync_meta']`: `hasUnsavedLocalChanges`, `lastSyncedRevision`, and SHA-256 encrypted envelope fingerprints — never plaintext).
  - Cloud fetches never overwrite unsynced local edits, local-ahead revisions, or equal-revision diverged ciphertext (`localRev === cloudRev` with differing fingerprints); instead, the local blob is preserved and `ConflictModal` guides safe recovery.
- **Atomic First-Time & Concurrent Cloud Writes (`supabase/migrations/002_harden_upsert_rpc.sql`):**
  - `public.upsert_encrypted_vault` acquires a per-user transaction advisory lock (`pg_advisory_xact_lock`), validates non-negative sequential revisions and v2 AAD envelopes, uses `INSERT ... ON CONFLICT (user_id) DO NOTHING` on first insert (returning atomic `CONFLICT` instead of `23505 unique_violation`), and verifies `ROW_COUNT` on conditional `UPDATE`.
- **CSRF Protection (`lib/security/csrf.ts`):** All `POST`/`PUT`/`PATCH`/`DELETE` routes verify `Sec-Fetch-Site` and `Origin` against the request host / `NEXT_PUBLIC_APP_URL`, paired with `HttpOnly; SameSite=Lax; Secure` session cookies.
- **Distributed Rate Limiting & Trusted Proxy IP Extraction (`lib/security/rateLimit.ts`):**
  - Supports **Upstash Redis REST API** (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`) for production multi-instance / serverless deployments.
  - **Fail-closed on auth/MFA:** If configured Redis is unreachable, `auth` and `mfa` tiers fail closed (`429`) rather than permitting unlimited brute-force attempts.
  - **Account + User Keying:** Sign-in is rate-limited by both verified IP and SHA-256 email hash; MFA and vault endpoints are rate-limited by both verified IP and authenticated `userId`.
  - **No Untrusted Forwarded IP Headers:** Client-supplied `X-Forwarded-For` / `X-Real-Ip` headers are ignored by default (`TRUSTED_PROXY_PROVIDER=none`). Configure `cloudflare` (`cf-connecting-ip`), `vercel` (`x-vercel-forwarded-for`), or `custom` (rightmost `TRUSTED_PROXY_HOP_COUNT` hop) to match your verified reverse proxy.
- **No Privileged DB Credentials in Runtime:** Both browser and server routes use the Supabase `anon` key with the authenticated user's JWT so PostgreSQL RLS (`owner + aal2`) is enforced even if an application bug occurs.

---

## 6. Auto-Lock, Clipboard & URL Safety

- **Wall-Clock Auto-Lock (`hooks/useInactivityLock.ts`):** Tracks `Date.now()` timestamps with a 5-second heartbeat and `visibilitychange`/`focus` wake checks so sleeping laptops or suspended mobile browsers lock immediately upon waking.
- **Cross-Tab Lock:** Locking in one tab broadcasts `LOCK_VAULT` over `BroadcastChannel` to lock sibling tabs.
- **Best-Effort Safe Clipboard (`hooks/useClipboard.ts`):** When the clear timer fires, compares `navigator.clipboard.readText()` (when permitted) against the copied secret and avoids erasing a newer unrelated clipboard value. Clears pending secrets immediately when the vault locks.
- **Safe URLs (`lib/urlSafety.ts`):** External login links only allow `https:` and `http:` schemes (`rel="noopener noreferrer" target="_blank"`).
