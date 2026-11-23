# NMark Client Hub Integration Specification

## 1. Security Boundary Model

**NMark Pass Vault** (`https://vault.nmarkdesigns.com`) and **NMark Client Hub** are **strictly separate security domains**.

- Client Hub manages non-secret operational records: clients, websites, hosting providers, domain registrars, email services, service accounts, and technical metadata.
- Pass Vault exclusively stores encrypted credentials.
- **No passwords, decryption keys, or plaintext secrets ever flow between Pass Vault and Client Hub** (not via URLs, query parameters, postMessage, webhooks, shared cookies, or cross-origin APIs).
- Pass Vault authentication (Supabase Admin + TOTP MFA `aal2`) and Master Password decryption remain completely independent of Client Hub authentication.

---

## 2. Deep-Link Contract

Client Hub references a credential stored in Pass Vault solely by its **opaque stable UUID** (`vaultItemId`):

```text
https://vault.nmarkdesigns.com/item/{vaultItemId}
```

### Example
```text
https://vault.nmarkdesigns.com/item/11111111-1111-4111-8111-111111111111
```

### How to Link a Record
1. Create or open the credential in **NMark Pass Vault**.
2. Click **Copy Deep Link** (or copy the **Stable Vault Item ID** shown in the Entry Modal).
3. Store only the `vault_item_id` (UUID string) in Client Hub's database (e.g., `hosting_accounts.vault_item_id` or `service_accounts.vault_item_id`).
4. In Client Hub's UI, render an external link:
   ```html
   <a
     href="https://vault.nmarkdesigns.com/item/{vaultItemId}"
     target="_blank"
     rel="noopener noreferrer"
   >
     Open in Pass Vault
   </a>
   ```

---

## 3. Authorization Flow When Opening a Deep Link

When an administrator clicks `https://vault.nmarkdesigns.com/item/{vaultItemId}` from Client Hub:

1. **ID Format Validation (`app/item/[id]/page.tsx`):**
   - Pass Vault validates `{vaultItemId}` against `/^[a-zA-Z0-9_-]{8,128}$/`. Invalid or malicious IDs are ignored safely.
2. **Gate 1 — Application Authentication (Cloud Mode):**
   - If not signed in, Pass Vault renders the single-admin Sign-In screen while remembering `{vaultItemId}` in memory. Zero credential data is returned by the server.
3. **Gate 2 — Mandatory TOTP MFA (`aal2`):**
   - If the session is not `aal2`, Pass Vault requires 6-digit TOTP verification before fetching the encrypted blob.
4. **Gate 3 — Local Master Password Unlock:**
   - Pass Vault requires the local Master Password to derive the AES-256-GCM key via Argon2id and decrypt the vault in browser memory.
5. **Post-Unlock Item Resolution (`components/vault/ItemList.tsx`):**
   - Only **after** unlocking does Pass Vault look up `{vaultItemId}` in the decrypted in-memory vault and open `EntryModal` for that entry.
   - If `{vaultItemId}` does not exist (e.g., deleted or wrong vault), a safe non-leaking banner reports that the entry was not found.

---

## 4. Integration Rules (Non-Negotiable)

| Allowed | Strictly Prohibited |
|---|---|
| Storing opaque `vault_item_id` UUIDs in Client Hub | Storing passwords, API secrets, or master passwords in Client Hub |
| Opening `https://vault.nmarkdesigns.com/item/{id}` in a new tab with `rel="noopener noreferrer"` | Passing credentials, tokens, or master passwords in URLs or query strings |
| Tagging Pass Vault entries with client slugs (e.g., `client-acme`, `dns`) | Exposing cross-origin credential APIs or CORS wildcard headers from Pass Vault |
| Keeping Pass Vault on its own subdomain (`vault.nmarkdesigns.com`) | Sharing session cookies across subdomains (`Domain=.nmarkdesigns.com`) |
| Independent Pass Vault MFA (`aal2`) + Master Password | Embedding Pass Vault inside an `<iframe>` (`frame-ancestors 'none'` blocks this) |
