# Vault — Personal Password Manager
## Complete Technical Documentation

---

## Table of Contents

1. [Overview](#1-overview)
2. [Security Architecture](#2-security-architecture)
3. [Cryptography Design](#3-cryptography-design)
4. [Data Model](#4-data-model)
5. [Storage Format](#5-storage-format)
6. [Project Structure](#6-project-structure)
7. [Module Reference](#7-module-reference)
8. [State Management](#8-state-management)
9. [Auto-Lock System](#9-auto-lock-system)
10. [Clipboard Security](#10-clipboard-security)
11. [Password Generator](#11-password-generator)
12. [Import / Export](#12-import--export)
13. [UI Components](#13-ui-components)
14. [Build & Deployment](#14-build--deployment)
15. [Dependencies](#15-dependencies)
16. [Security Threat Model](#16-security-threat-model)
17. [Known Limitations](#17-known-limitations)
18. [FAQ](#18-faq)

---

## 1. Overview

Vault is a **100% client-side, zero-knowledge personal password manager** built with Next.js 14. It runs entirely in the browser — there is no backend, no server, no API, no database, and no account system.

All data is encrypted on your device before being stored. The master password never leaves your browser and is never written to disk in any form. Even the developer of this application cannot access your data.

### Core Properties

| Property | Value |
|---|---|
| Architecture | 100% static SPA (Single Page Application) |
| Backend | None |
| Network requests | None (after initial page load) |
| Data persistence | `localStorage` — encrypted blob only |
| Users | Single user per browser |
| Recovery | Not possible by design |
| Hosting | Any static file host (Hostinger, Netlify, GitHub Pages, etc.) |

---

## 2. Security Architecture

### Zero-Knowledge Model

```
┌─────────────────────────────────────────────────────────────┐
│                        YOUR BROWSER                         │
│                                                             │
│   Master Password                                           │
│         │                                                   │
│         ▼                                                   │
│   Argon2id (WASM)  ──► 32-byte hash                        │
│         │                                                   │
│         ▼                                                   │
│   WebCrypto importKey ──► CryptoKey (non-extractable)       │
│         │                     │                             │
│         │                     ▼                             │
│         │           AES-256-GCM encrypt/decrypt             │
│         │                     │                             │
│         ▼                     ▼                             │
│   [zeroed from RAM]    localStorage                         │
│                        { version, kdf, encryption,          │
│                          ciphertext }  ◄── ONLY THIS        │
│                          (base64 encoded)   PERSISTS        │
└─────────────────────────────────────────────────────────────┘
```

### What is NEVER stored

- Master password (plaintext or hashed)
- Derived key bytes
- Decrypted vault contents
- Any plaintext credentials

### What IS stored (localStorage key: `secure_vault_blob`)

- Argon2id parameters (memory, iterations, parallelism)
- Salt (16 random bytes, base64)
- AES-GCM IV (12 random bytes, base64)
- AES-256-GCM ciphertext + authentication tag (base64)

---

## 3. Cryptography Design

### 3.1 Key Derivation — Argon2id

When you create or unlock the vault, your master password is processed through **Argon2id**, a memory-hard password hashing algorithm that won the 2015 Password Hashing Competition.

**Parameters used:**

| Parameter | Value | Purpose |
|---|---|---|
| Algorithm | Argon2id | Hybrid mode: protects against both side-channel and GPU attacks |
| Memory | 65,536 KB (64 MB) | Forces high RAM usage — makes parallel GPU cracking expensive |
| Iterations | 3 | Time cost — adds CPU work |
| Parallelism | 1 | Single thread |
| Hash length | 32 bytes | Exactly the key size needed for AES-256 |
| Salt | 16 bytes (random) | Unique per vault — prevents rainbow table attacks |

**Why Argon2id specifically?**

- `Argon2d` — best against GPU attacks but vulnerable to side-channel attacks
- `Argon2i` — best against side-channel attacks but weaker against GPUs
- `Argon2id` — hybrid: first half uses Argon2i, second half uses Argon2d. Best of both worlds.

**Code location:** `lib/crypto.ts` → `deriveKey()`

```
masterPassword (string)
      │
      ▼ TextEncoder.encode()
passwordBytes (Uint8Array)
      │
      ├──► zeroMemory() ◄── zeroed immediately after argon2 call
      │
      ▼ argon2Hash({ type: Argon2id, mem: 65536, time: 3, hashLen: 32 })
32-byte hash (Uint8Array)
      │
      ▼ crypto.subtle.importKey('raw', ..., { name: 'AES-GCM' }, false, ['encrypt','decrypt'])
CryptoKey (non-extractable, in-memory only)
      │
      └──► zeroMemory() ◄── hash bytes zeroed after import
```

**Critical security properties of the derived `CryptoKey`:**
- `extractable: false` — the browser will not allow reading the key bytes back
- Exists only in JavaScript heap memory
- Discarded when `lock()` is called (reference set to `null`, GC collects it)

### 3.2 Encryption — AES-256-GCM

All vault data is encrypted using **AES-256-GCM** via the browser's native **WebCrypto API**.

| Property | Value |
|---|---|
| Algorithm | AES-GCM |
| Key size | 256 bits (32 bytes) |
| IV (nonce) | 12 bytes, random per encryption |
| Authentication tag | 128 bits (included in ciphertext) |
| IV reuse | Never — new random IV on every save |

**Why AES-256-GCM?**

GCM (Galois/Counter Mode) provides **authenticated encryption** — it not only encrypts the data but also produces an authentication tag. If anyone tampers with the stored ciphertext (even a single bit), decryption will throw an error rather than returning corrupted data. This protects against both eavesdropping and tampering.

**Code location:** `lib/crypto.ts` → `encryptVault()`, `decryptVault()`

### 3.3 Randomness

The application uses **only** `crypto.getRandomValues()` (the browser's CSPRNG — Cryptographically Secure Pseudo-Random Number Generator) for:

- Salt generation (16 bytes)
- IV generation (12 bytes)
- Password generation (character selection + Fisher-Yates shuffle)

`Math.random()` is **never used** for any security-sensitive operation.

### 3.4 Memory Zeroing

Sensitive byte arrays are overwritten with zeros immediately after use:

| Buffer | When zeroed |
|---|---|
| `passwordBytes` (UTF-8 encoded master password) | Inside `finally` block after `argon2Hash()` call |
| `hashBytes` (32-byte Argon2 output) | After `crypto.subtle.importKey()` |
| `plaintext` (JSON-encoded vault) | After `crypto.subtle.encrypt()` |
| Decrypted `plaintextBuf` | After `JSON.parse()` |
| `salt` (Uint8Array) | When `lock()` is called |

**Note:** JavaScript does not guarantee when GC reclaims memory, so zeroing typed arrays is a best-effort mitigation against cold-boot or memory-dump attacks.

---

## 4. Data Model

### VaultItem

Each credential entry stored in the vault:

```typescript
interface VaultItem {
  id: string;           // UUID v4 (crypto.getRandomValues-based)
  category: 'posao' | 'projekti' | 'licno';
  title: string;        // Display name (e.g. "GitHub")
  username: string;     // Username or email
  password: string;     // The credential password
  url: string;          // Website URL
  notes: string;        // Free-form notes
  createdAt: string;    // ISO 8601 timestamp
  updatedAt: string;    // ISO 8601 timestamp
}
```

### VaultSettings

Stored inside the encrypted vault (not in plaintext):

```typescript
interface VaultSettings {
  autoLockMinutes: number;       // Default: 5
  clipboardClearSeconds: number; // Default: 20
}
```

### PlaintextVault

The complete decrypted structure (only exists in RAM while unlocked):

```typescript
interface PlaintextVault {
  items: VaultItem[];
  settings: VaultSettings;
}
```

### Categories

| ID | Display Name | Use Case |
|---|---|---|
| `posao` | Posao | Work-related credentials |
| `projekti` | Projekti | Project-related credentials |
| `licno` | Lično | Personal credentials |

---

## 5. Storage Format

The vault is stored in `localStorage` under the key `secure_vault_blob`.

### Full Structure

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "memory": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "<base64-encoded 16 bytes>"
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "iv": "<base64-encoded 12 bytes>"
  },
  "ciphertext": "<base64-encoded AES-GCM ciphertext + 16-byte auth tag>"
}
```

### Field Reference

| Field | Type | Description |
|---|---|---|
| `version` | `1` | Schema version for future migrations |
| `kdf.algorithm` | `"argon2id"` | Key derivation algorithm identifier |
| `kdf.memory` | `65536` | Argon2 memory parameter in KiB |
| `kdf.iterations` | `3` | Argon2 time parameter |
| `kdf.parallelism` | `1` | Argon2 parallelism parameter |
| `kdf.salt` | base64 string | 16 random bytes, generated once at vault creation |
| `encryption.algorithm` | `"AES-256-GCM"` | Encryption algorithm identifier |
| `encryption.iv` | base64 string | 12 random bytes, re-generated on every save |
| `ciphertext` | base64 string | Encrypted vault JSON + 16-byte GCM authentication tag |

### Storage Lifecycle

```
First run:
  generateSalt() ──► stored in kdf.salt (never changes)

Every save:
  generateIV() ──► new random IV each time
  encryptVault() ──► new ciphertext
  localStorage.setItem('secure_vault_blob', JSON.stringify(blob))

Lock:
  Zustand state cleared (key, vault, salt → null)
  Salt buffer zeroed via zeroMemory()

Unlock:
  kdf.salt read from blob ──► deriveKey(password, salt) ──► decryptVault()
```

---

## 6. Project Structure

```
vault-app/
│
├── app/                          # Next.js App Router
│   ├── layout.tsx                # HTML shell, Inter font, dark mode
│   ├── page.tsx                  # Client-side router (setup/unlock/vault)
│   └── globals.css               # Tailwind base + scrollbar styles
│
├── components/
│   ├── auth/
│   │   ├── SetupPage.tsx         # First-run: create master password
│   │   └── UnlockPage.tsx        # Subsequent logins
│   ├── vault/
│   │   ├── VaultLayout.tsx       # Main app shell (sidebar + content)
│   │   ├── Sidebar.tsx           # Navigation + lock + export
│   │   ├── ItemList.tsx          # Filtered list of vault entries
│   │   ├── EntryModal.tsx        # Create/edit/delete entry modal
│   │   ├── PasswordGenerator.tsx # Inline password generator widget
│   │   └── SettingsPanel.tsx     # Settings, change password, backup
│   └── ui/
│       └── LoadingScreen.tsx     # Initial loading spinner
│
├── hooks/
│   ├── useInactivityLock.ts      # Auto-lock timer
│   └── useClipboard.ts           # Clipboard with auto-clear
│
├── lib/
│   ├── types.ts                  # All TypeScript interfaces
│   ├── crypto.ts                 # Core cryptography functions
│   ├── vaultService.ts           # High-level vault operations
│   └── passwordGenerator.ts     # Cryptographically secure generator
│
├── store/
│   └── vaultStore.ts             # Zustand in-memory state
│
├── out/                          # Static export output (after npm run build)
│   ├── index.html
│   ├── 404.html
│   ├── favicon.ico
│   └── _next/                   # Hashed JS/CSS chunks
│
├── next.config.js                # Static export + argon2-browser webpack alias
├── tsconfig.json                 # Strict TypeScript config
├── tailwind.config.ts            # Tailwind CSS config
└── package.json
```

---

## 7. Module Reference

### `lib/types.ts`

Pure TypeScript type definitions. No runtime code. Imported throughout the application.

**Exports:** `VaultCategory`, `VaultItem`, `VaultSettings`, `PlaintextVault`, `KdfParams`, `EncryptionParams`, `EncryptedVaultBlob`, `PasswordGenOptions`, `ExportPayload`

---

### `lib/crypto.ts`

The cryptographic core of the application. All functions are pure or async-pure — no side effects on external state.

| Function | Signature | Description |
|---|---|---|
| `bufToBase64` | `(buf: ArrayBuffer \| Uint8Array) => string` | Binary-safe buffer to base64 |
| `base64ToBuf` | `(b64: string) => Uint8Array` | Base64 to Uint8Array |
| `zeroMemory` | `(buf: Uint8Array) => void` | Fill array with zeros |
| `generateSalt` | `() => Uint8Array` | 16 CSPRNG bytes |
| `generateIV` | `() => Uint8Array` | 12 CSPRNG bytes |
| `deriveKey` | `(password: string, salt: Uint8Array) => Promise<CryptoKey>` | Argon2id → AES-256-GCM key |
| `encryptVault` | `(vault, key, salt) => Promise<EncryptedVaultBlob>` | Serialize + encrypt vault |
| `decryptVault` | `(blob, key) => Promise<PlaintextVault>` | Decrypt + parse vault |
| `getKdfParams` | `(blob: EncryptedVaultBlob) => KdfParams` | Extract KDF params |
| `validateBlobStructure` | `(obj: unknown) => obj is EncryptedVaultBlob` | Type guard for import validation |

---

### `lib/vaultService.ts`

High-level vault lifecycle operations. Coordinates crypto layer with localStorage.

| Function | Description |
|---|---|
| `hasVault()` | Returns `true` if an encrypted blob exists in localStorage |
| `loadBlob()` | Reads, parses, and validates the blob from localStorage |
| `createVault(password)` | First-run: generate salt, derive key, encrypt default vault, persist |
| `unlockVault(password)` | Read stored salt, derive key, decrypt vault, return both |
| `saveVault(vault, key, salt)` | Re-encrypt with existing key/salt, persist new blob |
| `lockVault(salt)` | Zero the salt buffer (key is zeroed by the store) |
| `exportVault()` | Return raw encrypted JSON string from localStorage |
| `importVault(json)` | Validate and overwrite local vault with new encrypted blob |
| `deleteVault()` | Remove vault from localStorage |
| `addItem(vault, item)` | Pure function — returns new vault with item appended |
| `updateItem(vault, item)` | Pure function — returns new vault with item replaced |
| `deleteItem(vault, id)` | Pure function — returns new vault with item removed |
| `updateSettings(vault, settings)` | Pure function — returns new vault with settings updated |
| `changePassword(vault, newPassword)` | Generate new salt, re-derive key, re-encrypt, return new material |
| `triggerDownload(json, filename)` | Create blob URL and programmatically trigger file download |

---

### `lib/passwordGenerator.ts`

Generates random passwords using only `crypto.getRandomValues`.

| Function | Description |
|---|---|
| `generatePassword(options)` | Generate a password with specified character sets and length |

**Algorithm:**
1. Build charset from enabled options (uppercase, lowercase, digits, symbols)
2. Guarantee at least one character from each enabled set (pick one from each)
3. Fill remaining positions from the full charset
4. Apply Fisher-Yates shuffle using `crypto.getRandomValues` with rejection sampling

**Rejection sampling** ensures uniform distribution — if a random value falls outside the largest multiple of the charset length that fits in a `uint32`, it is discarded and a new value is drawn. This eliminates modulo bias.

---

### `store/vaultStore.ts`

Zustand store. **Nothing in this store persists to any storage.** All state lives only in JavaScript heap memory and is wiped on lock or page reload.

**State:**

| Field | Type | Description |
|---|---|---|
| `isUnlocked` | `boolean` | Whether vault is currently decrypted and accessible |
| `isFirstRun` | `boolean` | Whether this is the initial setup |
| `cryptoKey` | `CryptoKey \| null` | Non-extractable AES-256-GCM key |
| `salt` | `Uint8Array \| null` | Argon2 salt (needed to re-encrypt on save) |
| `vault` | `PlaintextVault \| null` | Decrypted vault (in RAM only) |
| `isSaving` | `boolean` | Async save in progress |
| `saveError` | `string \| null` | Last save error message |

**Actions:**

| Action | Description |
|---|---|
| `unlock(key, vault, salt)` | Set all crypto material and decrypted vault in memory |
| `lock()` | Zero salt buffer, null all sensitive fields |
| `addVaultItem(item)` | Add item, update in-memory vault, re-encrypt and save |
| `updateVaultItem(item)` | Update item, update in-memory vault, re-encrypt and save |
| `deleteVaultItem(id)` | Remove item, update in-memory vault, re-encrypt and save |
| `saveSettings(settings)` | Update settings, re-encrypt and save |
| `updateCryptoMaterial(key, salt)` | Used after password change |

---

## 8. State Management

### Application States

```
                    ┌─────────────┐
          mounted   │             │
  ──────────────────►  LOADING    │
                    │             │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
     no vault │                  vault exists
              ▼                         ▼
       ┌─────────────┐          ┌─────────────┐
       │             │          │             │
       │    SETUP    │          │   UNLOCK    │
       │  (SetupPage)│          │ (UnlockPage)│
       │             │          │             │
       └──────┬──────┘          └──────┬──────┘
              │                        │
    createVault()              unlockVault()
              │                        │
              └────────────┬───────────┘
                           │
                           ▼
                   ┌─────────────┐
                   │             │
                   │    VAULT    │
                   │ (VaultLayout│
                   │  + sidebar) │
                   │             │
                   └──────┬──────┘
                          │
            ┌─────────────┼─────────────┐
            │             │             │
      inactivity     tab hidden    window blur /
       timeout        (hidden)      beforeunload
            │             │             │
            └─────────────┴─────────────┘
                          │
                       lock()
                          │
                          ▼
                   Back to UNLOCK
```

---

## 9. Auto-Lock System

**File:** `hooks/useInactivityLock.ts`

The vault automatically locks itself under four conditions:

| Trigger | Event | Behavior |
|---|---|---|
| Inactivity | No user input for N minutes | Calls `lock()` after timeout |
| Tab hidden | `document.visibilitychange` (hidden) | Immediate lock |
| Window blur | `window.blur` | Immediate lock |
| Page unload | `window.beforeunload` | Lock before page closes |

**Activity events that reset the inactivity timer:**
- `mousemove`
- `mousedown`
- `keydown`
- `touchstart`
- `scroll`
- `click`

**Configurable:** The auto-lock duration is read from `vault.settings.autoLockMinutes`. Default is 5 minutes. Changing it in Settings takes effect immediately on the next activity.

**Implementation note:** The hook is mounted inside `VaultLayout` and is only active while `isUnlocked === true`. It cleans up all event listeners on unmount.

---

## 10. Clipboard Security

**File:** `hooks/useClipboard.ts`

When a password is copied to clipboard:

1. `navigator.clipboard.writeText(password)` is called
2. A countdown timer starts (default: 20 seconds)
3. The UI shows "Copied! Clipboard clears in Ns"
4. After N seconds: `navigator.clipboard.writeText('')` clears the clipboard
5. If the user copies a new password before the timer expires, the old timer is cancelled

The clear delay is configurable in Settings via `vault.settings.clipboardClearSeconds`.

**Fallback:** If `navigator.clipboard` is unavailable (e.g. HTTP context), a `textarea` + `document.execCommand('copy')` fallback is used. The clear attempt is still made via `navigator.clipboard.writeText('')` (best-effort).

---

## 11. Password Generator

**File:** `lib/passwordGenerator.ts`, `components/vault/PasswordGenerator.tsx`

### Options

| Option | Default | Character Set |
|---|---|---|
| Uppercase | ✅ | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| Lowercase | ✅ | `abcdefghijklmnopqrstuvwxyz` |
| Digits | ✅ | `0123456789` |
| Symbols | ✅ | `!@#$%^&*()_+-=[]{}|;:,.<>?` |
| Length | 20 | 4–128 characters |

### Algorithm (Cryptographically Secure)

```
1. Build charset from enabled options
2. For each enabled option: pick one guaranteed character
   └─► pickRandom(charset) uses crypto.getRandomValues + rejection sampling
3. Fill remaining (length - guaranteedCount) positions from full charset
4. Fisher-Yates shuffle the entire pool using crypto.getRandomValues
5. Return joined string
```

**Rejection sampling** in `pickRandom`:
```typescript
const max = Math.floor(0x100000000 / charset.length) * charset.length;
do {
  crypto.getRandomValues(buf);
  rand = buf[0];
} while (rand >= max);
return charset[rand % charset.length];
```
This eliminates modulo bias — every character in the charset has exactly equal probability.

---

## 12. Import / Export

### Export

- **What:** The raw encrypted JSON blob from localStorage
- **What it contains:** Only the encrypted ciphertext — no plaintext, no keys
- **Format:** `.json` file
- **Security:** The exported file requires your master password to be useful. It is safe to store in cloud backup.
- **Trigger:** Sidebar "Export Backup" button or Settings → "Export Encrypted Backup"
- **Filename:** `vault-backup-YYYY-MM-DD.json`

### Import

- **What:** Accepts a previously exported `.json` file
- **Validation:** `validateBlobStructure()` checks `version`, `kdf.algorithm`, `encryption.algorithm`, and all required fields
- **Effect:** Overwrites the current vault in localStorage and immediately locks the app
- **Why it locks:** The imported vault was encrypted with a (possibly different) master password. You must re-unlock with the correct password for the imported vault.
- **Danger zone:** There is a warning in the UI — importing is irreversible without another backup.

### Migrate to Another Device

1. On Device A: Settings → Export Encrypted Backup → save the `.json` file
2. Transfer the file to Device B (USB, email, cloud, etc.)
3. On Device B: Open Vault → Settings → Import Vault Backup → select the file
4. Vault locks — unlock with the same master password used on Device A

---

## 13. UI Components

### `SetupPage`

Shown on first run (no vault in localStorage).

- Master password input with show/hide toggle
- Confirm password input
- **Strength meter:** scores password on length ≥12, length ≥16, has uppercase, has digit, has symbol (0–4 scale)
- Validation: minimum 8 characters, passwords must match
- Warning banner about no recovery
- On submit: `createVault(password)` → `unlock(key, vault, salt)` → redirects to vault

### `UnlockPage`

Shown when a vault exists but is locked.

- Single password input
- On submit: `unlockVault(password)` — runs Argon2id + AES-GCM decryption
- Loading state: "Unlocking..." spinner during key derivation
- Error: Wrong password shows generic "Incorrect password" (never reveals internal error details)
- Password field is cleared on every attempt (success or failure)

### `VaultLayout`

Main shell. Mounts `useInactivityLock` hook. Composed of:
- `Sidebar` (left)
- `ItemList` or `SettingsPanel` (right), swapped by `activeView` state

### `Sidebar`

Navigation:
- All Items (shows total count)
- Posao / Projekti / Lično (shows per-category count)
- Settings
- Export Backup (bottom)
- Lock Vault (bottom, red)

### `ItemList`

- Search bar (filters title, username, URL)
- Filtered list of entries
- Per-item actions (hover to reveal):
  - 👁 Show/hide password inline
  - 📋 Copy password with countdown
- "Add" button opens `EntryModal` in create mode
- Click any item opens `EntryModal` in edit mode

### `EntryModal`

Full CRUD for vault entries.

**Fields:** Title (required), Category (toggle buttons), Username/Email, Password (with show/hide + copy), URL, Notes (textarea)

**Features:**
- Inline `PasswordGenerator` widget (toggle with "Generate" link)
- Copy password button with clipboard countdown
- Timestamps shown in edit mode (Created / Updated)
- Delete with two-step confirmation (click Delete → confirm dialog appears)
- Keyboard: `Escape` closes the modal
- Click outside modal closes it

### `PasswordGenerator`

Inline widget inside `EntryModal`.

- Length slider (4–128)
- Toggle buttons for each character set
- "Generate" button → shows the generated password
- Copy button with auto-clear countdown
- "Use This" button → fills the password field in the parent modal

### `SettingsPanel`

Three sections:

**Auto-Lock:**
- Slider: 1–60 minutes
- Slider: 5–120 seconds clipboard clear
- "Save Settings" button (re-encrypts vault with new settings)

**Change Master Password:**
- New password + confirm
- Generates new random salt, re-derives key, re-encrypts entire vault
- Does NOT lock the vault — stays unlocked with new material

**Backup & Restore:**
- Export button
- Import button (file picker, `.json` only)
- Import warning banner
- Success/error feedback

---

## 14. Build & Deployment

### Prerequisites

- Node.js 18+
- npm 9+

### Development

```bash
cd vault-app
npm run dev
# Open http://localhost:3000
```

### Production Build

```bash
npm run build
```

Output: `vault-app/out/` directory containing static HTML/CSS/JS.

### Type Check (without building)

```bash
npm run typecheck
```

### Deploy to Hostinger

1. Run `npm run build` locally
2. Open Hostinger → File Manager → `public_html/`
3. Upload **all contents** of `vault-app/out/` into `public_html/`
4. Your vault is live at your domain root

**Deploy to a subdirectory** (e.g. `yourdomain.com/vault/`):

Add to `next.config.js`:
```js
basePath: '/vault',
```
Then rebuild and upload `out/` contents into `public_html/vault/`.

### What NOT to upload

| Folder/File | Reason |
|---|---|
| `node_modules/` | Dev dependencies — never goes to production |
| `.next/` | Build cache — not the export output |
| `vault-app/` root | Source code — not needed on server |
| `.env*` files | Not used, but don't expose anyway |

### Webpack Note: argon2-browser

The standard `argon2-browser` entry point (`lib/argon2.js`) dynamically loads the WASM binary via `require('../dist/argon2.wasm')`. Webpack converts this to an asset URL string, which causes `atob(url)` to throw.

**Fix applied in `next.config.js`:**

```js
config.resolve.alias = {
  'argon2-browser': require.resolve('argon2-browser/dist/argon2-bundled.min.js'),
};
```

The bundled version has the WASM embedded as base64 directly in the JS — no external file loading needed at runtime.

---

## 15. Dependencies

### Runtime

| Package | Version | Purpose |
|---|---|---|
| `next` | 14.x | Framework, static export, App Router |
| `react` / `react-dom` | 18.x | UI layer |
| `argon2-browser` | 1.x | Argon2id key derivation (WASM) |
| `zustand` | 5.x | Lightweight in-memory state management |
| `uuid` | 13.x | UUID v4 generation for item IDs |
| `lucide-react` | latest | SVG icon components |
| `tailwindcss` | 3.x | Utility-first CSS |

### Dev Only

| Package | Purpose |
|---|---|
| `typescript` | Type checking |
| `@types/uuid` | TypeScript types for uuid |
| `@types/argon2-browser` | TypeScript types for argon2-browser |
| `@types/react` / `@types/node` | TypeScript DOM/Node types |
| `eslint` / `eslint-config-next` | Linting |
| `postcss` | Tailwind CSS processing |

### No Extra Crypto Libraries

The application intentionally uses **no third-party cryptography libraries** beyond argon2-browser. All symmetric encryption, key import, and randomness use the browser's built-in **WebCrypto API** (`window.crypto.subtle`).

---

## 16. Security Threat Model

### Threats Mitigated

| Threat | Mitigation |
|---|---|
| Server breach | No server — nothing to breach |
| Database leak | No database — nothing to leak |
| Network interception | No network requests after page load |
| Weak password hashing | Argon2id (64 MB memory cost) |
| Rainbow table attack | Random 16-byte salt per vault |
| Ciphertext tampering | AES-GCM auth tag — decryption throws on tamper |
| Master password in logs | No logging of any vault-related data |
| Master password in storage | Never written — only in RAM during key derivation |
| Clipboard exposure | Auto-clear after configurable timeout |
| Session hijacking | Vault re-locks on tab switch and window blur |
| Inactivity exposure | Auto-lock after configurable inactivity period |
| XSS-based data theft | No `dangerouslySetInnerHTML`, React escapes all output |
| Modulo bias in password gen | Rejection sampling with `crypto.getRandomValues` |
| Weak exported backup | Export = encrypted blob, requires master password to decrypt |

### Threats NOT Mitigated

| Threat | Reason |
|---|---|
| Compromised browser extensions | Extensions can read DOM and intercept clipboard — use a clean browser profile |
| Physical device access with unlocked vault | If someone sits at your unlocked computer, the vault is visible |
| Keylogger | If malware logs keystrokes, the master password is captured during unlock |
| Browser memory dump | `zeroMemory()` is best-effort — GC timing is not guaranteed |
| Forgotten master password | By design — zero-knowledge means zero recovery |
| Browser localStorage cleared | Vault data would be lost — always keep an export backup |
| XSS via compromised CDN | This app has no CDN dependencies after initial load, but if Next.js chunks are served from a compromised host, all bets are off |

---

## 17. Known Limitations

1. **Single device** — Vault exists only in the browser's `localStorage` on the device where it was created. It does not sync across devices. Use Export/Import to migrate.

2. **Single browser** — Each browser (Chrome, Firefox, Safari) has its own `localStorage`. A vault created in Chrome is not visible in Firefox on the same machine.

3. **localStorage cleared** — Browsers can clear `localStorage` when disk space is low, or if the user clears browsing data. Keep regular encrypted backups.

4. **No recovery** — If you forget your master password, your data is permanently inaccessible. There is no "forgot password" flow by design.

5. **Argon2 WASM startup** — The first unlock after a cold page load takes 2–5 seconds while Argon2id processes the 64 MB memory cost. This is intentional and normal.

6. **HTTP context** — `navigator.clipboard.writeText` requires a secure context (HTTPS). On HTTP, the copy button falls back to `document.execCommand('copy')`, and clipboard clearing may not work.

7. **No password history** — Previous passwords for an entry are not stored.

8. **No TOTP / 2FA fields** — The vault stores only passwords, not TOTP secrets (though you could paste a TOTP seed into the Notes field).

9. **Safari private mode** — Safari may restrict or quota `localStorage` in Private Browsing mode, causing save failures.

---

## 18. FAQ

**Q: Can I use this on my phone?**
Yes. The app is a responsive web app. Open it in your mobile browser. Auto-lock will trigger when you switch apps (tab hidden / blur events).

**Q: What happens if I clear my browser data?**
Your vault (the encrypted blob in `localStorage`) will be deleted. The data is unrecoverable without a backup. Always export a backup after making changes.

**Q: Is the exported file safe to store in Dropbox/Google Drive?**
Yes. The exported file is the same encrypted blob — it requires your master password to decrypt. Without the password, it is cryptographically unreadable. 64 MB of Argon2id memory cost makes brute force extremely expensive.

**Q: Can I change my master password?**
Yes. Settings → Change Master Password. This generates a new random salt, re-derives the key with Argon2id, and re-encrypts the entire vault. Your existing entries are preserved.

**Q: What does "Lock Vault" do exactly?**
It calls `lock()` in the Zustand store, which:
1. Zeroes the `salt` Uint8Array with `zeroMemory()`
2. Sets `cryptoKey`, `salt`, and `vault` to `null` in React state
3. The JavaScript garbage collector will eventually reclaim the memory

The encrypted blob in `localStorage` is untouched — it stays there so you can unlock again.

**Q: Why does unlocking take a few seconds?**
Argon2id is intentionally slow. It uses 64 MB of RAM and runs 3 iterations. This makes brute-force attacks impractical — an attacker testing millions of passwords per second on a GPU would be slowed to a few per second by the memory cost.

**Q: Why can't I see my vault data in DevTools → Application → Local Storage?**
You can see the **encrypted blob** (the `secure_vault_blob` key), but it contains only base64-encoded ciphertext. Without the master password and Argon2id key derivation, the ciphertext is meaningless.

**Q: Does this app make any network requests?**
Only to load the initial static assets (HTML, JS, CSS) from the host. After that, nothing. You can disconnect from the internet and the app will continue working normally.

**Q: What if I import a vault backup but use the wrong password to unlock?**
The decryption will fail with "Incorrect password." The imported vault blob is still intact in `localStorage` — you can try again with the correct password.

**Q: Can two people share one vault?**
No. The vault is single-user by design. If you want to share credentials, export the backup, share the file, and share the master password through a secure channel (not email).
