// ============================================================
// VAULT SERVICE
// High-level vault operations: create, unlock, lock, save,
// export, import. Coordinates crypto layer with localStorage.
// INVARIANT: plaintext NEVER written to any persistent store.
// ============================================================

import {
  deriveKey,
  encryptVault,
  decryptVault,
  generateSalt,
  base64ToBuf,
  validateBlobStructure,
  zeroMemory,
} from './crypto';
import type {
  PlaintextVault,
  EncryptedVaultBlob,
  VaultItem,
  VaultSettings,
} from './types';

export const VAULT_STORAGE_KEY = 'secure_vault_blob';

// ----------------------------------------------------------
// Default vault structure for first-run
// ----------------------------------------------------------

export function defaultVault(): PlaintextVault {
  return {
    items: [],
    settings: {
      autoLockMinutes: 5,
      clipboardClearSeconds: 20,
      lockOnBlur: false,
    },
  };
}

// ----------------------------------------------------------
// hasVault — check if an encrypted blob exists in storage
// ----------------------------------------------------------

export function hasVault(): boolean {
  if (typeof window === 'undefined') return false;
  return localStorage.getItem(VAULT_STORAGE_KEY) !== null;
}

// ----------------------------------------------------------
// loadBlob — read and parse the stored encrypted blob
// ----------------------------------------------------------

export function loadBlob(): EncryptedVaultBlob | null {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem(VAULT_STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!validateBlobStructure(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

// ----------------------------------------------------------
// persistBlob — store encrypted blob (no plaintext ever here)
// ----------------------------------------------------------

function persistBlob(blob: EncryptedVaultBlob): void {
  localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(blob));
}

// ----------------------------------------------------------
// createVault — first-run: derive key from new master password,
// encrypt default vault, persist blob, return key + vault.
// ----------------------------------------------------------

export async function createVault(masterPassword: string): Promise<{
  key: CryptoKey;
  vault: PlaintextVault;
  salt: Uint8Array;
}> {
  const salt = generateSalt();
  const key = await deriveKey(masterPassword, salt);
  const vault = defaultVault();
  const blob = await encryptVault(vault, key, salt);
  persistBlob(blob);
  return { key, vault, salt };
}

// ----------------------------------------------------------
// unlockVault — derive key from password + stored salt/KDF params,
// decrypt and return the vault in memory.
// ----------------------------------------------------------

export async function unlockVault(masterPassword: string): Promise<{
  key: CryptoKey;
  vault: PlaintextVault;
  salt: Uint8Array;
}> {
  const blob = loadBlob();
  if (!blob) throw new Error('No vault found.');

  const salt = base64ToBuf(blob.kdf.salt);
  const key = await deriveKey(masterPassword, salt, {
    memory: blob.kdf.memory,
    iterations: blob.kdf.iterations,
    parallelism: blob.kdf.parallelism,
  });
  const vault = await decryptVault(blob, key);

  return { key, vault, salt };
}

// ----------------------------------------------------------
// verifyMasterPassword — check if password decrypts stored blob
// ----------------------------------------------------------

export async function verifyMasterPassword(masterPassword: string): Promise<boolean> {
  const blob = loadBlob();
  if (!blob) return false;

  const salt = base64ToBuf(blob.kdf.salt);
  try {
    const key = await deriveKey(masterPassword, salt, {
      memory: blob.kdf.memory,
      iterations: blob.kdf.iterations,
      parallelism: blob.kdf.parallelism,
    });
    await decryptVault(blob, key);
    return true;
  } catch {
    return false;
  } finally {
    zeroMemory(salt);
  }
}

// ----------------------------------------------------------
// saveVault — re-encrypt vault with current key and same salt,
// persist updated blob. Salt is preserved across saves.
// ----------------------------------------------------------

export async function saveVault(
  vault: PlaintextVault,
  key: CryptoKey,
  salt: Uint8Array
): Promise<void> {
  const blob = await encryptVault(vault, key, salt);
  persistBlob(blob);
}

// ----------------------------------------------------------
// lockVault — zero the salt buffer (key zeroed by store)
// ----------------------------------------------------------

export function lockVault(salt: Uint8Array): void {
  zeroMemory(salt);
}

// ----------------------------------------------------------
// exportVault — return the raw encrypted blob JSON string.
// NEVER exports plaintext.
// ----------------------------------------------------------

export function exportVault(): string | null {
  if (typeof window === 'undefined') return null;
  const raw = localStorage.getItem(VAULT_STORAGE_KEY);
  if (!raw) return null;
  // Validate it parses correctly before export
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!validateBlobStructure(parsed)) return null;
    return raw;
  } catch {
    return null;
  }
}

// ----------------------------------------------------------
// importVault — validate and overwrite local vault with
// the provided encrypted blob. Plaintext is never exposed.
// ----------------------------------------------------------

export function importVault(jsonString: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonString);
  } catch {
    throw new Error('Invalid file: not valid JSON.');
  }

  if (!validateBlobStructure(parsed)) {
    throw new Error('Invalid vault file: structure or version mismatch.');
  }

  // Safe: only storing encrypted blob
  localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(parsed));
}

// ----------------------------------------------------------
// deleteVault — wipe vault from storage (dangerous!)
// ----------------------------------------------------------

export function deleteVault(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(VAULT_STORAGE_KEY);
}

// ----------------------------------------------------------
// addItem / updateItem / deleteItem — vault mutations
// (operate on in-memory PlaintextVault only)
// ----------------------------------------------------------

export function addItem(vault: PlaintextVault, item: VaultItem): PlaintextVault {
  return { ...vault, items: [...vault.items, item] };
}

export function updateItem(vault: PlaintextVault, updated: VaultItem): PlaintextVault {
  return {
    ...vault,
    items: vault.items.map((i) => (i.id === updated.id ? updated : i)),
  };
}

export function deleteItem(vault: PlaintextVault, id: string): PlaintextVault {
  return { ...vault, items: vault.items.filter((i) => i.id !== id) };
}

export function updateSettings(
  vault: PlaintextVault,
  settings: VaultSettings
): PlaintextVault {
  return { ...vault, settings };
}

// ----------------------------------------------------------
// triggerDownload — helper for export
// ----------------------------------------------------------

export function triggerDownload(json: string, filename: string): void {
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ----------------------------------------------------------
// getSaltFromBlob — retrieve current salt for re-encryption
// ----------------------------------------------------------

export function getSaltFromBlob(): Uint8Array | null {
  const blob = loadBlob();
  if (!blob) return null;
  return base64ToBuf(blob.kdf.salt);
}

// ----------------------------------------------------------
// changePassword — re-encrypt vault with new master password
// ----------------------------------------------------------

export async function changePassword(
  vault: PlaintextVault,
  newMasterPassword: string
): Promise<{ key: CryptoKey; salt: Uint8Array }> {
  const newSalt = generateSalt();
  const newKey = await deriveKey(newMasterPassword, newSalt);
  const blob = await encryptVault(vault, newKey, newSalt);
  persistBlob(blob);
  return { key: newKey, salt: newSalt };
}
