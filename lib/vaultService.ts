// ============================================================
// VAULT SERVICE — NMark Pass Vault v2
// High-level vault operations: create, unlock, lock, save,
// export, verified import, recovery snapshots, and safe reset.
//
// INVARIANT: Plaintext credentials NEVER touch localStorage.
// ============================================================

import {
  deriveKey,
  encryptVault,
  decryptVault,
  generateSalt,
  base64ToBuf,
  validateBlobStructure,
  parseEncryptedBlobJson,
  getBlobRevision,
  zeroMemory,
  ARGON2_MEMORY,
  ARGON2_ITER,
  ARGON2_PARALLEL,
} from './crypto';
import { generateVaultItemId } from './urlSafety';
import type {
  PlaintextVault,
  EncryptedVaultBlob,
  EncryptedVaultBlobV2,
  VaultItem,
  VaultSettings,
  RecoverySnapshot,
} from './types';

export const VAULT_STORAGE_KEY = 'secure_vault_blob';
export const RECOVERY_SNAPSHOTS_KEY = 'secure_vault_recovery_snapshots';
export const DEVICE_ID_KEY = 'secure_vault_device_id';
const MAX_RECOVERY_SNAPSHOTS = 5;

// ----------------------------------------------------------
// Optimistic Concurrency Error for localStorage writes
// ----------------------------------------------------------

export class VaultRevisionConflictError extends Error {
  readonly expectedRevision: number;
  readonly actualRevision: number;
  readonly storedBlob: EncryptedVaultBlob;

  constructor(
    expectedRevision: number,
    actualRevision: number,
    storedBlob: EncryptedVaultBlob
  ) {
    super(
      `Vault was modified in another tab (expected revision ${expectedRevision}, found ${actualRevision}).`
    );
    this.name = 'VaultRevisionConflictError';
    this.expectedRevision = expectedRevision;
    this.actualRevision = actualRevision;
    this.storedBlob = storedBlob;
  }
}

// ----------------------------------------------------------
// Device ID (opaque random identifier per browser profile)
// ----------------------------------------------------------

export function getOrCreateDeviceId(): string {
  if (typeof window === 'undefined') return 'server';
  try {
    const existing = localStorage.getItem(DEVICE_ID_KEY);
    if (existing && existing.length >= 8 && existing.length <= 128) {
      return existing;
    }
    const created = generateVaultItemId();
    localStorage.setItem(DEVICE_ID_KEY, created);
    return created;
  } catch {
    return generateVaultItemId();
  }
}

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
      autoHidePasswordSeconds: 30,
    },
  };
}

// ----------------------------------------------------------
// Local Storage Blob Access
// ----------------------------------------------------------

export function hasVault(): boolean {
  if (typeof window === 'undefined') return false;
  return loadBlob() !== null;
}

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

export function persistBlob(
  blob: EncryptedVaultBlob,
  options?: { expectedRevision?: number; force?: boolean }
): void {
  if (!validateBlobStructure(blob)) {
    throw new Error('Refusing to persist invalid encrypted vault blob.');
  }

  if (!options?.force && options?.expectedRevision !== undefined) {
    const current = loadBlob();
    if (current) {
      const currentRev = getBlobRevision(current);
      if (currentRev !== options.expectedRevision) {
        throw new VaultRevisionConflictError(
          options.expectedRevision,
          currentRev,
          current
        );
      }
    }
  }

  localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(blob));
}

// ----------------------------------------------------------
// Encrypted Recovery Snapshots (never stores plaintext)
// ----------------------------------------------------------

export function listRecoverySnapshots(): RecoverySnapshot[] {
  if (typeof window === 'undefined') return [];
  const raw = localStorage.getItem(RECOVERY_SNAPSHOTS_KEY);
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (s): s is RecoverySnapshot =>
        typeof s === 'object' &&
        s !== null &&
        typeof (s as RecoverySnapshot).createdAt === 'string' &&
        typeof (s as RecoverySnapshot).reason === 'string' &&
        validateBlobStructure((s as RecoverySnapshot).blob)
    );
  } catch {
    return [];
  }
}

export function createRecoverySnapshot(
  reason: RecoverySnapshot['reason'],
  explicitBlob?: EncryptedVaultBlob
): RecoverySnapshot | null {
  if (typeof window === 'undefined') return null;
  const blob = explicitBlob ?? loadBlob();
  if (!blob || !validateBlobStructure(blob)) return null;

  const snapshot: RecoverySnapshot = {
    createdAt: new Date().toISOString(),
    reason,
    blob,
  };

  const existing = listRecoverySnapshots();
  const updated = [snapshot, ...existing].slice(0, MAX_RECOVERY_SNAPSHOTS);
  try {
    localStorage.setItem(RECOVERY_SNAPSHOTS_KEY, JSON.stringify(updated));
  } catch {
    // If storage is tight, try saving just the latest snapshot
    try {
      localStorage.setItem(RECOVERY_SNAPSHOTS_KEY, JSON.stringify([snapshot]));
    } catch {
      // Best-effort; don't block primary vault save
    }
  }
  return snapshot;
}

export function clearRecoverySnapshots(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(RECOVERY_SNAPSHOTS_KEY);
}

// ----------------------------------------------------------
// createVault — First-run vault creation (Envelope v2, rev 1)
// ----------------------------------------------------------

export async function createVault(masterPassword: string): Promise<{
  key: CryptoKey;
  vault: PlaintextVault;
  salt: Uint8Array;
  revision: number;
  blob: EncryptedVaultBlobV2;
}> {
  const salt = generateSalt();
  const key = await deriveKey(masterPassword, salt);
  const vault = defaultVault();
  const revision = 1;
  const blob = await encryptVault(vault, key, salt, {
    revision,
    updatedByDevice: getOrCreateDeviceId(),
  });
  persistBlob(blob, { force: true });
  return { key, vault, salt, revision, blob };
}

// ----------------------------------------------------------
// unlockVault — Supports both v1 (auto-migrates safely to v2) & v2
// ----------------------------------------------------------

export async function unlockVault(
  masterPassword: string,
  explicitBlob?: EncryptedVaultBlob
): Promise<{
  key: CryptoKey;
  vault: PlaintextVault;
  salt: Uint8Array;
  revision: number;
  blob: EncryptedVaultBlob;
  migratedFromV1: boolean;
}> {
  const blob = explicitBlob ?? loadBlob();
  if (!blob) throw new Error('No vault found.');

  const salt = base64ToBuf(blob.kdf.salt);
  let key: CryptoKey;
  let vault: PlaintextVault;

  try {
    key = await deriveKey(masterPassword, salt, {
      memory: blob.kdf.memory,
      iterations: blob.kdf.iterations,
      parallelism: blob.kdf.parallelism,
    });
    vault = await decryptVault(blob, key);
  } catch (err) {
    zeroMemory(salt);
    throw err;
  }

  // Transparent, safe v1 -> v2 upgrade (preserves encrypted v1 recovery snapshot first)
  if (blob.version === 1 && !explicitBlob) {
    createRecoverySnapshot('v1_migration', blob);
    const upgradedBlob = await encryptVault(vault, key, salt, {
      revision: 1,
      updatedByDevice: getOrCreateDeviceId(),
      kdfParams: {
        memory: blob.kdf.memory,
        iterations: blob.kdf.iterations,
        parallelism: blob.kdf.parallelism,
      },
    });
    persistBlob(upgradedBlob, { force: true });
    return {
      key,
      vault,
      salt,
      revision: 1,
      blob: upgradedBlob,
      migratedFromV1: true,
    };
  }

  return {
    key,
    vault,
    salt,
    revision: getBlobRevision(blob),
    blob,
    migratedFromV1: false,
  };
}

// ----------------------------------------------------------
// verifyMasterPassword — Verify password decrypts current blob
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
// saveVault — Re-encrypt as v2 with incremented revision + OCC
// ----------------------------------------------------------

export async function saveVault(
  vault: PlaintextVault,
  key: CryptoKey,
  salt: Uint8Array,
  options?: {
    expectedRevision?: number;
    nextRevision?: number;
    force?: boolean;
  }
): Promise<EncryptedVaultBlobV2> {
  const expectedRevision = options?.expectedRevision;
  const nextRevision =
    options?.nextRevision ?? (expectedRevision !== undefined ? expectedRevision + 1 : 1);

  const blob = await encryptVault(vault, key, salt, {
    revision: nextRevision,
    updatedByDevice: getOrCreateDeviceId(),
  });

  persistBlob(blob, {
    expectedRevision,
    force: options?.force,
  });

  return blob;
}

// ----------------------------------------------------------
// lockVault — Zero temporary salt buffer (best-effort)
// ----------------------------------------------------------

export function lockVault(salt: Uint8Array | null | undefined): void {
  zeroMemory(salt);
}

// ----------------------------------------------------------
// exportVault — Return raw encrypted blob JSON (NEVER plaintext)
// ----------------------------------------------------------

export function exportVault(): string | null {
  if (typeof window === 'undefined') return null;
  const blob = loadBlob();
  if (!blob) return null;
  return JSON.stringify(blob, null, 2);
}

// ----------------------------------------------------------
// Verified Import Flow — NEVER destroys an existing vault if
// validation or decryption fails.
// ----------------------------------------------------------

export interface VerifiedBackupResult {
  sourceVersion: 1 | 2;
  blob: EncryptedVaultBlob;
  vault: PlaintextVault;
  key: CryptoKey;
  salt: Uint8Array;
  itemCount: number;
}

export async function verifyBackupImport(
  jsonString: string,
  backupMasterPassword: string
): Promise<VerifiedBackupResult> {
  const parsed = parseEncryptedBlobJson(jsonString);
  const salt = base64ToBuf(parsed.kdf.salt);

  try {
    const key = await deriveKey(backupMasterPassword, salt, {
      memory: parsed.kdf.memory,
      iterations: parsed.kdf.iterations,
      parallelism: parsed.kdf.parallelism,
    });
    const vault = await decryptVault(parsed, key);
    return {
      sourceVersion: parsed.version,
      blob: parsed,
      vault,
      key,
      salt,
      itemCount: vault.items.length,
    };
  } catch (err) {
    zeroMemory(salt);
    throw err;
  }
}

export async function commitVerifiedBackupImport(
  verified: VerifiedBackupResult,
  options?: { nextRevision?: number }
): Promise<{
  blob: EncryptedVaultBlobV2;
  revision: number;
}> {
  // Always snapshot the current valid vault before overwriting
  createRecoverySnapshot('import');

  const current = loadBlob();
  const baseRevision = Math.max(
    current ? getBlobRevision(current) : 0,
    getBlobRevision(verified.blob)
  );
  const nextRevision = options?.nextRevision ?? baseRevision + 1;

  // Persist in hardened v2 format while preserving the verified key & salt
  const upgraded = await encryptVault(verified.vault, verified.key, verified.salt, {
    revision: nextRevision,
    updatedByDevice: getOrCreateDeviceId(),
    kdfParams: {
      memory: verified.blob.kdf.memory,
      iterations: verified.blob.kdf.iterations,
      parallelism: verified.blob.kdf.parallelism,
    },
  });

  persistBlob(upgraded, { force: true });
  return { blob: upgraded, revision: nextRevision };
}

/**
 * Restore a previously saved encrypted recovery snapshot after verifying its password.
 */
export async function restoreRecoverySnapshot(
  snapshot: RecoverySnapshot,
  masterPassword: string
): Promise<{
  key: CryptoKey;
  vault: PlaintextVault;
  salt: Uint8Array;
  blob: EncryptedVaultBlobV2;
  revision: number;
}> {
  const verified = await verifyBackupImport(JSON.stringify(snapshot.blob), masterPassword);
  const { blob, revision } = await commitVerifiedBackupImport(verified);
  return {
    key: verified.key,
    vault: verified.vault,
    salt: verified.salt,
    blob,
    revision,
  };
}

// ----------------------------------------------------------
// Safe Reset — Creates recovery snapshot before wiping active vault
// ----------------------------------------------------------

export function safeResetVault(): RecoverySnapshot | null {
  if (typeof window === 'undefined') return null;
  const snapshot = createRecoverySnapshot('reset');
  localStorage.removeItem(VAULT_STORAGE_KEY);
  return snapshot;
}

export function deleteVault(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(VAULT_STORAGE_KEY);
}

// ----------------------------------------------------------
// Pure Vault Mutations (operate on in-memory PlaintextVault only)
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
// triggerDownload — Helper for encrypted backup export
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
// changePassword — Re-encrypt vault with fresh salt, new Argon2id key,
// and incremented revision. Creates encrypted recovery snapshot first.
// ----------------------------------------------------------

export async function changePassword(
  vault: PlaintextVault,
  newMasterPassword: string,
  expectedRevision?: number
): Promise<{
  key: CryptoKey;
  salt: Uint8Array;
  blob: EncryptedVaultBlobV2;
  revision: number;
}> {
  createRecoverySnapshot('password_change');

  const current = loadBlob();
  const baseRevision = expectedRevision ?? (current ? getBlobRevision(current) : 0);
  const nextRevision = baseRevision + 1;

  const newSalt = generateSalt();
  const newKey = await deriveKey(newMasterPassword, newSalt, {
    memory: ARGON2_MEMORY,
    iterations: ARGON2_ITER,
    parallelism: ARGON2_PARALLEL,
  });

  const blob = await encryptVault(vault, newKey, newSalt, {
    revision: nextRevision,
    updatedByDevice: getOrCreateDeviceId(),
  });

  persistBlob(blob, {
    expectedRevision: current ? getBlobRevision(current) : undefined,
  });

  return { key: newKey, salt: newSalt, blob, revision: nextRevision };
}
