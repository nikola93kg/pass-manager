// ============================================================
// CLOUD / LOCAL ENCRYPTED BLOB RECONCILIATION
// Prevents silent overwrite of unsynced local changes, including
// equal-revision diverged ciphertext and local-ahead states.
// Operates exclusively on encrypted envelopes & SHA-256 digests.
// ============================================================

import { getBlobRevision } from './crypto';
import type {
  EncryptedVaultBlob,
  LocalSyncMetadata,
  VaultConflict,
} from './types';

/**
 * Computes a deterministic, non-sensitive SHA-256 hex digest of an encrypted
 * vault envelope (version, revision, KDF params, salt, IV, ciphertext).
 * Used strictly for divergence detection — never touches plaintext.
 */
export async function computeBlobFingerprint(
  blob: EncryptedVaultBlob
): Promise<string> {
  const canonical = [
    `v=${blob.version}`,
    `rev=${getBlobRevision(blob)}`,
    `kdf=${blob.kdf.algorithm}:${blob.kdf.memory}:${blob.kdf.iterations}:${blob.kdf.parallelism}:${blob.kdf.salt}`,
    `enc=${blob.encryption.algorithm}:${blob.encryption.iv}:${blob.version === 2 ? blob.encryption.aadVersion : 0}`,
    `ct=${blob.ciphertext}`,
  ].join('|');

  const encoded = new TextEncoder().encode(canonical);
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuf), (b) =>
    b.toString(16).padStart(2, '0')
  ).join('');
}

export type ReconcileResult =
  | { action: 'first_run' }
  | { action: 'needs_cloud_migration'; localBlob: EncryptedVaultBlob; localFingerprint: string }
  | { action: 'use_cloud'; cloudBlob: EncryptedVaultBlob; cloudFingerprint: string }
  | { action: 'in_sync'; blob: EncryptedVaultBlob; fingerprint: string }
  | {
      action: 'fast_forward_cloud';
      cloudBlob: EncryptedVaultBlob;
      cloudFingerprint: string;
    }
  | {
      action: 'conflict';
      localBlob: EncryptedVaultBlob;
      localFingerprint: string;
      cloudBlob: EncryptedVaultBlob;
      cloudFingerprint: string;
      conflict: VaultConflict;
    };

/**
 * Pure reconciliation logic deciding how to safely handle localStorage vs.
 * cloud encrypted vault envelopes on startup/session refresh.
 *
 * INVARIANT: Never recommends overwriting unsynced local data or equal-revision
 * diverged ciphertext.
 */
export async function reconcileLocalAndCloudBlobs(params: {
  localBlob: EncryptedVaultBlob | null;
  cloudBlob: EncryptedVaultBlob | null;
  syncMeta: LocalSyncMetadata | null;
}): Promise<ReconcileResult> {
  const { localBlob, cloudBlob, syncMeta } = params;

  if (!localBlob && !cloudBlob) {
    return { action: 'first_run' };
  }

  if (localBlob && !cloudBlob) {
    const localFingerprint = await computeBlobFingerprint(localBlob);
    return { action: 'needs_cloud_migration', localBlob, localFingerprint };
  }

  if (!localBlob && cloudBlob) {
    const cloudFingerprint = await computeBlobFingerprint(cloudBlob);
    return { action: 'use_cloud', cloudBlob, cloudFingerprint };
  }

  // Both local and cloud blobs exist
  const local = localBlob!;
  const cloud = cloudBlob!;
  const [localFingerprint, cloudFingerprint] = await Promise.all([
    computeBlobFingerprint(local),
    computeBlobFingerprint(cloud),
  ]);

  if (localFingerprint === cloudFingerprint) {
    return { action: 'in_sync', blob: cloud, fingerprint: cloudFingerprint };
  }

  const localRev = getBlobRevision(local);
  const cloudRev = getBlobRevision(cloud);
  const hasUnsaved = syncMeta?.hasUnsavedLocalChanges === true;

  // Safe fast-forward ONLY when:
  // 1. Local has NO unsaved local changes, AND
  // 2. Local exactly matches the last known synced cloud fingerprint, AND
  // 3. Cloud is strictly newer (cloudRev > localRev).
  const localMatchesLastSynced =
    syncMeta !== null &&
    !hasUnsaved &&
    syncMeta.lastSyncedFingerprint !== null &&
    syncMeta.lastSyncedFingerprint === localFingerprint;

  if (localMatchesLastSynced && cloudRev > localRev) {
    return {
      action: 'fast_forward_cloud',
      cloudBlob: cloud,
      cloudFingerprint,
    };
  }

  // Otherwise, local and cloud have diverged — surface explicit conflict
  // without overwriting local data!
  let reason: VaultConflict['reason'];
  if (hasUnsaved) {
    reason = 'unsaved_local_changes';
  } else if (localRev === cloudRev) {
    reason = 'equal_revision_diverged';
  } else if (localRev > cloudRev) {
    reason = 'local_ahead_of_cloud';
  } else {
    reason = 'revision_mismatch';
  }

  return {
    action: 'conflict',
    localBlob: local,
    localFingerprint,
    cloudBlob: cloud,
    cloudFingerprint,
    conflict: {
      source: 'cloud',
      localRevision: localRev,
      remoteRevision: cloudRev,
      remoteBlob: cloud,
      detectedAt: new Date().toISOString(),
      reason,
    },
  };
}
