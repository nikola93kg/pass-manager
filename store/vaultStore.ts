// ============================================================
// VAULT STORE (Zustand) — NMark Pass Vault v2
// - In-memory only: plaintext vault & CryptoKey never persist.
// - Serialized async write queue: eliminates concurrent save races.
// - Revision-aware optimistic concurrency for multi-tab & cloud sync.
// - Tracks unsaved changes, sync status, and conflict recovery state.
// ============================================================

import { create } from 'zustand';
import type {
  PlaintextVault,
  VaultItem,
  VaultSettings,
  SyncMode,
  SyncStatus,
  VaultConflict,
  EncryptedVaultBlob,
  EncryptedVaultBlobV2,
} from '@/lib/types';
import {
  saveVault,
  lockVault,
  addItem,
  updateItem,
  deleteItem,
  updateSettings,
  createRecoverySnapshot,
  persistBlob,
  VaultRevisionConflictError,
} from '@/lib/vaultService';
import { getBlobRevision } from '@/lib/crypto';
import { pushCloudVault, CloudSyncConflictError } from '@/lib/cloudSync';
import { broadcastTabMessage } from '@/lib/tabSync';

// Module-level serialized FIFO write queue so concurrent mutations
// never race or overwrite newer ciphertext out of order.
let writeQueueTail: Promise<unknown> = Promise.resolve();

function enqueueSerializedWrite<T>(task: () => Promise<T>): Promise<T> {
  const run = writeQueueTail.then(task, task);
  writeQueueTail = run.then(
    () => undefined,
    () => undefined
  );
  return run;
}

export function resetWriteQueueForTests(): void {
  writeQueueTail = Promise.resolve();
}

interface VaultState {
  // Auth / lock state
  isUnlocked: boolean;
  isFirstRun: boolean;

  // Crypto — non-extractable key & salt in memory only
  cryptoKey: CryptoKey | null;
  salt: Uint8Array | null;

  // Decrypted vault & concurrency metadata — in memory only
  vault: PlaintextVault | null;
  revision: number;
  lastSavedAt: string | null;

  // Sync & durability state
  syncMode: SyncMode;
  syncStatus: SyncStatus;
  hasUnsavedChanges: boolean;
  isSaving: boolean;
  saveError: string | null;
  conflict: VaultConflict | null;
  migratedFromV1: boolean;

  // Deep link target (Client Hub integration)
  pendingDeepLinkItemId: string | null;

  // Actions
  setFirstRun: (value: boolean) => void;
  setSyncMode: (mode: SyncMode) => void;
  setPendingDeepLinkItemId: (id: string | null) => void;
  clearSaveError: () => void;
  clearMigrationNotice: () => void;
  reportExternalConflict: (conflict: VaultConflict) => void;
  dismissConflict: () => void;

  unlock: (
    key: CryptoKey,
    vault: PlaintextVault,
    salt: Uint8Array,
    revision?: number,
    options?: { migratedFromV1?: boolean }
  ) => void;
  lock: (options?: { broadcast?: boolean }) => void;

  addVaultItem: (item: VaultItem) => Promise<void>;
  updateVaultItem: (item: VaultItem) => Promise<void>;
  deleteVaultItem: (id: string) => Promise<void>;
  saveSettings: (settings: VaultSettings) => Promise<void>;
  retrySave: () => Promise<void>;
  resolveConflictKeepLocal: () => Promise<void>;
  resolveConflictAcceptRemote: (remoteVault: PlaintextVault, remoteBlob: EncryptedVaultBlob) => void;
  updateCryptoMaterial: (key: CryptoKey, salt: Uint8Array, revision?: number, syncedBlob?: EncryptedVaultBlobV2) => Promise<void>;
}

export const useVaultStore = create<VaultState>((set, get) => {
  async function persistMutation(
    mutate: (current: PlaintextVault) => PlaintextVault,
    options?: { forceLocal?: boolean; overrideExpectedRevision?: number }
  ): Promise<void> {
    return enqueueSerializedWrite(async () => {
      const state = get();
      if (!state.vault || !state.cryptoKey || !state.salt || !state.isUnlocked) {
        throw new Error('Vault is locked.');
      }

      const expectedRevision = options?.overrideExpectedRevision ?? state.revision;
      const nextRevision = expectedRevision + 1;
      const nextVault = mutate(state.vault);

      // Update UI optimistically for responsiveness, marking dirty until durable
      set({
        vault: nextVault,
        isSaving: true,
        syncStatus: 'saving',
        hasUnsavedChanges: true,
        saveError: null,
      });

      let encryptedBlob: EncryptedVaultBlobV2;
      try {
        encryptedBlob = await saveVault(nextVault, state.cryptoKey, state.salt, {
          expectedRevision,
          nextRevision,
          force: options?.forceLocal,
        });
      } catch (err: unknown) {
        if (err instanceof VaultRevisionConflictError) {
          set({
            isSaving: false,
            syncStatus: 'conflict',
            hasUnsavedChanges: true,
            saveError: err.message,
            conflict: {
              source: 'tab',
              localRevision: expectedRevision,
              remoteRevision: err.actualRevision,
              remoteBlob: err.storedBlob,
              detectedAt: new Date().toISOString(),
            },
          });
          throw err;
        }

        const message = err instanceof Error ? err.message : 'Failed to persist vault locally.';
        // Roll back in-memory state if local persistence failed cleanly
        set({
          vault: state.vault,
          isSaving: false,
          syncStatus: 'error',
          hasUnsavedChanges: false,
          saveError: message,
        });
        throw err;
      }

      // Notify sibling tabs of the new local revision
      broadcastTabMessage({ type: 'VAULT_REVISION_UPDATED', revision: nextRevision });

      // Push encrypted blob to cloud if cloud sync is active
      if (get().syncMode === 'cloud') {
        try {
          const cloudRes = await pushCloudVault(encryptedBlob, expectedRevision);
          set({
            revision: cloudRes.revision,
            lastSavedAt: cloudRes.updatedAt,
            isSaving: false,
            syncStatus: 'synced',
            hasUnsavedChanges: false,
            saveError: null,
            conflict: null,
          });
          return;
        } catch (err: unknown) {
          if (err instanceof CloudSyncConflictError) {
            set({
              revision: nextRevision,
              isSaving: false,
              syncStatus: 'conflict',
              hasUnsavedChanges: true,
              saveError: err.message,
              conflict: {
                source: 'cloud',
                localRevision: expectedRevision,
                remoteRevision: err.remoteRevision,
                remoteBlob: err.remoteBlob,
                detectedAt: new Date().toISOString(),
              },
            });
            throw err;
          }

          // Local write succeeded, cloud sync failed (e.g., offline) — keep local state and mark unsynced
          const message =
            err instanceof Error ? err.message : 'Saved locally, but cloud sync failed.';
          set({
            revision: nextRevision,
            lastSavedAt: encryptedBlob.updatedAt,
            isSaving: false,
            syncStatus: 'offline_local',
            hasUnsavedChanges: true,
            saveError: message,
          });
          return;
        }
      }

      // Local-only mode succeeded
      set({
        revision: nextRevision,
        lastSavedAt: encryptedBlob.updatedAt,
        isSaving: false,
        syncStatus: 'synced',
        hasUnsavedChanges: false,
        saveError: null,
        conflict: null,
      });
    });
  }

  return {
    isUnlocked: false,
    isFirstRun: false,
    cryptoKey: null,
    salt: null,
    vault: null,
    revision: 0,
    lastSavedAt: null,
    syncMode: 'local',
    syncStatus: 'idle',
    hasUnsavedChanges: false,
    isSaving: false,
    saveError: null,
    conflict: null,
    migratedFromV1: false,
    pendingDeepLinkItemId: null,

    setFirstRun: (value) => set({ isFirstRun: value }),
    setSyncMode: (mode) => set({ syncMode: mode }),
    setPendingDeepLinkItemId: (id) => set({ pendingDeepLinkItemId: id }),
    clearSaveError: () => set({ saveError: null }),
    clearMigrationNotice: () => set({ migratedFromV1: false }),
    reportExternalConflict: (conflict) =>
      set({
        conflict,
        syncStatus: 'conflict',
        saveError:
          conflict.source === 'tab'
            ? `Another tab updated the vault to revision ${conflict.remoteRevision}.`
            : `Cloud vault is at revision ${conflict.remoteRevision}.`,
      }),
    dismissConflict: () => set({ conflict: null }),

    unlock: (key, vault, salt, revision = 1, options) => {
      set({
        isUnlocked: true,
        cryptoKey: key,
        vault,
        salt,
        revision,
        lastSavedAt: new Date().toISOString(),
        syncStatus: 'synced',
        hasUnsavedChanges: false,
        saveError: null,
        conflict: null,
        migratedFromV1: options?.migratedFromV1 ?? false,
      });
    },

    lock: (options) => {
      const { salt } = get();
      if (salt) {
        lockVault(salt);
      }
      if (options?.broadcast !== false) {
        broadcastTabMessage({ type: 'LOCK_VAULT' });
      }
      set({
        isUnlocked: false,
        cryptoKey: null,
        salt: null,
        vault: null,
        revision: 0,
        isSaving: false,
        syncStatus: 'idle',
        hasUnsavedChanges: false,
        saveError: null,
        conflict: null,
      });
    },

    addVaultItem: (item) => persistMutation((v) => addItem(v, item)),
    updateVaultItem: (item) => persistMutation((v) => updateItem(v, item)),
    deleteVaultItem: (id) => persistMutation((v) => deleteItem(v, id)),
    saveSettings: (settings) => persistMutation((v) => updateSettings(v, settings)),

    retrySave: () => persistMutation((v) => v),

    resolveConflictKeepLocal: async () => {
      const { conflict } = get();
      if (!conflict) return;
      // Save remote version as an encrypted recovery snapshot before superseding it
      createRecoverySnapshot('manual', conflict.remoteBlob);
      await persistMutation((v) => v, {
        forceLocal: true,
        overrideExpectedRevision: conflict.remoteRevision,
      });
    },

    resolveConflictAcceptRemote: (remoteVault, remoteBlob) => {
      // Save current local version as encrypted recovery snapshot before replacing
      createRecoverySnapshot('manual');
      persistBlob(remoteBlob, { force: true });
      const rev = getBlobRevision(remoteBlob);
      set({
        vault: remoteVault,
        revision: rev,
        lastSavedAt: new Date().toISOString(),
        syncStatus: 'synced',
        hasUnsavedChanges: false,
        saveError: null,
        conflict: null,
      });
    },

    updateCryptoMaterial: async (key, salt, revision, syncedBlob) => {
      const { salt: prevSalt, syncMode, revision: currentRevision } = get();
      const targetRev = revision ?? currentRevision;
      if (prevSalt && prevSalt !== salt) {
        lockVault(prevSalt);
      }
      set({ cryptoKey: key, salt, revision: targetRev });

      if (syncMode === 'cloud' && syncedBlob) {
        try {
          const res = await pushCloudVault(syncedBlob, currentRevision);
          set({
            revision: res.revision,
            lastSavedAt: res.updatedAt,
            syncStatus: 'synced',
            hasUnsavedChanges: false,
            saveError: null,
          });
        } catch (err: unknown) {
          set({
            syncStatus: 'offline_local',
            hasUnsavedChanges: true,
            saveError:
              err instanceof Error
                ? err.message
                : 'Password updated locally, but cloud sync failed.',
          });
        }
      }
    },
  };
});
