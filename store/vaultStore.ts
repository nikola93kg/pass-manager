// ============================================================
// VAULT STORE (Zustand)
// In-memory only. Nothing here persists to storage.
// On lock: key and vault are wiped from memory.
// ============================================================

import { create } from 'zustand';
import type { PlaintextVault, VaultItem, VaultSettings } from '@/lib/types';
import {
  saveVault,
  lockVault,
  addItem,
  updateItem,
  deleteItem,
  updateSettings,
} from '@/lib/vaultService';

interface VaultState {
  // Auth state
  isUnlocked: boolean;
  isFirstRun: boolean;

  // Crypto — non-extractable key in memory only
  cryptoKey: CryptoKey | null;
  salt: Uint8Array | null;

  // Decrypted vault — in memory only
  vault: PlaintextVault | null;

  // UI state
  isSaving: boolean;
  saveError: string | null;

  // Actions
  setFirstRun: (value: boolean) => void;
  unlock: (key: CryptoKey, vault: PlaintextVault, salt: Uint8Array) => void;
  lock: () => void;
  clearSaveError: () => void;
  saveCurrentVault: () => Promise<void>;
  addVaultItem: (item: VaultItem) => Promise<void>;
  updateVaultItem: (item: VaultItem) => Promise<void>;
  deleteVaultItem: (id: string) => Promise<void>;
  saveSettings: (settings: VaultSettings) => Promise<void>;
  replaceVault: (vault: PlaintextVault) => void;
  updateCryptoMaterial: (key: CryptoKey, salt: Uint8Array) => void;
}

export const useVaultStore = create<VaultState>((set, get) => ({
  isUnlocked: false,
  isFirstRun: false,
  cryptoKey: null,
  salt: null,
  vault: null,
  isSaving: false,
  saveError: null,

  setFirstRun: (value) => set({ isFirstRun: value }),

  clearSaveError: () => set({ saveError: null }),

  unlock: (key, vault, salt) => {
    set({
      isUnlocked: true,
      cryptoKey: key,
      vault,
      salt,
      saveError: null,
    });
  },

  lock: () => {
    const { salt } = get();
    // Zero the salt buffer if it exists
    if (salt) {
      lockVault(salt);
    }
    // Clear all sensitive state
    set({
      isUnlocked: false,
      cryptoKey: null,
      salt: null,
      vault: null,
      saveError: null,
    });
  },

  saveCurrentVault: async () => {
    const { vault, cryptoKey, salt } = get();
    if (!vault || !cryptoKey || !salt) return;
    set({ isSaving: true, saveError: null });
    try {
      await saveVault(vault, cryptoKey, salt);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Save failed.';
      set({ saveError: message });
      throw err;
    } finally {
      set({ isSaving: false });
    }
  },

  addVaultItem: async (item) => {
    const { vault, cryptoKey, salt } = get();
    if (!vault || !cryptoKey || !salt) return;
    const previous = vault;
    const updated = addItem(vault, item);
    set({ vault: updated, isSaving: true, saveError: null });
    try {
      await saveVault(updated, cryptoKey, salt);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Save failed.';
      set({ vault: previous, saveError: message });
      throw err;
    } finally {
      set({ isSaving: false });
    }
  },

  updateVaultItem: async (item) => {
    const { vault, cryptoKey, salt } = get();
    if (!vault || !cryptoKey || !salt) return;
    const previous = vault;
    const updated = updateItem(vault, item);
    set({ vault: updated, isSaving: true, saveError: null });
    try {
      await saveVault(updated, cryptoKey, salt);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Save failed.';
      set({ vault: previous, saveError: message });
      throw err;
    } finally {
      set({ isSaving: false });
    }
  },

  deleteVaultItem: async (id) => {
    const { vault, cryptoKey, salt } = get();
    if (!vault || !cryptoKey || !salt) return;
    const previous = vault;
    const updated = deleteItem(vault, id);
    set({ vault: updated, isSaving: true, saveError: null });
    try {
      await saveVault(updated, cryptoKey, salt);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Save failed.';
      set({ vault: previous, saveError: message });
      throw err;
    } finally {
      set({ isSaving: false });
    }
  },

  saveSettings: async (settings) => {
    const { vault, cryptoKey, salt } = get();
    if (!vault || !cryptoKey || !salt) return;
    const previous = vault;
    const updated = updateSettings(vault, settings);
    set({ vault: updated, isSaving: true, saveError: null });
    try {
      await saveVault(updated, cryptoKey, salt);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Save failed.';
      set({ vault: previous, saveError: message });
      throw err;
    } finally {
      set({ isSaving: false });
    }
  },

  replaceVault: (vault) => set({ vault }),

  updateCryptoMaterial: (key, salt) => {
    const { salt: prevSalt } = get();
    if (prevSalt && prevSalt !== salt) {
      lockVault(prevSalt);
    }
    set({ cryptoKey: key, salt });
  },
}));
