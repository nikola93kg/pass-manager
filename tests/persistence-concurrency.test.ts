import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  createVault,
  loadBlob,
  persistBlob,
  listRecoverySnapshots,
  VAULT_STORAGE_KEY,
  VaultRevisionConflictError,
} from '@/lib/vaultService';
import { encryptVault, decryptVault, getBlobRevision } from '@/lib/crypto';
import { useVaultStore, resetWriteQueueForTests } from '@/store/vaultStore';
import type { VaultItem } from '@/lib/types';

function makeItem(n: number): VaultItem {
  return {
    id: `item-uuid-0000-0000-00000000000${n}`,
    category: 'projekti',
    title: `Service ${n}`,
    username: `user${n}@nmarkdesigns.com`,
    password: `SecretPass#${n}!`,
    url: `https://service${n}.example.com`,
    notes: '',
    tags: [`tag-${n}`],
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
}

describe('Vault Persistence, Serialized Concurrency, Multi-Tab & Cloud Conflicts', () => {
  beforeEach(() => {
    localStorage.clear();
    resetWriteQueueForTests();
    useVaultStore.getState().lock({ broadcast: false });
    useVaultStore.getState().setSyncMode('local');
    vi.restoreAllMocks();
  });

  it('serializes rapid concurrent updates without losing any writes or corrupting revisions', async () => {
    const created = await createVault('ConcurrentMaster!2026');
    useVaultStore.getState().unlock(created.key, created.vault, created.salt, created.revision);

    // Fire 6 rapid concurrent mutations simultaneously
    await Promise.all([
      useVaultStore.getState().addVaultItem(makeItem(1)),
      useVaultStore.getState().addVaultItem(makeItem(2)),
      useVaultStore.getState().addVaultItem(makeItem(3)),
      useVaultStore.getState().addVaultItem(makeItem(4)),
      useVaultStore.getState().saveSettings({
        autoLockMinutes: 15,
        clipboardClearSeconds: 30,
        lockOnBlur: true,
        autoHidePasswordSeconds: 20,
      }),
      useVaultStore.getState().updateVaultItem({ ...makeItem(1), title: 'Service 1 Updated' }),
    ]);

    const state = useVaultStore.getState();
    expect(state.revision).toBe(7); // initial 1 + 6 serialized writes
    expect(state.vault?.items).toHaveLength(4);
    expect(state.vault?.items.find((i) => i.id === makeItem(1).id)?.title).toBe(
      'Service 1 Updated'
    );
    expect(state.hasUnsavedChanges).toBe(false);
    expect(state.syncStatus).toBe('synced');

    // Verify persisted encrypted blob in localStorage matches exact final state
    const persisted = loadBlob();
    expect(persisted).not.toBeNull();
    expect(getBlobRevision(persisted!)).toBe(7);
    const decrypted = await decryptVault(persisted!, created.key);
    expect(decrypted.items).toHaveLength(4);
    expect(decrypted.settings.autoLockMinutes).toBe(15);
  });

  it('rolls back cleanly on failed localStorage writes and surfaces saveError', async () => {
    const created = await createVault('RollbackMaster!2026');
    useVaultStore.getState().unlock(created.key, created.vault, created.salt, created.revision);

    const setItemSpy = vi
      .spyOn(Storage.prototype, 'setItem')
      .mockImplementationOnce(() => {
        throw new Error('QuotaExceededError: storage full');
      });

    await expect(useVaultStore.getState().addVaultItem(makeItem(1))).rejects.toThrow(
      /QuotaExceededError/i
    );

    const state = useVaultStore.getState();
    expect(state.vault?.items).toHaveLength(0); // rolled back cleanly
    expect(state.revision).toBe(1);
    expect(state.saveError).toMatch(/QuotaExceededError/i);
    expect(state.syncStatus).toBe('error');

    setItemSpy.mockRestore();

    // Subsequent write succeeds cleanly
    await useVaultStore.getState().addVaultItem(makeItem(2));
    expect(useVaultStore.getState().vault?.items).toHaveLength(1);
    expect(useVaultStore.getState().revision).toBe(2);
    expect(useVaultStore.getState().saveError).toBeNull();
  });

  it('detects stale multi-tab overwrites via optimistic concurrency and prevents silent data loss', async () => {
    const created = await createVault('MultiTabMaster!2026');
    useVaultStore.getState().unlock(created.key, created.vault, created.salt, created.revision);

    // Simulate Tab B writing revision 2 directly to localStorage while Tab A is still on revision 1
    const tabBVault = { ...created.vault, items: [makeItem(9)] };
    const tabBBlob = await encryptVault(tabBVault, created.key, created.salt, { revision: 2 });
    persistBlob(tabBBlob, { force: true });

    // Tab A tries to save based on stale revision 1 -> must fail with conflict, NOT overwrite Tab B!
    await expect(useVaultStore.getState().addVaultItem(makeItem(1))).rejects.toBeInstanceOf(
      VaultRevisionConflictError
    );

    // Tab B's data in localStorage is untouched
    const stillStored = loadBlob()!;
    expect(getBlobRevision(stillStored)).toBe(2);
    const decryptedStored = await decryptVault(stillStored, created.key);
    expect(decryptedStored.items[0].id).toBe(makeItem(9).id);

    // Conflict state is flagged in store
    const state = useVaultStore.getState();
    expect(state.syncStatus).toBe('conflict');
    expect(state.conflict?.source).toBe('tab');
    expect(state.conflict?.remoteRevision).toBe(2);
    expect(state.hasUnsavedChanges).toBe(true);

    // Resolving by keeping local snapshots the remote blob first, then advances to rev 3
    await useVaultStore.getState().resolveConflictKeepLocal();
    expect(useVaultStore.getState().revision).toBe(3);
    expect(useVaultStore.getState().conflict).toBeNull();
    expect(listRecoverySnapshots().length).toBeGreaterThanOrEqual(1);
    expect(localStorage.getItem(VAULT_STORAGE_KEY)).toBeTruthy();
  });

  it('detects cloud sync HTTP 409 conflicts and exposes remote blob for safe recovery', async () => {
    const created = await createVault('CloudConflictMaster!2026');
    useVaultStore.getState().setSyncMode('cloud');
    useVaultStore.getState().unlock(created.key, created.vault, created.salt, created.revision);

    const remoteVault = { ...created.vault, items: [makeItem(8)] };
    const remoteBlob = await encryptVault(remoteVault, created.key, created.salt, { revision: 4 });

    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: 'Sync conflict',
          remoteRevision: 4,
          remoteBlob,
        }),
        { status: 409, headers: { 'Content-Type': 'application/json' } }
      )
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(useVaultStore.getState().addVaultItem(makeItem(1))).rejects.toThrow(
      /Cloud sync conflict/i
    );

    const state = useVaultStore.getState();
    expect(state.syncStatus).toBe('conflict');
    expect(state.conflict?.source).toBe('cloud');
    expect(state.conflict?.remoteRevision).toBe(4);

    // Accept remote revision cleanly
    const decryptedRemote = await decryptVault(remoteBlob, created.key);
    useVaultStore.getState().resolveConflictAcceptRemote(decryptedRemote, remoteBlob);

    expect(useVaultStore.getState().conflict).toBeNull();
    expect(useVaultStore.getState().revision).toBe(4);
    expect(useVaultStore.getState().vault?.items[0].id).toBe(makeItem(8).id);
    expect(listRecoverySnapshots().length).toBeGreaterThanOrEqual(1);
  });
});
