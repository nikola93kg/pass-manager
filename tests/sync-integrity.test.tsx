import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import {
  reconcileLocalAndCloudBlobs,
  computeBlobFingerprint,
} from '@/lib/syncReconcile';
import {
  createVault,
  persistBlob,
  loadBlob,
  markLocalUnsynced,
  markCloudSynced,
  VAULT_STORAGE_KEY,
} from '@/lib/vaultService';
import { encryptVault, decryptVault } from '@/lib/crypto';
import VaultApp from '@/components/VaultApp';
import { useVaultStore, resetWriteQueueForTests } from '@/store/vaultStore';
import type { PlaintextVault } from '@/lib/types';

function makeVaultWithTitle(title: string): PlaintextVault {
  return {
    items: [
      {
        id: '33333333-3333-4333-8333-333333333333',
        category: 'posao',
        title,
        username: 'ops@nmarkdesigns.com',
        password: `Pw-${title}!2026`,
        url: 'https://example.com',
        notes: '',
        tags: [],
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
    ],
    settings: { autoLockMinutes: 5, clipboardClearSeconds: 20, lockOnBlur: false },
  };
}

describe('Finding 2 Regression — Unsynced Local Data Protection & Divergence Detection', () => {
  beforeEach(() => {
    localStorage.clear();
    resetWriteQueueForTests();
    useVaultStore.getState().lock({ broadcast: false });
    vi.restoreAllMocks();
  });

  it('detects conflict when local and cloud have EQUAL revision numbers but DIFFERENT ciphertext', async () => {
    const created = await createVault('EqualRevMaster!2026');
    const localBlob = await encryptVault(
      makeVaultWithTitle('Local Offline Edit'),
      created.key,
      created.salt,
      { revision: 5 }
    );
    const cloudBlob = await encryptVault(
      makeVaultWithTitle('Other Device Cloud Edit'),
      created.key,
      created.salt,
      { revision: 5 }
    );

    const res = await reconcileLocalAndCloudBlobs({
      localBlob,
      cloudBlob,
      syncMeta: null,
    });

    expect(res.action).toBe('conflict');
    if (res.action === 'conflict') {
      expect(res.conflict.reason).toBe('equal_revision_diverged');
      expect(res.conflict.localRevision).toBe(5);
      expect(res.conflict.remoteRevision).toBe(5);
    }
  });

  it('detects conflict when local has unsynced changes even if cloud has a HIGHER revision', async () => {
    const created = await createVault('UnsavedLocalMaster!2026');
    const localBlob = await encryptVault(
      makeVaultWithTitle('Unsynced Local Rev 4'),
      created.key,
      created.salt,
      { revision: 4 }
    );
    const cloudBlob = await encryptVault(
      makeVaultWithTitle('Cloud Rev 7'),
      created.key,
      created.salt,
      { revision: 7 }
    );

    const syncMeta = await markLocalUnsynced(localBlob);
    const res = await reconcileLocalAndCloudBlobs({
      localBlob,
      cloudBlob,
      syncMeta,
    });

    expect(res.action).toBe('conflict');
    if (res.action === 'conflict') {
      expect(res.conflict.reason).toBe('unsaved_local_changes');
      expect(res.conflict.localRevision).toBe(4);
      expect(res.conflict.remoteRevision).toBe(7);
    }
  });

  it('detects conflict when local revision is strictly AHEAD of cloud revision', async () => {
    const created = await createVault('LocalAheadMaster!2026');
    const localBlob = await encryptVault(
      makeVaultWithTitle('Local Ahead Rev 8'),
      created.key,
      created.salt,
      { revision: 8 }
    );
    const cloudBlob = await encryptVault(
      makeVaultWithTitle('Older Cloud Rev 6'),
      created.key,
      created.salt,
      { revision: 6 }
    );

    const res = await reconcileLocalAndCloudBlobs({
      localBlob,
      cloudBlob,
      syncMeta: null,
    });

    expect(res.action).toBe('conflict');
    if (res.action === 'conflict') {
      expect(res.conflict.reason).toBe('local_ahead_of_cloud');
    }
  });

  it('fast-forwards cleanly ONLY when local has no unsaved changes and matches last synced fingerprint', async () => {
    const created = await createVault('CleanFastForward!2026');
    const syncedLocal = await encryptVault(
      makeVaultWithTitle('Synced Rev 3'),
      created.key,
      created.salt,
      { revision: 3 }
    );
    const newerCloud = await encryptVault(
      makeVaultWithTitle('Cloud Rev 4'),
      created.key,
      created.salt,
      { revision: 4 }
    );

    const syncMeta = await markCloudSynced(syncedLocal);
    const res = await reconcileLocalAndCloudBlobs({
      localBlob: syncedLocal,
      cloudBlob: newerCloud,
      syncMeta,
    });

    expect(res.action).toBe('fast_forward_cloud');

    // Identical ciphertext reconciles as in_sync
    const sameRes = await reconcileLocalAndCloudBlobs({
      localBlob: newerCloud,
      cloudBlob: newerCloud,
      syncMeta,
    });
    expect(sameRes.action).toBe('in_sync');
    expect(await computeBlobFingerprint(newerCloud)).toHaveLength(64);
  });

  it('VaultApp NEVER overwrites localStorage on equal-revision diverged cloud blob, unlocks local blob, and opens ConflictModal', async () => {
    const masterPw = 'ProtectUnsyncedLocal!2026';
    const created = await createVault(masterPw);

    const localBlob = await encryptVault(
      makeVaultWithTitle('My Unsynced Local Secret'),
      created.key,
      created.salt,
      { revision: 2 }
    );
    const cloudBlob = await encryptVault(
      makeVaultWithTitle('Other Device Cloud Secret'),
      created.key,
      created.salt,
      { revision: 2 }
    );

    persistBlob(localBlob, { force: true });
    const rawLocalBefore = localStorage.getItem(VAULT_STORAGE_KEY);

    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const target = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
      if (target.includes('/api/auth/session')) {
        return new Response(
          JSON.stringify({
            mode: 'cloud',
            step: 'authenticated',
            userEmail: 'admin@nmarkdesigns.com',
            userId: 'admin-uuid-001',
            aal: 'aal2',
            hasTotpFactor: true,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (target.includes('/api/vault') && (!init?.method || init.method === 'GET')) {
        return new Response(
          JSON.stringify({
            exists: true,
            blob: cloudBlob,
            revision: 2,
            updatedAt: cloudBlob.updatedAt,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (target.includes('/api/vault') && init?.method === 'PUT') {
        const body = JSON.parse(String(init.body));
        return new Response(
          JSON.stringify({
            revision: body.blob.revision,
            updatedAt: body.blob.updatedAt,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('{}', { status: 404 });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<VaultApp />);

    // 1. Divergence banner appears on UnlockPage AND localStorage was NOT overwritten!
    await waitFor(() => {
      expect(screen.getByText(/have diverged/i)).toBeInTheDocument();
    });
    expect(localStorage.getItem(VAULT_STORAGE_KEY)).toBe(rawLocalBefore);

    // 2. Unlock with local master password -> opens ConflictModal while showing local vault intact
    fireEvent.change(screen.getByLabelText(/Master Password/i), {
      target: { value: masterPw },
    });
    fireEvent.click(screen.getByRole('button', { name: /Unlock Vault/i }));

    await waitFor(() => {
      expect(screen.getByText(/Cloud Sync Conflict Detected/i)).toBeInTheDocument();
      expect(screen.getByText(/encrypted ciphertexts differ/i)).toBeInTheDocument();
    });

    // Local data is intact in memory
    expect(useVaultStore.getState().vault?.items[0].title).toBe('My Unsynced Local Secret');

    // 3. Resolving by keeping local advances revision monotonically to rev 3 and pushes to cloud
    fireEvent.click(screen.getByRole('button', { name: /Keep My Local Changes/i }));

    await waitFor(() => {
      expect(useVaultStore.getState().conflict).toBeNull();
      expect(useVaultStore.getState().revision).toBe(3);
      expect(useVaultStore.getState().syncStatus).toBe('synced');
    });

    const finalStored = loadBlob()!;
    const finalDecrypted = await decryptVault(finalStored, created.key);
    expect(finalDecrypted.items[0].title).toBe('My Unsynced Local Secret');
  });
});
