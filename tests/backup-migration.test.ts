import { describe, it, expect, beforeEach } from 'vitest';
import {
  createVault,
  unlockVault,
  exportVault,
  verifyBackupImport,
  commitVerifiedBackupImport,
  listRecoverySnapshots,
  restoreRecoverySnapshot,
  safeResetVault,
  loadBlob,
  persistBlob,
  VAULT_STORAGE_KEY,
} from '@/lib/vaultService';
import {
  deriveKey,
  encryptVaultLegacyV1ForTest,
  generateSalt,
  decryptVault,
} from '@/lib/crypto';
import type { PlaintextVault } from '@/lib/types';

describe('Backup, Verified Import, Version Migration & Recovery Snapshots', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('exports encrypted JSON only and never leaks plaintext credentials', async () => {
    const created = await createVault('ExportMaster!2026');
    const updatedVault: PlaintextVault = {
      ...created.vault,
      items: [
        {
          id: 'item-export-test-0001',
          category: 'posao',
          title: 'AWS Root',
          username: 'root@nmarkdesigns.com',
          password: 'UltraSecretAwsPassword!999',
          url: 'https://console.aws.amazon.com',
          notes: 'Hardware MFA attached',
          tags: ['aws'],
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
    };
    const { saveVault } = await import('@/lib/vaultService');
    await saveVault(updatedVault, created.key, created.salt, {
      expectedRevision: 1,
      nextRevision: 2,
    });

    const exported = exportVault();
    expect(exported).not.toBeNull();
    expect(exported).not.toContain('UltraSecretAwsPassword!999');
    expect(exported).not.toContain('root@nmarkdesigns.com');
    expect(exported).toContain('"version": 2');
  });

  it('never destroys an existing valid vault when importing corrupted, incompatible, or wrong-password backups', async () => {
    await createVault('ExistingVaultPassword!2026');
    const originalRaw = localStorage.getItem(VAULT_STORAGE_KEY);
    expect(originalRaw).toBeTruthy();

    // 1. Corrupted JSON
    await expect(verifyBackupImport('{bad json', 'any')).rejects.toThrow(/malformed JSON/i);
    expect(localStorage.getItem(VAULT_STORAGE_KEY)).toBe(originalRaw);

    // 2. Incompatible version
    await expect(
      verifyBackupImport(JSON.stringify({ version: 99, kdf: {}, encryption: {}, ciphertext: 'aa' }), 'any')
    ).rejects.toThrow(/validation/i);
    expect(localStorage.getItem(VAULT_STORAGE_KEY)).toBe(originalRaw);

    // 3. Valid backup blob but WRONG master password
    const validBackupJson = exportVault()!;
    await expect(
      verifyBackupImport(validBackupJson, 'CompletelyWrongPassword!2026')
    ).rejects.toThrow(/Decryption failed/i);
    expect(localStorage.getItem(VAULT_STORAGE_KEY)).toBe(originalRaw);
  });

  it('verifies backup decryptability, creates recovery snapshot, and restores cleanly', async () => {
    // Create Vault A (backup source)
    const saltA = generateSalt();
    const keyA = await deriveKey('BackupSourcePassword!2026', saltA);
    const backupVault: PlaintextVault = {
      items: [
        {
          id: 'backup-entry-12345678',
          category: 'licno',
          title: 'Restored Entry',
          username: 'nikola@nmarkdesigns.com',
          password: 'RestoredSecret!2026',
          url: 'https://nmarkdesigns.com',
          notes: '',
          tags: ['backup'],
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
      settings: { autoLockMinutes: 7, clipboardClearSeconds: 15, lockOnBlur: false },
    };
    const v1BackupBlob = await encryptVaultLegacyV1ForTest(backupVault, keyA, saltA);

    // Create active Vault B
    await createVault('ActiveVaultPassword!2026');

    // Verify & commit v1 backup into active vault
    const verified = await verifyBackupImport(
      JSON.stringify(v1BackupBlob),
      'BackupSourcePassword!2026'
    );
    expect(verified.sourceVersion).toBe(1);
    expect(verified.itemCount).toBe(1);

    const committed = await commitVerifiedBackupImport(verified);
    expect(committed.blob.version).toBe(2);

    // Previous active Vault B must be preserved in Recovery Snapshots
    const snapshots = listRecoverySnapshots();
    expect(snapshots).toHaveLength(1);
    expect(snapshots[0].reason).toBe('import');

    // Can restore the previous Vault B snapshot using Vault B's password!
    const restoredB = await restoreRecoverySnapshot(
      snapshots[0],
      'ActiveVaultPassword!2026'
    );
    expect(restoredB.vault.items).toHaveLength(0);
  });

  it('transparently migrates an existing v1 localStorage vault to v2 on unlock with a recovery snapshot', async () => {
    const salt = generateSalt();
    const key = await deriveKey('V1MigrationPassword!2026', salt);
    const v1Vault: PlaintextVault = {
      items: [
        {
          id: 'v1-item-99999999',
          category: 'projekti',
          title: 'Client Hosting',
          username: 'admin',
          password: 'LegacyHostPassword!1',
          url: 'https://panel.hostinger.com',
          notes: 'v1 record',
          tags: [],
          createdAt: '2025-10-01T00:00:00.000Z',
          updatedAt: '2025-10-01T00:00:00.000Z',
        },
      ],
      settings: { autoLockMinutes: 5, clipboardClearSeconds: 20 },
    };

    const v1Blob = await encryptVaultLegacyV1ForTest(v1Vault, key, salt);
    persistBlob(v1Blob, { force: true });
    expect(loadBlob()?.version).toBe(1);

    const unlocked = await unlockVault('V1MigrationPassword!2026');
    expect(unlocked.migratedFromV1).toBe(true);
    expect(unlocked.revision).toBe(1);
    expect(unlocked.vault.items[0].title).toBe('Client Hosting');

    // Stored blob is now v2 with AAD and decryptable
    const storedAfter = loadBlob()!;
    expect(storedAfter.version).toBe(2);
    const reDecrypted = await decryptVault(storedAfter, unlocked.key);
    expect(reDecrypted.items[0].password).toBe('LegacyHostPassword!1');

    // Encrypted v1 snapshot preserved
    const snaps = listRecoverySnapshots();
    expect(snaps.some((s) => s.reason === 'v1_migration' && s.blob.version === 1)).toBe(true);
  });

  it('creates an encrypted recovery snapshot on safeResetVault before clearing active vault', async () => {
    await createVault('ResetVaultPassword!2026');
    const snap = safeResetVault();
    expect(snap).not.toBeNull();
    expect(snap?.reason).toBe('reset');
    expect(loadBlob()).toBeNull();
    expect(listRecoverySnapshots()).toHaveLength(1);
  });
});
