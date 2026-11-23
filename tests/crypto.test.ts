import { describe, it, expect } from 'vitest';
import {
  deriveKey,
  encryptVault,
  encryptVaultLegacyV1ForTest,
  decryptVault,
  generateSalt,
  generateIV,
  validateBlobStructure,
  parseEncryptedBlobJson,
  bufToBase64,
  base64ToBuf,
  KDF_LIMITS,
} from '@/lib/crypto';
import { generatePassword } from '@/lib/passwordGenerator';
import type { PlaintextVault, EncryptedVaultBlobV2 } from '@/lib/types';

const SAMPLE_VAULT: PlaintextVault = {
  items: [
    {
      id: '11111111-1111-4111-8111-111111111111',
      category: 'posao',
      title: 'Cloudflare Production',
      username: 'ops@nmarkdesigns.com',
      password: 'S3cur3!Client#Password99',
      url: 'https://dash.cloudflare.com',
      notes: 'Primary DNS account',
      tags: ['dns', 'hosting'],
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    },
  ],
  settings: {
    autoLockMinutes: 5,
    clipboardClearSeconds: 20,
    lockOnBlur: false,
    autoHidePasswordSeconds: 30,
  },
};

describe('Cryptography — AES-256-GCM (AAD) + Argon2id + Envelope Validation', () => {
  it('completes a v2 encryption/decryption round trip with full fidelity', async () => {
    const salt = generateSalt();
    const key = await deriveKey('CorrectHorseBatteryStaple!2026', salt);
    const blob = await encryptVault(SAMPLE_VAULT, key, salt, {
      revision: 3,
      updatedByDevice: 'device-test-1',
    });

    expect(blob.version).toBe(2);
    expect(blob.revision).toBe(3);
    expect(blob.encryption.aadVersion).toBe(1);
    expect(validateBlobStructure(blob)).toBe(true);

    // Ensure ciphertext never leaks plaintext
    expect(blob.ciphertext).not.toContain('S3cur3!Client#Password99');
    expect(blob.ciphertext).not.toContain('Cloudflare');

    const decrypted = await decryptVault(blob, key);
    expect(decrypted).toEqual(SAMPLE_VAULT);
  });

  it('rejects decryption with an incorrect master password', async () => {
    const salt = generateSalt();
    const correctKey = await deriveKey('RightMasterPassword!2026', salt);
    const wrongKey = await deriveKey('WrongMasterPassword!2026', salt);

    const blob = await encryptVault(SAMPLE_VAULT, correctKey, salt, { revision: 1 });
    await expect(decryptVault(blob, wrongKey)).rejects.toThrow(/Decryption failed/i);
  });

  it('detects tampered ciphertext bytes', async () => {
    const salt = generateSalt();
    const key = await deriveKey('MasterPasswordStrong!2026', salt);
    const blob = await encryptVault(SAMPLE_VAULT, key, salt, { revision: 1 });

    const ctBytes = base64ToBuf(blob.ciphertext);
    ctBytes[0] ^= 0xff; // flip bits
    const tampered: EncryptedVaultBlobV2 = {
      ...blob,
      ciphertext: bufToBase64(ctBytes),
    };

    await expect(decryptVault(tampered, key)).rejects.toThrow(/Decryption failed/i);
  });

  it('detects tampered envelope metadata via v2 AES-GCM AAD', async () => {
    const salt = generateSalt();
    const key = await deriveKey('MasterPasswordStrong!2026', salt);
    const blob = await encryptVault(SAMPLE_VAULT, key, salt, { revision: 5 });

    // Tamper revision number in envelope
    const tamperedRev: EncryptedVaultBlobV2 = { ...blob, revision: 99 };
    await expect(decryptVault(tamperedRev, key)).rejects.toThrow(/Decryption failed/i);

    // Tamper KDF iterations in envelope
    const tamperedKdf: EncryptedVaultBlobV2 = {
      ...blob,
      kdf: { ...blob.kdf, iterations: 4 },
    };
    await expect(decryptVault(tamperedKdf, key)).rejects.toThrow(/Decryption failed/i);
  });

  it('decrypts legacy v1 blobs and normalizes missing v2 fields safely', async () => {
    const salt = generateSalt();
    const key = await deriveKey('LegacyV1Password!2026', salt);
    // Simulate v1 item without tags or lockOnBlur
    const v1RawVault = {
      items: [
        {
          id: 'legacy-item-1234',
          category: 'licno',
          title: 'Legacy Entry',
          username: 'legacy@example.com',
          password: 'OldPassword!123',
          url: 'https://example.com',
          notes: '',
          createdAt: '2025-01-01T00:00:00.000Z',
          updatedAt: '2025-01-01T00:00:00.000Z',
        },
      ],
      settings: {
        autoLockMinutes: 10,
        clipboardClearSeconds: 25,
      },
    } as unknown as PlaintextVault;

    const v1Blob = await encryptVaultLegacyV1ForTest(v1RawVault, key, salt);
    expect(v1Blob.version).toBe(1);
    expect(validateBlobStructure(v1Blob)).toBe(true);

    const decrypted = await decryptVault(v1Blob, key);
    expect(decrypted.items).toHaveLength(1);
    expect(decrypted.items[0].tags).toEqual([]);
    expect(decrypted.settings.lockOnBlur).toBe(false);
    expect(decrypted.settings.autoHidePasswordSeconds).toBe(30);
  });

  it('rejects invalid KDF parameters, malformed base64, wrong IV lengths, and oversized payloads before KDF runs', async () => {
    const salt = generateSalt();
    const key = await deriveKey('ValidMasterPassword!2026', salt);
    const valid = await encryptVault(SAMPLE_VAULT, key, salt, { revision: 1 });

    // Memory below minimum floor
    expect(
      validateBlobStructure({ ...valid, kdf: { ...valid.kdf, memory: 512 } })
    ).toBe(false);

    // Memory above DoS cap
    expect(
      validateBlobStructure({
        ...valid,
        kdf: { ...valid.kdf, memory: KDF_LIMITS.MAX_MEMORY_KIB + 1 },
      })
    ).toBe(false);

    // Iterations above DoS cap
    expect(
      validateBlobStructure({ ...valid, kdf: { ...valid.kdf, iterations: 999 } })
    ).toBe(false);

    // Invalid parallelism
    expect(
      validateBlobStructure({ ...valid, kdf: { ...valid.kdf, parallelism: 0 } })
    ).toBe(false);

    // Wrong IV length (16 bytes instead of 12 bytes)
    expect(
      validateBlobStructure({
        ...valid,
        encryption: { ...valid.encryption, iv: bufToBase64(new Uint8Array(16)) },
      })
    ).toBe(false);

    // Too-short ciphertext (< 16-byte GCM tag)
    expect(
      validateBlobStructure({
        ...valid,
        ciphertext: bufToBase64(new Uint8Array(8)),
      })
    ).toBe(false);

    // deriveKey itself rejects out-of-bounds KDF params
    await expect(
      deriveKey('Password!1234', salt, { memory: 128 })
    ).rejects.toThrow(/Invalid KDF memory/i);

    await expect(
      deriveKey('Password!1234', new Uint8Array(4))
    ).rejects.toThrow(/Invalid KDF salt length/i);

    // Oversized JSON rejected
    expect(() => parseEncryptedBlobJson('x'.repeat(5 * 1024 * 1024 + 10))).toThrow(
      /5 MiB/i
    );
  });

  it('generates unique 96-bit IVs across repeated encryptions', async () => {
    const salt = generateSalt();
    const key = await deriveKey('UniqueIvTestPassword!2026', salt);
    const seen = new Set<string>();

    for (let i = 0; i < 40; i++) {
      const iv = generateIV();
      expect(iv.byteLength).toBe(12);
      const blob = await encryptVault(SAMPLE_VAULT, key, salt, { revision: i + 1 });
      expect(seen.has(blob.encryption.iv)).toBe(false);
      seen.add(blob.encryption.iv);
    }
    expect(seen.size).toBe(40);
  });

  it('generates cryptographically strong passwords meeting requested character classes', () => {
    const pw = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      digits: true,
      symbols: true,
    });
    expect(pw.length).toBe(32);
    expect(/[A-Z]/.test(pw)).toBe(true);
    expect(/[a-z]/.test(pw)).toBe(true);
    expect(/[0-9]/.test(pw)).toBe(true);
    expect(/[^A-Za-z0-9]/.test(pw)).toBe(true);
  });
});
