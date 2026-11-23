// ============================================================
// CRYPTO UTILITIES
// AES-256-GCM + Argon2id key derivation via argon2-browser
// All operations are async and use WebCrypto API.
// Master password NEVER leaves this module as plaintext.
// ============================================================

import { hash as argon2Hash, ArgonType } from 'argon2-browser';
import type { KdfParams, EncryptedVaultBlob, PlaintextVault } from './types';

// ----------------------------------------------------------
// Constants
// ----------------------------------------------------------
const ARGON2_MEMORY   = 65536; // 64 MB
const ARGON2_ITER     = 3;
const ARGON2_PARALLEL = 1;
const ARGON2_HASHLEN  = 32;
const AES_IV_BYTES    = 12;
const SALT_BYTES      = 16;

// ----------------------------------------------------------
// Helpers: base64 <-> Uint8Array (no atob/btoa for binary safety)
// ----------------------------------------------------------

export function bufToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBuf(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ----------------------------------------------------------
// zeroMemory — overwrite sensitive byte arrays
// ----------------------------------------------------------

export function zeroMemory(buf: Uint8Array): void {
  buf.fill(0);
}

// ----------------------------------------------------------
// generateSalt — 16 random bytes via CSPRNG
// ----------------------------------------------------------

export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}

// ----------------------------------------------------------
// generateIV — 12 random bytes via CSPRNG
// ----------------------------------------------------------

export function generateIV(): Uint8Array {
  const iv = new Uint8Array(AES_IV_BYTES);
  crypto.getRandomValues(iv);
  return iv;
}

// ----------------------------------------------------------
// deriveKey — Argon2id → CryptoKey (AES-256-GCM)
// Master password is consumed as a string, converted to
// UTF-8 bytes locally, and never persisted or returned.
// ----------------------------------------------------------

export interface KdfDeriveOptions {
  memory?: number;
  iterations?: number;
  parallelism?: number;
}

export async function deriveKey(
  masterPassword: string,
  salt: Uint8Array,
  options?: KdfDeriveOptions
): Promise<CryptoKey> {
  // Encode password to bytes (stays local)
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(masterPassword);

  let hashBytes: Uint8Array;

  try {
    const result = await argon2Hash({
      pass: passwordBytes,
      salt,
      type: ArgonType.Argon2id,
      mem: options?.memory ?? ARGON2_MEMORY,
      time: options?.iterations ?? ARGON2_ITER,
      parallelism: options?.parallelism ?? ARGON2_PARALLEL,
      hashLen: ARGON2_HASHLEN,
    });

    hashBytes = result.hash;
  } finally {
    // Zero password bytes immediately
    zeroMemory(passwordBytes);
  }

  // Import 32-byte hash as non-extractable AES-GCM key
  // Slice to ensure a plain ArrayBuffer (not SharedArrayBuffer) for importKey
  const keyMaterial = hashBytes!.slice().buffer as ArrayBuffer;
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );

  // Zero derived bytes
  zeroMemory(hashBytes!);

  return cryptoKey;
}

// ----------------------------------------------------------
// encryptVault — serialize vault, encrypt with AES-256-GCM
// Returns a complete EncryptedVaultBlob ready for storage.
// ----------------------------------------------------------

export async function encryptVault(
  vault: PlaintextVault,
  key: CryptoKey,
  salt: Uint8Array
): Promise<EncryptedVaultBlob> {
  const iv = generateIV();

  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(vault));

  // Use plain ArrayBuffer slice to avoid SharedArrayBuffer in WebCrypto
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv.slice() },
    key,
    plaintext.slice()
  );

  // Zero plaintext bytes
  zeroMemory(plaintext);

  return {
    version: 1,
    kdf: {
      algorithm: 'argon2id',
      memory: ARGON2_MEMORY,
      iterations: ARGON2_ITER,
      parallelism: ARGON2_PARALLEL,
      salt: bufToBase64(salt),
    },
    encryption: {
      algorithm: 'AES-256-GCM',
      iv: bufToBase64(iv),
    },
    ciphertext: bufToBase64(ciphertextBuf),
  };
}

// ----------------------------------------------------------
// decryptVault — decrypt blob with AES-256-GCM
// Throws if tampered, wrong key, or malformed.
// ----------------------------------------------------------

export async function decryptVault(
  blob: EncryptedVaultBlob,
  key: CryptoKey
): Promise<PlaintextVault> {
  const iv = base64ToBuf(blob.encryption.iv);
  const ciphertext = base64ToBuf(blob.ciphertext);

  let plaintextBuf: ArrayBuffer;
  try {
    plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv.slice() },
      key,
      ciphertext.slice()
    );
  } catch {
    throw new Error('Decryption failed: wrong password or corrupted vault.');
  }

  const decoder = new TextDecoder();
  const jsonStr = decoder.decode(plaintextBuf);

  // Zero plaintext buffer
  zeroMemory(new Uint8Array(plaintextBuf));

  let vault: PlaintextVault;
  try {
    vault = JSON.parse(jsonStr) as PlaintextVault;
  } catch {
    throw new Error('Vault data is corrupted.');
  }

  // Structural validation
  if (!Array.isArray(vault.items) || typeof vault.settings !== 'object') {
    throw new Error('Vault structure is invalid.');
  }

  return vault;
}

// ----------------------------------------------------------
// getKdfParams — extract KDF params from stored blob
// ----------------------------------------------------------

export function getKdfParams(blob: EncryptedVaultBlob): KdfParams {
  return blob.kdf;
}

// ----------------------------------------------------------
// validateBlobStructure — guard for import
// ----------------------------------------------------------

export function validateBlobStructure(obj: unknown): obj is EncryptedVaultBlob {
  if (typeof obj !== 'object' || obj === null) return false;
  const b = obj as Record<string, unknown>;
  if (b['version'] !== 1) return false;
  if (typeof b['kdf'] !== 'object' || b['kdf'] === null) return false;
  if (typeof b['encryption'] !== 'object' || b['encryption'] === null) return false;
  if (typeof b['ciphertext'] !== 'string') return false;
  const kdf = b['kdf'] as Record<string, unknown>;
  if (kdf['algorithm'] !== 'argon2id') return false;
  if (typeof kdf['salt'] !== 'string' || kdf['salt'].length === 0) return false;
  if (
    typeof kdf['memory'] !== 'number' ||
    !Number.isInteger(kdf['memory']) ||
    kdf['memory'] < 1024 ||
    kdf['memory'] > 1048576
  ) {
    return false;
  }
  if (
    typeof kdf['iterations'] !== 'number' ||
    !Number.isInteger(kdf['iterations']) ||
    kdf['iterations'] < 1 ||
    kdf['iterations'] > 100
  ) {
    return false;
  }
  if (
    typeof kdf['parallelism'] !== 'number' ||
    !Number.isInteger(kdf['parallelism']) ||
    kdf['parallelism'] < 1 ||
    kdf['parallelism'] > 16
  ) {
    return false;
  }
  const enc = b['encryption'] as Record<string, unknown>;
  if (enc['algorithm'] !== 'AES-256-GCM') return false;
  if (typeof enc['iv'] !== 'string' || enc['iv'].length === 0) return false;
  return true;
}
