// ============================================================
// CRYPTO UTILITIES — NMark Pass Vault v2
// AES-256-GCM (Web Crypto API) + Argon2id (argon2-browser WASM)
//
// Envelope Versioning:
// - Version 1 (legacy): AES-256-GCM without AAD, no revision field.
//   Supported for backward-compatible decryption and backup import.
// - Version 2 (current): AES-256-GCM with deterministic AAD binding
//   version, revision, KDF params, salt, algorithm, and IV.
//
// Realistic Memory Security Note:
// `zeroMemory()` overwrites temporary Uint8Array buffers on a
// best-effort basis. In JavaScript/V8, immutable strings (such as
// masterPassword, serialized JSON, and React state) and opaque
// WebCrypto CryptoKey handles are managed by the garbage collector
// and cannot be guaranteed zeroized. See SECURITY.md.
// ============================================================

import { hash as argon2Hash, ArgonType } from 'argon2-browser';
import type {
  KdfParams,
  EncryptedVaultBlob,
  EncryptedVaultBlobV1,
  EncryptedVaultBlobV2,
  PlaintextVault,
  VaultCategory,
  VaultItem,
} from './types';

// ----------------------------------------------------------
// Cryptographic Constants & Validation Bounds
// ----------------------------------------------------------
export const ARGON2_MEMORY = 65536; // 64 MiB (KiB)
export const ARGON2_ITER = 3;
export const ARGON2_PARALLEL = 1;
export const ARGON2_HASHLEN = 32; // 256-bit AES key

export const AES_IV_BYTES = 12; // 96-bit NIST AES-GCM nonce
export const AES_GCM_TAG_BYTES = 16; // 128-bit authentication tag
export const SALT_BYTES = 16;

// Hard bounds enforced BEFORE executing expensive Argon2id KDF
export const KDF_LIMITS = {
  MIN_MEMORY_KIB: 16384, // 16 MiB minimum security floor
  MAX_MEMORY_KIB: 262144, // 256 MiB DoS cap
  MIN_ITERATIONS: 1,
  MAX_ITERATIONS: 20,
  MIN_PARALLELISM: 1,
  MAX_PARALLELISM: 8,
  MIN_SALT_BYTES: 16,
  MAX_SALT_BYTES: 64,
} as const;

export const MAX_VAULT_JSON_BYTES = 5 * 1024 * 1024; // 5 MiB raw JSON cap
export const MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024; // 4 MiB decoded ciphertext cap

const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const VALID_CATEGORIES = new Set<VaultCategory>(['posao', 'projekti', 'licno']);

// ----------------------------------------------------------
// Base64 <-> Uint8Array (chunked for large vaults, strict decode)
// ----------------------------------------------------------

export function bufToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const CHUNK_SIZE = 0x8000;
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    let str = '';
    for (let j = 0; j < chunk.length; j++) {
      str += String.fromCharCode(chunk[j]);
    }
    parts.push(str);
  }
  return btoa(parts.join(''));
}

export function base64ToBuf(b64: string): Uint8Array {
  if (typeof b64 !== 'string' || b64.length === 0 || b64.length % 4 !== 0 || !BASE64_REGEX.test(b64)) {
    throw new Error('Invalid base64 encoding.');
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ----------------------------------------------------------
// Best-effort byte buffer zeroing
// ----------------------------------------------------------

export function zeroMemory(buf: Uint8Array | null | undefined): void {
  if (buf) {
    buf.fill(0);
  }
}

// ----------------------------------------------------------
// CSPRNG Salt & IV Generation
// ----------------------------------------------------------

export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}

export function generateIV(): Uint8Array {
  const iv = new Uint8Array(AES_IV_BYTES);
  crypto.getRandomValues(iv);
  return iv;
}

// ----------------------------------------------------------
// Canonical AAD for Envelope Format v2
// Binds version, revision, KDF params, salt, and IV to GCM tag.
// ----------------------------------------------------------

export function buildVaultAadV2(params: {
  revision: number;
  kdf: KdfParams;
  iv: string;
}): Uint8Array {
  const canonical = [
    'nmark-pass-vault:v2:aad1',
    `rev=${params.revision}`,
    `kdf=${params.kdf.algorithm}:${params.kdf.memory}:${params.kdf.iterations}:${params.kdf.parallelism}:${params.kdf.salt}`,
    `enc=AES-256-GCM:${params.iv}`,
  ].join('|');
  return new TextEncoder().encode(canonical);
}

// ----------------------------------------------------------
// KDF Parameter Validation
// ----------------------------------------------------------

export interface KdfDeriveOptions {
  memory?: number;
  iterations?: number;
  parallelism?: number;
}

export function validateKdfParams(kdf: {
  memory: number;
  iterations: number;
  parallelism: number;
  saltBytesLength?: number;
}): void {
  if (
    !Number.isInteger(kdf.memory) ||
    kdf.memory < KDF_LIMITS.MIN_MEMORY_KIB ||
    kdf.memory > KDF_LIMITS.MAX_MEMORY_KIB
  ) {
    throw new Error(
      `Invalid KDF memory parameter (allowed: ${KDF_LIMITS.MIN_MEMORY_KIB}–${KDF_LIMITS.MAX_MEMORY_KIB} KiB).`
    );
  }
  if (
    !Number.isInteger(kdf.iterations) ||
    kdf.iterations < KDF_LIMITS.MIN_ITERATIONS ||
    kdf.iterations > KDF_LIMITS.MAX_ITERATIONS
  ) {
    throw new Error(
      `Invalid KDF iterations parameter (allowed: ${KDF_LIMITS.MIN_ITERATIONS}–${KDF_LIMITS.MAX_ITERATIONS}).`
    );
  }
  if (
    !Number.isInteger(kdf.parallelism) ||
    kdf.parallelism < KDF_LIMITS.MIN_PARALLELISM ||
    kdf.parallelism > KDF_LIMITS.MAX_PARALLELISM
  ) {
    throw new Error(
      `Invalid KDF parallelism parameter (allowed: ${KDF_LIMITS.MIN_PARALLELISM}–${KDF_LIMITS.MAX_PARALLELISM}).`
    );
  }
  if (
    kdf.saltBytesLength !== undefined &&
    (kdf.saltBytesLength < KDF_LIMITS.MIN_SALT_BYTES ||
      kdf.saltBytesLength > KDF_LIMITS.MAX_SALT_BYTES)
  ) {
    throw new Error(
      `Invalid KDF salt length (allowed: ${KDF_LIMITS.MIN_SALT_BYTES}–${KDF_LIMITS.MAX_SALT_BYTES} bytes).`
    );
  }
}

// ----------------------------------------------------------
// deriveKey — Argon2id -> non-extractable AES-256-GCM CryptoKey
// ----------------------------------------------------------

export async function deriveKey(
  masterPassword: string,
  salt: Uint8Array,
  options?: KdfDeriveOptions
): Promise<CryptoKey> {
  if (!masterPassword) {
    throw new Error('Master password is required.');
  }

  const memory = options?.memory ?? ARGON2_MEMORY;
  const iterations = options?.iterations ?? ARGON2_ITER;
  const parallelism = options?.parallelism ?? ARGON2_PARALLEL;

  validateKdfParams({
    memory,
    iterations,
    parallelism,
    saltBytesLength: salt.byteLength,
  });

  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(masterPassword);
  let hashBytes: Uint8Array | null = null;
  let keyMaterial: Uint8Array | null = null;

  try {
    const result = await argon2Hash({
      pass: passwordBytes,
      salt,
      type: ArgonType.Argon2id,
      mem: memory,
      time: iterations,
      parallelism,
      hashLen: ARGON2_HASHLEN,
    });

    hashBytes = result.hash;
    // Copy into a dedicated plain ArrayBuffer-backed Uint8Array for WebCrypto importKey
    keyMaterial = new Uint8Array(hashBytes.byteLength);
    keyMaterial.set(hashBytes);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial.buffer as ArrayBuffer,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['encrypt', 'decrypt']
    );

    return cryptoKey;
  } finally {
    zeroMemory(passwordBytes);
    zeroMemory(hashBytes);
    zeroMemory(keyMaterial);
  }
}

// ----------------------------------------------------------
// Vault Normalization (ensures v1 decrypted vaults get v2 defaults)
// ----------------------------------------------------------

export function normalizePlaintextVault(raw: unknown): PlaintextVault {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Vault structure is invalid.');
  }
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj.items) || typeof obj.settings !== 'object' || obj.settings === null) {
    throw new Error('Vault structure is invalid.');
  }

  const rawSettings = obj.settings as Record<string, unknown>;
  const autoLockMinutes =
    typeof rawSettings.autoLockMinutes === 'number' &&
    Number.isFinite(rawSettings.autoLockMinutes) &&
    rawSettings.autoLockMinutes >= 1 &&
    rawSettings.autoLockMinutes <= 120
      ? Math.round(rawSettings.autoLockMinutes)
      : 5;

  const clipboardClearSeconds =
    typeof rawSettings.clipboardClearSeconds === 'number' &&
    Number.isFinite(rawSettings.clipboardClearSeconds) &&
    rawSettings.clipboardClearSeconds >= 5 &&
    rawSettings.clipboardClearSeconds <= 300
      ? Math.round(rawSettings.clipboardClearSeconds)
      : 20;

  const lockOnBlur =
    typeof rawSettings.lockOnBlur === 'boolean' ? rawSettings.lockOnBlur : false;

  const autoHidePasswordSeconds =
    typeof rawSettings.autoHidePasswordSeconds === 'number' &&
    Number.isFinite(rawSettings.autoHidePasswordSeconds) &&
    rawSettings.autoHidePasswordSeconds >= 5 &&
    rawSettings.autoHidePasswordSeconds <= 300
      ? Math.round(rawSettings.autoHidePasswordSeconds)
      : 30;

  const items: VaultItem[] = obj.items.map((entry, idx) => {
    if (typeof entry !== 'object' || entry === null) {
      throw new Error(`Vault item at index ${idx} is corrupted.`);
    }
    const e = entry as Record<string, unknown>;
    const cat =
      typeof e.category === 'string' && VALID_CATEGORIES.has(e.category as VaultCategory)
        ? (e.category as VaultCategory)
        : 'licno';

    const tags = Array.isArray(e.tags)
      ? e.tags
          .filter((t): t is string => typeof t === 'string')
          .map((t) => t.trim())
          .filter((t) => t.length > 0 && t.length <= 40)
      : [];

    return {
      id: typeof e.id === 'string' && e.id.length > 0 ? e.id : `legacy-${idx}`,
      category: cat,
      title: typeof e.title === 'string' ? e.title : 'Untitled',
      username: typeof e.username === 'string' ? e.username : '',
      password: typeof e.password === 'string' ? e.password : '',
      url: typeof e.url === 'string' ? e.url : '',
      notes: typeof e.notes === 'string' ? e.notes : '',
      tags: Array.from(new Set(tags)),
      createdAt: typeof e.createdAt === 'string' ? e.createdAt : new Date().toISOString(),
      updatedAt: typeof e.updatedAt === 'string' ? e.updatedAt : new Date().toISOString(),
    };
  });

  return {
    items,
    settings: {
      autoLockMinutes,
      clipboardClearSeconds,
      lockOnBlur,
      autoHidePasswordSeconds,
    },
  };
}

// ----------------------------------------------------------
// encryptVault — Always produces hardened v2 envelope with AAD
// ----------------------------------------------------------

export interface EncryptVaultOptions {
  revision?: number;
  updatedByDevice?: string;
  kdfParams?: Omit<KdfParams, 'algorithm' | 'salt'>;
}

export async function encryptVault(
  vault: PlaintextVault,
  key: CryptoKey,
  salt: Uint8Array,
  options: EncryptVaultOptions = {}
): Promise<EncryptedVaultBlobV2> {
  if (salt.byteLength < KDF_LIMITS.MIN_SALT_BYTES || salt.byteLength > KDF_LIMITS.MAX_SALT_BYTES) {
    throw new Error('Invalid salt length for encryption.');
  }

  const revision = options.revision ?? 1;
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error('Invalid vault revision number.');
  }

  const iv = generateIV();
  const ivB64 = bufToBase64(iv);
  const saltB64 = bufToBase64(salt);

  const kdf: KdfParams = {
    algorithm: 'argon2id',
    memory: options.kdfParams?.memory ?? ARGON2_MEMORY,
    iterations: options.kdfParams?.iterations ?? ARGON2_ITER,
    parallelism: options.kdfParams?.parallelism ?? ARGON2_PARALLEL,
    salt: saltB64,
  };

  validateKdfParams({
    memory: kdf.memory,
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    saltBytesLength: salt.byteLength,
  });

  const aad = buildVaultAadV2({ revision, kdf, iv: ivB64 });
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(vault));

  if (plaintext.byteLength > MAX_CIPHERTEXT_BYTES - AES_GCM_TAG_BYTES) {
    zeroMemory(plaintext);
    throw new Error('Vault exceeds maximum supported size.');
  }

  let ciphertextBuf: ArrayBuffer;
  try {
    ciphertextBuf = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv.slice(),
        additionalData: aad.slice(),
      },
      key,
      plaintext.slice()
    );
  } finally {
    zeroMemory(plaintext);
  }

  const blob: EncryptedVaultBlobV2 = {
    version: 2,
    revision,
    updatedAt: new Date().toISOString(),
    ...(options.updatedByDevice ? { updatedByDevice: options.updatedByDevice } : {}),
    kdf,
    encryption: {
      algorithm: 'AES-256-GCM',
      iv: ivB64,
      aadVersion: 1,
    },
    ciphertext: bufToBase64(ciphertextBuf),
  };

  return blob;
}

/**
 * Legacy v1 encryption helper — ONLY for migration/compatibility tests.
 * Production code must always use encryptVault() (v2).
 */
export async function encryptVaultLegacyV1ForTest(
  vault: PlaintextVault,
  key: CryptoKey,
  salt: Uint8Array
): Promise<EncryptedVaultBlobV1> {
  const iv = generateIV();
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  try {
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.slice() },
      key,
      plaintext.slice()
    );
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
  } finally {
    zeroMemory(plaintext);
  }
}

// ----------------------------------------------------------
// decryptVault — Supports both v1 (no AAD) and v2 (with AAD)
// ----------------------------------------------------------

export async function decryptVault(
  blob: EncryptedVaultBlob,
  key: CryptoKey
): Promise<PlaintextVault> {
  if (!validateBlobStructure(blob)) {
    throw new Error('Vault envelope failed structural validation.');
  }

  const iv = base64ToBuf(blob.encryption.iv);
  const ciphertext = base64ToBuf(blob.ciphertext);

  const decryptParams: AesGcmParams =
    blob.version === 2
      ? {
          name: 'AES-GCM',
          iv: iv.slice(),
          additionalData: buildVaultAadV2({
            revision: blob.revision,
            kdf: blob.kdf,
            iv: blob.encryption.iv,
          }).slice(),
        }
      : {
          name: 'AES-GCM',
          iv: iv.slice(),
        };

  let plaintextBuf: ArrayBuffer;
  try {
    plaintextBuf = await crypto.subtle.decrypt(
      decryptParams,
      key,
      ciphertext.slice()
    );
  } catch {
    throw new Error('Decryption failed: wrong password, tampered metadata, or corrupted vault.');
  }

  const plaintextBytes = new Uint8Array(plaintextBuf);
  let jsonStr: string;
  try {
    jsonStr = new TextDecoder().decode(plaintextBytes);
  } finally {
    zeroMemory(plaintextBytes);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error('Vault data is corrupted.');
  }

  return normalizePlaintextVault(parsed);
}

// ----------------------------------------------------------
// Helpers: KDF extraction, revision helper, strict blob guard
// ----------------------------------------------------------

export function getKdfParams(blob: EncryptedVaultBlob): KdfParams {
  return blob.kdf;
}

export function getBlobRevision(blob: EncryptedVaultBlob): number {
  return blob.version === 2 ? blob.revision : 0;
}

export function validateBlobStructure(obj: unknown): obj is EncryptedVaultBlob {
  if (typeof obj !== 'object' || obj === null) return false;
  const b = obj as Record<string, unknown>;

  const version = b['version'];
  if (version !== 1 && version !== 2) return false;

  if (typeof b['kdf'] !== 'object' || b['kdf'] === null) return false;
  if (typeof b['encryption'] !== 'object' || b['encryption'] === null) return false;
  if (typeof b['ciphertext'] !== 'string' || b['ciphertext'].length === 0) return false;

  // Guard against oversized payloads before base64 decoding
  if (b['ciphertext'].length > Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 4) {
    return false;
  }

  const kdf = b['kdf'] as Record<string, unknown>;
  if (kdf['algorithm'] !== 'argon2id') return false;
  if (typeof kdf['salt'] !== 'string' || kdf['salt'].length === 0) return false;

  if (
    typeof kdf['memory'] !== 'number' ||
    !Number.isInteger(kdf['memory']) ||
    kdf['memory'] < KDF_LIMITS.MIN_MEMORY_KIB ||
    kdf['memory'] > KDF_LIMITS.MAX_MEMORY_KIB
  ) {
    return false;
  }

  if (
    typeof kdf['iterations'] !== 'number' ||
    !Number.isInteger(kdf['iterations']) ||
    kdf['iterations'] < KDF_LIMITS.MIN_ITERATIONS ||
    kdf['iterations'] > KDF_LIMITS.MAX_ITERATIONS
  ) {
    return false;
  }

  if (
    typeof kdf['parallelism'] !== 'number' ||
    !Number.isInteger(kdf['parallelism']) ||
    kdf['parallelism'] < KDF_LIMITS.MIN_PARALLELISM ||
    kdf['parallelism'] > KDF_LIMITS.MAX_PARALLELISM
  ) {
    return false;
  }

  const enc = b['encryption'] as Record<string, unknown>;
  if (enc['algorithm'] !== 'AES-256-GCM') return false;
  if (typeof enc['iv'] !== 'string' || enc['iv'].length === 0) return false;

  if (version === 2) {
    if (
      typeof b['revision'] !== 'number' ||
      !Number.isSafeInteger(b['revision']) ||
      b['revision'] < 0
    ) {
      return false;
    }
    if (typeof b['updatedAt'] !== 'string' || Number.isNaN(Date.parse(b['updatedAt']))) {
      return false;
    }
    if (
      b['updatedByDevice'] !== undefined &&
      (typeof b['updatedByDevice'] !== 'string' || b['updatedByDevice'].length > 128)
    ) {
      return false;
    }
    if (enc['aadVersion'] !== 1) return false;
  }

  // Strictly decode and verify byte lengths of salt, iv, and ciphertext
  try {
    const saltBytes = base64ToBuf(kdf['salt']);
    if (
      saltBytes.byteLength < KDF_LIMITS.MIN_SALT_BYTES ||
      saltBytes.byteLength > KDF_LIMITS.MAX_SALT_BYTES
    ) {
      return false;
    }

    const ivBytes = base64ToBuf(enc['iv']);
    if (ivBytes.byteLength !== AES_IV_BYTES) {
      return false;
    }

    const ctBytes = base64ToBuf(b['ciphertext']);
    if (ctBytes.byteLength < AES_GCM_TAG_BYTES || ctBytes.byteLength > MAX_CIPHERTEXT_BYTES) {
      return false;
    }
  } catch {
    return false;
  }

  return true;
}

export function parseEncryptedBlobJson(jsonString: string): EncryptedVaultBlob {
  if (typeof jsonString !== 'string' || jsonString.length === 0) {
    throw new Error('Vault data is empty.');
  }
  if (new TextEncoder().encode(jsonString).byteLength > MAX_VAULT_JSON_BYTES) {
    throw new Error('Vault file exceeds the 5 MiB maximum size limit.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonString);
  } catch {
    throw new Error('Invalid vault file: malformed JSON.');
  }
  if (!validateBlobStructure(parsed)) {
    throw new Error('Invalid vault file: failed format or cryptographic parameter validation.');
  }
  return parsed;
}
