// ============================================================
// VAULT TYPES — NMark Pass Vault v2
// Supports backward-compatible v1 blobs and hardened v2 blobs
// with authenticated metadata (AAD) and optimistic concurrency.
// ============================================================

export type VaultCategory = 'posao' | 'projekti' | 'licno';

export interface VaultItem {
  id: string;
  category: VaultCategory;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
}

export interface VaultSettings {
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  lockOnBlur?: boolean;
  autoHidePasswordSeconds?: number;
}

export interface PlaintextVault {
  items: VaultItem[];
  settings: VaultSettings;
}

// ---- Encrypted Storage Format ----

export interface KdfParams {
  algorithm: 'argon2id';
  memory: number; // KiB (e.g. 65536 = 64 MiB)
  iterations: number;
  parallelism: number;
  salt: string; // base64 (16 bytes)
}

export interface EncryptionParamsV1 {
  algorithm: 'AES-256-GCM';
  iv: string; // base64 (12 bytes)
}

export interface EncryptionParamsV2 extends EncryptionParamsV1 {
  aadVersion: 1;
}

export interface EncryptedVaultBlobV1 {
  version: 1;
  kdf: KdfParams;
  encryption: EncryptionParamsV1;
  ciphertext: string; // base64
}

export interface EncryptedVaultBlobV2 {
  version: 2;
  revision: number; // monotonic integer for optimistic concurrency
  updatedAt: string; // ISO 8601
  updatedByDevice?: string; // opaque random UUID per browser install
  kdf: KdfParams;
  encryption: EncryptionParamsV2;
  ciphertext: string; // base64
}

export type EncryptedVaultBlob = EncryptedVaultBlobV1 | EncryptedVaultBlobV2;

// ---- Password Generator ----

export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
}

// ---- Backup / Import / Export ----

export type ExportPayload = EncryptedVaultBlob;

export interface RecoverySnapshot {
  createdAt: string;
  reason: 'import' | 'password_change' | 'cloud_migration' | 'reset' | 'v1_migration' | 'manual';
  blob: EncryptedVaultBlob;
}

// ---- Sync & Concurrency ----

export type SyncMode = 'local' | 'cloud';

export type SyncStatus =
  | 'idle'
  | 'saving'
  | 'synced'
  | 'offline_local'
  | 'conflict'
  | 'error';

export interface VaultConflict {
  source: 'tab' | 'cloud';
  localRevision: number;
  remoteRevision: number;
  remoteBlob: EncryptedVaultBlob;
  detectedAt: string;
}

// ---- Auth & MFA ----

export type AuthStep =
  | 'loading'
  | 'local_only'
  | 'sign_in'
  | 'mfa_enroll'
  | 'mfa_challenge'
  | 'authenticated'
  | 'forbidden';

export interface AuthSessionState {
  mode: SyncMode;
  step: AuthStep;
  userEmail: string | null;
  userId: string | null;
  aal: 'aal1' | 'aal2' | null;
  hasTotpFactor: boolean;
}
