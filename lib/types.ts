// ============================================================
// VAULT TYPES — Production Password Vault
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
  createdAt: string; // ISO 8601
  updatedAt: string; // ISO 8601
}

export interface VaultSettings {
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  lockOnBlur?: boolean;
}

export interface PlaintextVault {
  items: VaultItem[];
  settings: VaultSettings;
}

// ---- Encrypted Storage Format ----

export interface KdfParams {
  algorithm: 'argon2id';
  memory: number;
  iterations: number;
  parallelism: number;
  salt: string; // base64
}

export interface EncryptionParams {
  algorithm: 'AES-256-GCM';
  iv: string; // base64
}

export interface EncryptedVaultBlob {
  version: 1;
  kdf: KdfParams;
  encryption: EncryptionParams;
  ciphertext: string; // base64
}

// ---- Password Generator ----

export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
}

// ---- Import / Export ----

export type ExportPayload = EncryptedVaultBlob;
