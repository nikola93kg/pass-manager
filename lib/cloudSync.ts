// ============================================================
// CLOUD SYNC CLIENT
// Communicates ONLY encrypted vault envelopes with /api/vault.
// Plaintext credentials and master passwords NEVER leave the browser.
// ============================================================

import type { EncryptedVaultBlob, EncryptedVaultBlobV2 } from './types';
import { validateBlobStructure } from './crypto';

export class CloudSyncConflictError extends Error {
  readonly remoteBlob: EncryptedVaultBlob;
  readonly remoteRevision: number;

  constructor(remoteBlob: EncryptedVaultBlob, remoteRevision: number) {
    super(`Cloud sync conflict: remote revision ${remoteRevision} is newer than local.`);
    this.name = 'CloudSyncConflictError';
    this.remoteBlob = remoteBlob;
    this.remoteRevision = remoteRevision;
  }
}

export class CloudAuthError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'CloudAuthError';
    this.status = status;
  }
}

export interface CloudVaultResponse {
  exists: boolean;
  blob: EncryptedVaultBlobV2 | null;
  revision: number;
  updatedAt: string | null;
}

export async function fetchCloudVault(): Promise<CloudVaultResponse> {
  const res = await fetch('/api/vault', {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });

  if (res.status === 401 || res.status === 403) {
    const body = await res.json().catch(() => ({}));
    throw new CloudAuthError(body.error || 'Authentication or MFA required.', res.status);
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Failed to fetch cloud vault (${res.status}).`);
  }

  const data = (await res.json()) as CloudVaultResponse;
  if (data.exists && data.blob && !validateBlobStructure(data.blob)) {
    throw new Error('Remote vault payload failed structural integrity validation.');
  }

  return data;
}

export async function pushCloudVault(
  blob: EncryptedVaultBlobV2,
  expectedRevision: number
): Promise<{ revision: number; updatedAt: string }> {
  const res = await fetch('/api/vault', {
    method: 'PUT',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      expectedRevision,
      blob,
    }),
  });

  if (res.status === 409) {
    const body = await res.json().catch(() => ({}));
    if (body.remoteBlob && validateBlobStructure(body.remoteBlob)) {
      throw new CloudSyncConflictError(body.remoteBlob, body.remoteRevision ?? 0);
    }
    throw new Error('Cloud sync conflict detected. Please reload the latest vault.');
  }

  if (res.status === 401 || res.status === 403) {
    const body = await res.json().catch(() => ({}));
    throw new CloudAuthError(body.error || 'Authentication or MFA required.', res.status);
  }

  if (res.status === 429) {
    throw new Error('Rate limit exceeded. Please wait a moment and retry.');
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Failed to sync vault to cloud (${res.status}).`);
  }

  return (await res.json()) as { revision: number; updatedAt: string };
}

export async function createCloudSnapshot(
  blob: EncryptedVaultBlob,
  reason: string
): Promise<void> {
  const res = await fetch('/api/vault/snapshots', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ reason, blob }),
  });

  if (!res.ok && res.status !== 404) {
    // Non-fatal: log generic status without leaking any data
    throw new Error(`Failed to store encrypted cloud snapshot (${res.status}).`);
  }
}
