import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { encryptVault, deriveKey, generateSalt } from '@/lib/crypto';
import { resetRateLimitsForTests } from '@/lib/security/rateLimit';
import type { PlaintextVault } from '@/lib/types';

// Mock the Supabase server client factory so we can test actual Next.js route handlers
const mockCreateSupabaseServerClient = vi.fn();
vi.mock('@/lib/supabase/server', () => ({
  createSupabaseServerClient: () => mockCreateSupabaseServerClient(),
}));

import { GET as getVaultRoute, PUT as putVaultRoute } from '@/app/api/vault/route';

const SAMPLE_VAULT: PlaintextVault = {
  items: [],
  settings: { autoLockMinutes: 5, clipboardClearSeconds: 20, lockOnBlur: false },
};

describe('API Route Integration — /api/vault Authorization, Validation & 409 Conflicts', () => {
  const originalAdminEmail = process.env.ALLOWED_ADMIN_EMAIL;
  const originalAdminId = process.env.ALLOWED_ADMIN_USER_ID;

  beforeEach(() => {
    resetRateLimitsForTests();
    mockCreateSupabaseServerClient.mockReset();
    process.env.ALLOWED_ADMIN_EMAIL = 'admin@nmarkdesigns.com';
    process.env.ALLOWED_ADMIN_USER_ID = 'admin-uuid-001';
  });

  afterEach(() => {
    if (originalAdminEmail === undefined) delete process.env.ALLOWED_ADMIN_EMAIL;
    else process.env.ALLOWED_ADMIN_EMAIL = originalAdminEmail;
    if (originalAdminId === undefined) delete process.env.ALLOWED_ADMIN_USER_ID;
    else process.env.ALLOWED_ADMIN_USER_ID = originalAdminId;
  });

  it('returns 401 when an unauthenticated caller accesses GET /api/vault', async () => {
    mockCreateSupabaseServerClient.mockResolvedValue({
      auth: {
        getUser: async () => ({ data: { user: null }, error: null }),
        mfa: { getAuthenticatorAssuranceLevel: async () => ({ data: null, error: null }) },
      },
    });

    const req = new Request('https://vault.nmarkdesigns.com/api/vault', { method: 'GET' });
    const res = await getVaultRoute(req);
    expect(res.status).toBe(401);
  });

  it('returns 403 MFA_REQUIRED when admin has only aal1 (no TOTP verification)', async () => {
    mockCreateSupabaseServerClient.mockResolvedValue({
      auth: {
        getUser: async () => ({
          data: { user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' } },
          error: null,
        }),
        mfa: {
          getAuthenticatorAssuranceLevel: async () => ({
            data: { currentLevel: 'aal1', nextLevel: 'aal2' },
            error: null,
          }),
        },
      },
    });

    const req = new Request('https://vault.nmarkdesigns.com/api/vault', { method: 'GET' });
    const res = await getVaultRoute(req);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.code).toBe('MFA_REQUIRED');
  });

  it('returns 400 when PUT /api/vault receives an invalid or non-v2 blob', async () => {
    mockCreateSupabaseServerClient.mockResolvedValue({
      auth: {
        getUser: async () => ({
          data: { user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' } },
          error: null,
        }),
        mfa: {
          getAuthenticatorAssuranceLevel: async () => ({
            data: { currentLevel: 'aal2', nextLevel: 'aal2' },
            error: null,
          }),
        },
      },
      rpc: vi.fn(),
    });

    const req = new Request('https://vault.nmarkdesigns.com/api/vault', {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        host: 'vault.nmarkdesigns.com',
        origin: 'https://vault.nmarkdesigns.com',
        'sec-fetch-site': 'same-origin',
      },
      body: JSON.stringify({
        expectedRevision: 0,
        blob: { version: 2, revision: 1, kdf: { algorithm: 'argon2id', memory: 1 } },
      }),
    });

    const res = await putVaultRoute(req);
    expect(res.status).toBe(400);
  });

  it('returns 409 Conflict with remoteBlob when optimistic concurrency RPC detects stale revision', async () => {
    const salt = generateSalt();
    const key = await deriveKey('RouteTestMaster!2026', salt);
    const localBlob = await encryptVault(SAMPLE_VAULT, key, salt, { revision: 2 });
    const remoteBlob = await encryptVault(SAMPLE_VAULT, key, salt, { revision: 5 });

    mockCreateSupabaseServerClient.mockResolvedValue({
      auth: {
        getUser: async () => ({
          data: { user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' } },
          error: null,
        }),
        mfa: {
          getAuthenticatorAssuranceLevel: async () => ({
            data: { currentLevel: 'aal2', nextLevel: 'aal2' },
            error: null,
          }),
        },
      },
      rpc: vi.fn().mockResolvedValue({
        data: {
          status: 'CONFLICT',
          remoteRevision: 5,
          remoteVault: remoteBlob,
        },
        error: null,
      }),
    });

    const req = new Request('https://vault.nmarkdesigns.com/api/vault', {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        host: 'vault.nmarkdesigns.com',
        origin: 'https://vault.nmarkdesigns.com',
        'sec-fetch-site': 'same-origin',
      },
      body: JSON.stringify({ expectedRevision: 1, blob: localBlob }),
    });

    const res = await putVaultRoute(req);
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.remoteRevision).toBe(5);
    expect(body.remoteBlob.revision).toBe(5);
  });

  it('returns 200 OK when authenticated aal2 admin pushes a valid v2 encrypted blob', async () => {
    const salt = generateSalt();
    const key = await deriveKey('RouteTestMaster!2026', salt);
    const blob = await encryptVault(SAMPLE_VAULT, key, salt, { revision: 1 });

    mockCreateSupabaseServerClient.mockResolvedValue({
      auth: {
        getUser: async () => ({
          data: { user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' } },
          error: null,
        }),
        mfa: {
          getAuthenticatorAssuranceLevel: async () => ({
            data: { currentLevel: 'aal2', nextLevel: 'aal2' },
            error: null,
          }),
        },
      },
      rpc: vi.fn().mockResolvedValue({
        data: {
          status: 'OK',
          revision: 1,
          updatedAt: blob.updatedAt,
        },
        error: null,
      }),
    });

    const req = new Request('https://vault.nmarkdesigns.com/api/vault', {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        host: 'vault.nmarkdesigns.com',
        origin: 'https://vault.nmarkdesigns.com',
        'sec-fetch-site': 'same-origin',
      },
      body: JSON.stringify({ expectedRevision: 0, blob }),
    });

    const res = await putVaultRoute(req);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.revision).toBe(1);
  });
});
