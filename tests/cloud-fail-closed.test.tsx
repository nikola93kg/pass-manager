import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import VaultApp from '@/components/VaultApp';
import { useVaultStore, resetWriteQueueForTests } from '@/store/vaultStore';
import { createVault } from '@/lib/vaultService';
import { GET as getSessionRoute } from '@/app/api/auth/session/route';

describe('Finding 1 Regression — Cloud Auth Fail-Closed Behavior', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    localStorage.clear();
    resetWriteQueueForTests();
    useVaultStore.getState().lock({ broadcast: false });
    vi.restoreAllMocks();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('fails closed (never falls back to local-only) when /api/auth/session throws a network error', async () => {
    // Even if a local encrypted vault exists in localStorage, a failed session check MUST NOT bypass auth!
    await createVault('ExistingLocalVault!2026');

    const fetchMock = vi.fn().mockRejectedValueOnce(new Error('Network offline'));
    vi.stubGlobal('fetch', fetchMock);

    render(<VaultApp />);

    await waitFor(() => {
      expect(screen.getByText(/Authentication Check Failed/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/Retry Authentication Check/i)).toBeInTheDocument();
    expect(screen.queryByText(/Unlock Vault/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Create Encrypted Vault/i)).not.toBeInTheDocument();

    // Clicking Retry recovers once /api/auth/session responds with cloud sign_in
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          mode: 'cloud',
          step: 'sign_in',
          userEmail: null,
          userId: null,
          aal: null,
          hasTotpFactor: false,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    fireEvent.click(screen.getByText(/Retry Authentication Check/i));
    await waitFor(() => {
      expect(screen.getByText(/Continue to MFA Verification/i)).toBeInTheDocument();
    });
  });

  it('fails closed when /api/auth/session returns HTTP 503 or 500', async () => {
    await createVault('ExistingLocalVault!2026');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: 'Cloud authentication is required in production but Supabase is not configured.',
          }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );

    render(<VaultApp />);

    await waitFor(() => {
      expect(screen.getByText(/Authentication Check Failed/i)).toBeInTheDocument();
      expect(screen.getByText(/Cloud authentication is required in production/i)).toBeInTheDocument();
    });
    expect(screen.queryByText(/Unlock Vault/i)).not.toBeInTheDocument();
  });

  it('preserves explicit local-only mode when /api/auth/session returns 200 local_only', async () => {
    await createVault('ExplicitLocalVault!2026');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            mode: 'local',
            step: 'local_only',
            userEmail: null,
            userId: null,
            aal: null,
            hasTotpFactor: false,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );

    render(<VaultApp />);

    await waitFor(() => {
      expect(screen.getByText(/Unlock Vault/i)).toBeInTheDocument();
    });
  });

  it('server GET /api/auth/session fails closed (503) in production without Supabase unless ALLOW_LOCAL_ONLY_MODE=true', async () => {
    delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    delete process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    delete process.env.ALLOW_LOCAL_ONLY_MODE;
    delete process.env.NEXT_PUBLIC_ALLOW_LOCAL_ONLY;
    (process.env as Record<string, string | undefined>).NODE_ENV = 'production';

    const denied = await getSessionRoute();
    expect(denied.status).toBe(503);
    const deniedBody = await denied.json();
    expect(deniedBody.code).toBe('CLOUD_AUTH_MISCONFIGURED');

    // Explicitly configured local-only production installation succeeds
    process.env.ALLOW_LOCAL_ONLY_MODE = 'true';
    const allowed = await getSessionRoute();
    expect(allowed.status).toBe(200);
    const allowedBody = await allowed.json();
    expect(allowedBody.mode).toBe('local');
    expect(allowedBody.step).toBe('local_only');
  });
});
