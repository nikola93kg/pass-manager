import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { authorizeVaultAccess, type AuthGuardClient } from '@/lib/auth/guard';
import { checkRateLimit, resetRateLimitsForTests } from '@/lib/security/rateLimit';
import { verifySameOriginRequest } from '@/lib/security/csrf';
import { buildContentSecurityPolicy, getSecurityHeaders } from '@/lib/security/csp';
import {
  getSafeExternalUrl,
  getSafeInternalRedirect,
  isValidVaultItemId,
  isSafeQrDataUri,
} from '@/lib/urlSafety';

function mockSupabase(params: {
  user: { id: string; email?: string } | null;
  aal: 'aal1' | 'aal2' | null;
}): AuthGuardClient {
  return {
    auth: {
      getUser: async () => ({ data: { user: params.user }, error: null }),
      mfa: {
        getAuthenticatorAssuranceLevel: async () => ({
          data: params.aal ? { currentLevel: params.aal, nextLevel: 'aal2' } : null,
          error: null,
        }),
      },
    },
  };
}

describe('Authentication, Single-Admin Allowlist, Mandatory MFA & Security Controls', () => {
  const originalAdminEmail = process.env.ALLOWED_ADMIN_EMAIL;
  const originalAdminId = process.env.ALLOWED_ADMIN_USER_ID;

  beforeEach(() => {
    resetRateLimitsForTests();
    process.env.ALLOWED_ADMIN_EMAIL = 'admin@nmarkdesigns.com';
    process.env.ALLOWED_ADMIN_USER_ID = 'admin-uuid-001';
  });

  afterEach(() => {
    if (originalAdminEmail === undefined) delete process.env.ALLOWED_ADMIN_EMAIL;
    else process.env.ALLOWED_ADMIN_EMAIL = originalAdminEmail;

    if (originalAdminId === undefined) delete process.env.ALLOWED_ADMIN_USER_ID;
    else process.env.ALLOWED_ADMIN_USER_ID = originalAdminId;
  });

  it('rejects unauthenticated requests to private vault records (401)', async () => {
    const res = await authorizeVaultAccess(mockSupabase({ user: null, aal: null }));
    expect(res.authorized).toBe(false);
    if (!res.authorized) {
      expect(res.status).toBe(401);
      expect(res.code).toBe('UNAUTHENTICATED');
    }
  });

  it('rejects authenticated users who are not the allowlisted admin (403)', async () => {
    const res = await authorizeVaultAccess(
      mockSupabase({
        user: { id: 'other-user-999', email: 'intruder@evil.com' },
        aal: 'aal2',
      })
    );
    expect(res.authorized).toBe(false);
    if (!res.authorized) {
      expect(res.status).toBe(403);
      expect(res.code).toBe('FORBIDDEN_USER');
    }
  });

  it('fails closed when allowlist env variables are missing (403)', async () => {
    delete process.env.ALLOWED_ADMIN_EMAIL;
    delete process.env.ALLOWED_ADMIN_USER_ID;

    const res = await authorizeVaultAccess(
      mockSupabase({
        user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' },
        aal: 'aal2',
      })
    );
    expect(res.authorized).toBe(false);
    if (!res.authorized) {
      expect(res.status).toBe(403);
      expect(res.code).toBe('FORBIDDEN_USER');
    }
  });

  it('enforces mandatory MFA (aal2): rejects aal1 sessions with 403 MFA_REQUIRED', async () => {
    const res = await authorizeVaultAccess(
      mockSupabase({
        user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' },
        aal: 'aal1',
      }),
      { requireMfa: true }
    );
    expect(res.authorized).toBe(false);
    if (!res.authorized) {
      expect(res.status).toBe(403);
      expect(res.code).toBe('MFA_REQUIRED');
    }
  });

  it('authorizes the allowlisted admin only after MFA (aal2) verification', async () => {
    const res = await authorizeVaultAccess(
      mockSupabase({
        user: { id: 'admin-uuid-001', email: 'admin@nmarkdesigns.com' },
        aal: 'aal2',
      }),
      { requireMfa: true }
    );
    expect(res.authorized).toBe(true);
    if (res.authorized) {
      expect(res.user.id).toBe('admin-uuid-001');
      expect(res.aal).toBe('aal2');
    }
  });

  it('enforces sliding-window rate limits and resets after window expires', () => {
    const cfg = { limit: 3, windowMs: 1000 };
    expect(checkRateLimit('ip:1', cfg, 1000).allowed).toBe(true);
    expect(checkRateLimit('ip:1', cfg, 1100).allowed).toBe(true);
    expect(checkRateLimit('ip:1', cfg, 1200).allowed).toBe(true);
    expect(checkRateLimit('ip:1', cfg, 1300).allowed).toBe(false);
    // After window passes
    expect(checkRateLimit('ip:1', cfg, 2100).allowed).toBe(true);
  });

  it('blocks cross-site CSRF state-changing requests while permitting same-origin', () => {
    const crossSite = new Request('https://vault.nmarkdesigns.com/api/vault', {
      method: 'PUT',
      headers: {
        host: 'vault.nmarkdesigns.com',
        origin: 'https://attacker.example',
        'sec-fetch-site': 'cross-site',
      },
    });
    expect(verifySameOriginRequest(crossSite).ok).toBe(false);

    const sameOrigin = new Request('https://vault.nmarkdesigns.com/api/vault', {
      method: 'PUT',
      headers: {
        host: 'vault.nmarkdesigns.com',
        origin: 'https://vault.nmarkdesigns.com',
        'sec-fetch-site': 'same-origin',
      },
    });
    expect(verifySameOriginRequest(sameOrigin).ok).toBe(true);
  });

  it('generates restrictive production CSP without unsafe-inline/unsafe-eval scripts', () => {
    const csp = buildContentSecurityPolicy({
      nonce: 'testnonce123',
      isDev: false,
      supabaseUrl: 'https://abc.supabase.co',
    });

    expect(csp).toContain("script-src 'self' 'nonce-testnonce123' 'wasm-unsafe-eval'");
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-eval'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("connect-src 'self' https://abc.supabase.co");

    const headers = getSecurityHeaders({ nonce: 'n', isDev: false });
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['Referrer-Policy']).toBe('no-referrer');
    expect(headers['Strict-Transport-Security']).toContain('max-age=');
  });

  it('validates external URLs, internal redirects, QR URIs, and Client Hub item IDs safely', () => {
    expect(getSafeExternalUrl('https://dash.cloudflare.com/login')).toBe(
      'https://dash.cloudflare.com/login'
    );
    expect(getSafeExternalUrl('javascript:alert(1)')).toBeNull();
    expect(getSafeExternalUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(getSafeExternalUrl('file:///etc/passwd')).toBeNull();

    expect(getSafeInternalRedirect('/item/11111111-1111-4111-8111-111111111111')).toBe(
      '/item/11111111-1111-4111-8111-111111111111'
    );
    expect(getSafeInternalRedirect('//evil.com/phish')).toBe('/');
    expect(getSafeInternalRedirect('https://evil.com')).toBe('/');

    expect(isValidVaultItemId('11111111-1111-4111-8111-111111111111')).toBe(true);
    expect(isValidVaultItemId('../etc/passwd')).toBe(false);
    expect(isValidVaultItemId('<script>')).toBe(false);
    expect(isValidVaultItemId('short')).toBe(false);

    expect(isSafeQrDataUri('data:image/svg+xml;utf8,<svg></svg>')).toBe(true);
    expect(isSafeQrDataUri('javascript:alert(1)')).toBe(false);
  });
});
