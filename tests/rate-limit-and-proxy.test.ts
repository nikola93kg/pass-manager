import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  enforceRateLimit,
  getClientIpFromHeaders,
  hashRateLimitKey,
  resetRateLimitsForTests,
  RATE_LIMIT_TIERS,
} from '@/lib/security/rateLimit';

describe('Finding 4 Regression — Distributed Rate Limiting & Proxy-Verified IP Extraction', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    resetRateLimitsForTests();
    vi.restoreAllMocks();
    delete process.env.TRUSTED_PROXY_PROVIDER;
    delete process.env.TRUSTED_PROXY_HOP_COUNT;
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('ignores client-spoofed X-Forwarded-For and X-Real-Ip headers when TRUSTED_PROXY_PROVIDER is unset (none)', () => {
    const spoofed = new Headers({
      'x-forwarded-for': '203.0.113.55, 10.0.0.1',
      'x-real-ip': '198.51.100.77',
      'cf-connecting-ip': '192.0.2.99',
    });

    expect(getClientIpFromHeaders(spoofed)).toBe('unverified-direct');
  });

  it('trusts ONLY cf-connecting-ip when TRUSTED_PROXY_PROVIDER=cloudflare', () => {
    process.env.TRUSTED_PROXY_PROVIDER = 'cloudflare';
    const headers = new Headers({
      'x-forwarded-for': '1.1.1.1',
      'cf-connecting-ip': '203.0.113.10',
    });
    expect(getClientIpFromHeaders(headers)).toBe('203.0.113.10');

    // Missing cf-connecting-ip does NOT fall back to spoofed x-forwarded-for
    const missingCf = new Headers({ 'x-forwarded-for': '1.1.1.1' });
    expect(getClientIpFromHeaders(missingCf)).toBe('unverified-cloudflare');
  });

  it('extracts verified Vercel edge IP when TRUSTED_PROXY_PROVIDER=vercel', () => {
    process.env.TRUSTED_PROXY_PROVIDER = 'vercel';
    const headers = new Headers({
      'x-forwarded-for': '6.6.6.6',
      'x-vercel-forwarded-for': '198.51.100.20, 203.0.113.21',
    });
    expect(getClientIpFromHeaders(headers)).toBe('203.0.113.21');
  });

  it('selects rightmost untrusted hop for TRUSTED_PROXY_PROVIDER=custom (resists client-prepended spoofed IPs)', () => {
    process.env.TRUSTED_PROXY_PROVIDER = 'custom';
    process.env.TRUSTED_PROXY_HOP_COUNT = '1';
    const headers = new Headers({
      // Attacker prepends 1.2.3.4, real proxy appends actual client 198.51.100.42
      'x-forwarded-for': '1.2.3.4, 198.51.100.42',
    });
    expect(getClientIpFromHeaders(headers)).toBe('198.51.100.42');

    // Rejects malformed injection payloads
    const bad = new Headers({ 'x-forwarded-for': '1.2.3.4; DROP TABLE users' });
    expect(getClientIpFromHeaders(bad)).toBe('unverified-custom');
  });

  it('uses Upstash Redis REST pipeline for distributed rate limiting and blocks above threshold', async () => {
    process.env.UPSTASH_REDIS_REST_URL = 'https://example-redis.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'test-token-placeholder';

    const fetchMock = vi
      .fn()
      // 1st call: INCR=1, PTTL=-1
      .mockResolvedValueOnce(
        new Response(JSON.stringify([{ result: 1 }, { result: -1 }]), { status: 200 })
      )
      // 1st call PEXPIRE
      .mockResolvedValueOnce(new Response(JSON.stringify([{ result: 1 }]), { status: 200 }))
      // 2nd call: INCR=11 (exceeds limit 10), PTTL=800000
      .mockResolvedValueOnce(
        new Response(JSON.stringify([{ result: 11 }, { result: 800000 }]), { status: 200 })
      );
    vi.stubGlobal('fetch', fetchMock);

    const first = await enforceRateLimit('auth:signin:ip:test', RATE_LIMIT_TIERS.auth);
    expect(first.allowed).toBe(true);
    expect(first.backend).toBe('upstash_redis');
    expect(first.remaining).toBe(9);

    const blocked = await enforceRateLimit('auth:signin:ip:test', RATE_LIMIT_TIERS.auth);
    expect(blocked.allowed).toBe(false);
    expect(blocked.backend).toBe('upstash_redis');
    expect(blocked.remaining).toBe(0);
  });

  it('fails CLOSED on auth/MFA tiers if configured Upstash Redis is unreachable', async () => {
    process.env.UPSTASH_REDIS_REST_URL = 'https://example-redis.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'test-token-placeholder';

    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Redis connection refused')));

    const authRes = await enforceRateLimit('auth:signin:ip:down', RATE_LIMIT_TIERS.auth);
    expect(authRes.allowed).toBe(false);
    expect(authRes.backend).toBe('redis_error_closed');

    // Non-auth vault read falls back gracefully to in-memory limiter
    const readRes = await enforceRateLimit('vault:read:ip:down', RATE_LIMIT_TIERS.vaultRead);
    expect(readRes.allowed).toBe(true);
    expect(readRes.backend).toBe('memory');
  });

  it('hashes account identifiers deterministically without leaking plaintext emails', async () => {
    const h1 = await hashRateLimitKey('Admin@NMarkDesigns.com');
    const h2 = await hashRateLimitKey('  admin@nmarkdesigns.com ');
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(32);
    expect(h1).not.toContain('nmark');
  });
});
