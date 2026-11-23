// ============================================================
// DISTRIBUTED & PROXY-SAFE RATE LIMITER
//
// 1. Distributed Backend: Uses Upstash Redis REST API when
//    UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN are set
//    (production-safe across multi-instance / serverless deployments).
// 2. Fail-Closed on Auth/MFA: If configured Redis fails transiently,
//    high-risk auth & MFA endpoints fail closed rather than allowing
//    unlimited brute-force attempts.
// 3. Trusted Proxy IP Extraction: NEVER trusts client-spoofable
//    X-Forwarded-For / X-Real-Ip unless TRUSTED_PROXY_PROVIDER is
//    explicitly configured for the deployment proxy.
// ============================================================

import {
  getTrustedProxyConfig,
  getUpstashRedisConfig,
  isInMemoryRateLimitFallbackAllowed,
} from '@/lib/env';

export interface RateLimitConfig {
  limit: number;
  windowMs: number;
  failClosedOnBackendError?: boolean;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  backend: 'upstash_redis' | 'memory' | 'redis_error_closed' | 'memory_unconfigured_prod';
}

export const RATE_LIMIT_TIERS = {
  auth: { limit: 10, windowMs: 15 * 60 * 1000, failClosedOnBackendError: true },
  mfa: { limit: 10, windowMs: 15 * 60 * 1000, failClosedOnBackendError: true },
  vaultRead: { limit: 120, windowMs: 5 * 60 * 1000, failClosedOnBackendError: false },
  vaultWrite: { limit: 60, windowMs: 5 * 60 * 1000, failClosedOnBackendError: false },
} as const;

const MAX_KEYS = 5000;
const buckets = new Map<string, number[]>();

// Strict IPv4 / IPv6 sanity check (rejects header injection / garbage)
const SAFE_IP_REGEX = /^[0-9a-fA-F:.]{3,64}$/;

function sanitizeIp(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!SAFE_IP_REGEX.test(trimmed)) return null;
  return trimmed;
}

/**
 * Synchronous sliding-window in-memory limiter (used in dev, single-node
 * deployments with RATE_LIMIT_ALLOW_IN_MEMORY=true, and unit tests).
 */
export function checkRateLimit(
  key: string,
  config: RateLimitConfig,
  now = Date.now()
): RateLimitResult {
  const cutoff = now - config.windowMs;

  if (buckets.size >= MAX_KEYS && !buckets.has(key)) {
    for (const [k, timestamps] of buckets.entries()) {
      const fresh = timestamps.filter((t) => t > cutoff);
      if (fresh.length === 0) buckets.delete(k);
      else buckets.set(k, fresh);
    }
    if (buckets.size >= MAX_KEYS) {
      const oldestKey = buckets.keys().next().value;
      if (oldestKey) buckets.delete(oldestKey);
    }
  }

  const existing = buckets.get(key) ?? [];
  const valid = existing.filter((t) => t > cutoff);

  const backend = isInMemoryRateLimitFallbackAllowed()
    ? 'memory'
    : 'memory_unconfigured_prod';

  if (valid.length >= config.limit) {
    buckets.set(key, valid);
    return {
      allowed: false,
      remaining: 0,
      resetAt: valid[0] + config.windowMs,
      backend,
    };
  }

  valid.push(now);
  buckets.set(key, valid);

  return {
    allowed: true,
    remaining: Math.max(0, config.limit - valid.length),
    resetAt: now + config.windowMs,
    backend,
  };
}

/**
 * Production-safe async rate limiter:
 * - Uses Upstash Redis REST atomic pipeline (INCR + PEXPIRE/PTTL) when configured.
 * - Fails closed on auth/MFA tiers if configured Redis is unreachable.
 * - Falls back to in-memory sliding window when Redis is not configured.
 */
export async function enforceRateLimit(
  key: string,
  config: RateLimitConfig,
  now = Date.now()
): Promise<RateLimitResult> {
  const redis = getUpstashRedisConfig();
  if (!redis) {
    return checkRateLimit(key, config, now);
  }

  const redisKey = `nmark_vault_rl:${key}`;
  try {
    const res = await fetch(`${redis.url}/pipeline`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${redis.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([
        ['INCR', redisKey],
        ['PTTL', redisKey],
      ]),
      cache: 'no-store',
    });

    if (!res.ok) {
      throw new Error(`Upstash Redis returned HTTP ${res.status}`);
    }

    const payload = (await res.json()) as Array<{ result?: number; error?: string }>;
    const count = Number(payload?.[0]?.result ?? 0);
    let pttl = Number(payload?.[1]?.result ?? -1);

    if (!Number.isFinite(count) || count <= 0) {
      throw new Error('Malformed Upstash Redis counter response');
    }

    // Set expiry on first hit or if key has no TTL
    if (count === 1 || pttl < 0) {
      await fetch(`${redis.url}/pipeline`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${redis.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify([['PEXPIRE', redisKey, String(config.windowMs)]]),
        cache: 'no-store',
      });
      pttl = config.windowMs;
    }

    const allowed = count <= config.limit;
    return {
      allowed,
      remaining: Math.max(0, config.limit - count),
      resetAt: now + Math.max(0, pttl),
      backend: 'upstash_redis',
    };
  } catch {
    if (config.failClosedOnBackendError) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: now + config.windowMs,
        backend: 'redis_error_closed',
      };
    }
    return checkRateLimit(key, config, now);
  }
}

export function resetRateLimitsForTests(): void {
  buckets.clear();
}

/**
 * Extracts a verified client IP ONLY according to the explicitly configured
 * deployment proxy (TRUSTED_PROXY_PROVIDER).
 *
 * When TRUSTED_PROXY_PROVIDER is unset ('none'), client-supplied X-Forwarded-For
 * and X-Real-Ip headers are IGNORED so callers cannot spoof IPs to bypass limits.
 */
export function getClientIpFromHeaders(headers: Headers): string {
  const { provider, hopCount } = getTrustedProxyConfig();

  if (provider === 'cloudflare') {
    const cfIp = sanitizeIp(headers.get('cf-connecting-ip'));
    return cfIp ?? 'unverified-cloudflare';
  }

  if (provider === 'vercel') {
    const vercelFwd = headers.get('x-vercel-forwarded-for');
    if (vercelFwd) {
      const parts = vercelFwd.split(',').map((s) => s.trim()).filter(Boolean);
      const rightmost = sanitizeIp(parts[parts.length - 1]);
      if (rightmost) return rightmost;
    }
    const realIp = sanitizeIp(headers.get('x-real-ip'));
    return realIp ?? 'unverified-vercel';
  }

  if (provider === 'custom') {
    const xff = headers.get('x-forwarded-for');
    if (xff) {
      const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
      // Select the rightmost untrusted hop based on verified proxy hop count
      // (NEVER blindly trust parts[0], which is attacker-controlled).
      const idx = Math.max(0, parts.length - hopCount);
      const candidate = sanitizeIp(parts[idx]);
      if (candidate) return candidate;
    }
    return 'unverified-custom';
  }

  // Default ('none'): do not trust spoofable forwarded headers
  return 'unverified-direct';
}

/**
 * Hashes an identifier (e.g., normalized email) with SHA-256 before using it
 * as a rate-limit key so raw PII never appears in Redis or memory keys.
 */
export async function hashRateLimitKey(raw: string): Promise<string> {
  const buf = new TextEncoder().encode(raw.trim().toLowerCase());
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32);
}
