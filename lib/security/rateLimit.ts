// ============================================================
// RATE LIMITER — Sliding-window in-memory limiter for auth & vault APIs
// Note: In multi-instance serverless deployments, pair with edge/WAF
// or Redis-backed rate limiting (documented in DEPLOYMENT.md).
// ============================================================

export interface RateLimitConfig {
  limit: number;
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export const RATE_LIMIT_TIERS = {
  auth: { limit: 10, windowMs: 15 * 60 * 1000 }, // 10 attempts / 15 min
  mfa: { limit: 10, windowMs: 15 * 60 * 1000 }, // 10 MFA attempts / 15 min
  vaultRead: { limit: 120, windowMs: 5 * 60 * 1000 }, // 120 reads / 5 min
  vaultWrite: { limit: 60, windowMs: 5 * 60 * 1000 }, // 60 writes / 5 min
} as const;

const MAX_KEYS = 5000;
const buckets = new Map<string, number[]>();

export function checkRateLimit(
  key: string,
  config: RateLimitConfig,
  now = Date.now()
): RateLimitResult {
  const cutoff = now - config.windowMs;

  // Guard against unbounded map growth under distributed floods
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

  if (valid.length >= config.limit) {
    buckets.set(key, valid);
    return {
      allowed: false,
      remaining: 0,
      resetAt: valid[0] + config.windowMs,
    };
  }

  valid.push(now);
  buckets.set(key, valid);

  return {
    allowed: true,
    remaining: Math.max(0, config.limit - valid.length),
    resetAt: now + config.windowMs,
  };
}

export function resetRateLimitsForTests(): void {
  buckets.clear();
}

export function getClientIpFromHeaders(headers: Headers): string {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0]?.trim();
    if (first) return first;
  }
  const realIp = headers.get('x-real-ip')?.trim();
  if (realIp) return realIp;
  return 'unknown';
}
