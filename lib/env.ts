// ============================================================
// ENVIRONMENT CONFIGURATION & VALIDATION
// Strictly separates public NEXT_PUBLIC_* vars from server-only
// secrets. Never logs secret values.
// ============================================================

export interface PublicSupabaseConfig {
  url: string;
  anonKey: string;
}

export function getPublicSupabaseConfig(): PublicSupabaseConfig | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();

  if (!url || !anonKey) {
    return null;
  }

  try {
    const parsed = new URL(url);
    if (
      parsed.protocol !== 'https:' &&
      parsed.hostname !== 'localhost' &&
      parsed.hostname !== '127.0.0.1'
    ) {
      return null;
    }
  } catch {
    return null;
  }

  return { url, anonKey };
}

export function isCloudSyncConfigured(): boolean {
  return getPublicSupabaseConfig() !== null;
}

/**
 * Determines whether running without Supabase cloud authentication is permitted.
 * - Always allowed in non-production environments (development/test) when Supabase is unset.
 * - In production, cloud auth is required by default (fail-closed) unless
 *   ALLOW_LOCAL_ONLY_MODE=true is explicitly set for an intentional local-only deployment.
 */
export function isLocalOnlyModeAllowed(): boolean {
  if (isCloudSyncConfigured()) {
    return false;
  }
  if (process.env.NODE_ENV !== 'production') {
    return true;
  }
  return (
    process.env.ALLOW_LOCAL_ONLY_MODE?.trim().toLowerCase() === 'true' ||
    process.env.NEXT_PUBLIC_ALLOW_LOCAL_ONLY?.trim().toLowerCase() === 'true'
  );
}

export function getAppOrigin(): string {
  const configured = process.env.NEXT_PUBLIC_APP_URL?.trim();
  if (configured) {
    try {
      return new URL(configured).origin;
    } catch {
      // fall through
    }
  }
  return 'https://vault.nmarkdesigns.com';
}

/**
 * Server-only: single-admin allowlist configuration.
 * When cloud sync is enabled, at least one of ALLOWED_ADMIN_EMAIL or
 * ALLOWED_ADMIN_USER_ID MUST be set (fail-closed).
 */
export function getAllowedAdminConfig(): {
  email: string | null;
  userId: string | null;
} {
  const email = process.env.ALLOWED_ADMIN_EMAIL?.trim().toLowerCase() || null;
  const userId = process.env.ALLOWED_ADMIN_USER_ID?.trim() || null;
  return { email, userId };
}

export function isUserAllowedAdmin(user: {
  id?: string | null;
  email?: string | null;
}): boolean {
  const { email: allowedEmail, userId: allowedUserId } = getAllowedAdminConfig();

  // Fail closed: if neither allowlist var is set, deny access in cloud mode
  if (!allowedEmail && !allowedUserId) {
    return false;
  }

  if (allowedUserId && user.id !== allowedUserId) {
    return false;
  }

  if (allowedEmail && (user.email ?? '').trim().toLowerCase() !== allowedEmail) {
    return false;
  }

  return true;
}

// ----------------------------------------------------------
// Trusted Proxy & Distributed Rate Limiter Config (Server-only)
// ----------------------------------------------------------

export type TrustedProxyProvider = 'none' | 'cloudflare' | 'vercel' | 'custom';

export function getTrustedProxyConfig(): {
  provider: TrustedProxyProvider;
  hopCount: number;
} {
  const raw = (process.env.TRUSTED_PROXY_PROVIDER ?? 'none').trim().toLowerCase();
  const provider: TrustedProxyProvider =
    raw === 'cloudflare' || raw === 'vercel' || raw === 'custom' ? raw : 'none';

  const parsedHops = Number.parseInt(process.env.TRUSTED_PROXY_HOP_COUNT ?? '1', 10);
  const hopCount =
    Number.isInteger(parsedHops) && parsedHops >= 1 && parsedHops <= 10 ? parsedHops : 1;

  return { provider, hopCount };
}

export interface UpstashRedisConfig {
  url: string;
  token: string;
}

export function getUpstashRedisConfig(): UpstashRedisConfig | null {
  const url = process.env.UPSTASH_REDIS_REST_URL?.trim();
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  if (!url || !token) return null;

  try {
    const parsed = new URL(url);
    if (
      parsed.protocol !== 'https:' &&
      parsed.hostname !== 'localhost' &&
      parsed.hostname !== '127.0.0.1'
    ) {
      return null;
    }
  } catch {
    return null;
  }

  return { url: url.replace(/\/+$/, ''), token };
}

export function isInMemoryRateLimitFallbackAllowed(): boolean {
  if (process.env.NODE_ENV !== 'production') {
    return true;
  }
  return process.env.RATE_LIMIT_ALLOW_IN_MEMORY?.trim().toLowerCase() === 'true';
}
