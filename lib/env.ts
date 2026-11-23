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
    if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
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
 * When cloud sync is enabled in production, at least one of
 * ALLOWED_ADMIN_EMAIL or ALLOWED_ADMIN_USER_ID MUST be set.
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
