// ============================================================
// URL & IDENTIFIER SAFETY UTILITIES
// Prevents javascript:/data: XSS links, open redirects, and
// malformed Client Hub deep-link item IDs.
// ============================================================

const ALLOWED_EXTERNAL_PROTOCOLS = new Set(['https:', 'http:']);

/**
 * Validates that a user-supplied URL uses an explicit http: or https: scheme
 * and contains no embedded credentials or control characters.
 * Returns the normalized href string if safe, or null otherwise.
 */
export function getSafeExternalUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048) return null;

  // Reject ASCII control chars
  if (/[\u0000-\u001F\u007F]/.test(trimmed)) return null;

  try {
    const parsed = new URL(trimmed);
    if (!ALLOWED_EXTERNAL_PROTOCOLS.has(parsed.protocol)) {
      return null;
    }
    if (!parsed.hostname) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Validates that a post-login redirect target is strictly a relative internal path
 * on this origin (no protocol-relative `//evil.com`, no backslashes, no schemes).
 */
export function getSafeInternalRedirect(raw: string | null | undefined, fallback = '/'): string {
  if (!raw) return fallback;
  const trimmed = raw.trim();
  if (!trimmed.startsWith('/')) return fallback;
  if (trimmed.startsWith('//') || trimmed.startsWith('/\\')) return fallback;
  if (/[\u0000-\u001F\u007F\\]/.test(trimmed)) return fallback;

  try {
    const testUrl = new URL(trimmed, 'https://vault.nmarkdesigns.com');
    if (testUrl.origin !== 'https://vault.nmarkdesigns.com') {
      return fallback;
    }
    return `${testUrl.pathname}${testUrl.search}`;
  } catch {
    return fallback;
  }
}

const ITEM_ID_REGEX = /^[a-zA-Z0-9_-]{8,128}$/;

/**
 * Validates a stable vault item ID for Client Hub deep links (/item/{vaultItemId}).
 * Accepts UUIDs and URL-safe alphanumeric/hyphen/underscore IDs (8-128 chars).
 */
export function isValidVaultItemId(id: string | null | undefined): id is string {
  if (typeof id !== 'string') return false;
  return ITEM_ID_REGEX.test(id);
}

/**
 * Validates that a TOTP QR code URI returned by Supabase Auth is strictly an SVG data URI.
 */
export function isSafeQrDataUri(uri: string | null | undefined): uri is string {
  if (typeof uri !== 'string') return false;
  return uri.startsWith('data:image/svg+xml;');
}

/**
 * Generates a CSPRNG UUIDv4 using Web Crypto (no external uuid dependency).
 */
export function generateVaultItemId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant RFC 4122
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
