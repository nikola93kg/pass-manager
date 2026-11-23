// ============================================================
// CONTENT SECURITY POLICY & HTTP SECURITY HEADERS
// Pure, testable header builder used by Next.js middleware.
//
// Notes on CSP decisions (also documented in SECURITY.md):
// - 'wasm-unsafe-eval' is required by argon2-browser to instantiate
//   its embedded Argon2id WebAssembly module. Unlike 'unsafe-eval',
//   it does NOT permit JavaScript eval() or new Function().
// - Production uses a per-request cryptographic nonce for scripts
//   (no 'unsafe-inline' in script-src).
// - 'unsafe-inline' in style-src is scoped to styles only (Next.js
//   and inline style attributes); script execution remains locked down.
// ============================================================

export interface CspOptions {
  nonce: string;
  isDev: boolean;
  supabaseUrl?: string;
}

export function buildContentSecurityPolicy({
  nonce,
  isDev,
  supabaseUrl,
}: CspOptions): string {
  const connectSources = ["'self'"];
  if (supabaseUrl) {
    try {
      const origin = new URL(supabaseUrl).origin;
      connectSources.push(origin);
    } catch {
      // ignore invalid URL
    }
  }
  if (isDev) {
    connectSources.push('ws:', 'wss:');
  }

  const scriptSrc = isDev
    ? ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'"]
    : ["'self'", `'nonce-${nonce}'`, "'wasm-unsafe-eval'"];

  const directives = [
    "default-src 'self'",
    `script-src ${scriptSrc.join(' ')}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src ${connectSources.join(' ')}`,
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];

  if (!isDev) {
    directives.push('upgrade-insecure-requests');
  }

  return directives.join('; ');
}

export function getSecurityHeaders(options: CspOptions): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Security-Policy': buildContentSecurityPolicy(options),
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy':
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
  };

  if (!options.isDev) {
    headers['Strict-Transport-Security'] =
      'max-age=63072000; includeSubDomains; preload';
  }

  return headers;
}
