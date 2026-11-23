// ============================================================
// CSRF ORIGIN VERIFICATION FOR STATE-CHANGING API ROUTES
// Verifies Origin / Sec-Fetch-Site on POST/PUT/PATCH/DELETE.
// ============================================================

export function verifySameOriginRequest(request: Request): {
  ok: boolean;
  reason?: string;
} {
  const method = request.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return { ok: true };
  }

  const secFetchSite = request.headers.get('sec-fetch-site');
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    return { ok: false, reason: 'Cross-site request rejected.' };
  }

  const origin = request.headers.get('origin');
  const host = request.headers.get('x-forwarded-host') ?? request.headers.get('host');

  if (origin) {
    try {
      const originUrl = new URL(origin);
      const allowedHosts = new Set<string>();
      if (host) allowedHosts.add(host.toLowerCase());

      const appUrl = process.env.NEXT_PUBLIC_APP_URL?.trim();
      if (appUrl) {
        try {
          allowedHosts.add(new URL(appUrl).host.toLowerCase());
        } catch {
          // ignore malformed env
        }
      }

      if (allowedHosts.size > 0 && !allowedHosts.has(originUrl.host.toLowerCase())) {
        return { ok: false, reason: 'Origin header does not match host.' };
      }
    } catch {
      return { ok: false, reason: 'Malformed Origin header.' };
    }
  } else if (process.env.NODE_ENV === 'production') {
    // In production browsers, state-changing fetch requests include Origin
    return { ok: false, reason: 'Missing Origin header.' };
  }

  return { ok: true };
}
