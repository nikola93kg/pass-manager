// ============================================================
// SERVER-SIDE AUTHENTICATION, SINGLE-ADMIN & MFA (AAL2) GUARD
// Enforces all three security gates before any vault API access:
// 1. Verified authenticated user (supabase.auth.getUser())
// 2. Single-admin allowlist match (fail-closed)
// 3. Mandatory MFA assurance level === 'aal2'
// ============================================================

import { isUserAllowedAdmin } from '@/lib/env';

export interface AuthGuardClient {
  auth: {
    getUser: () => Promise<{
      data: { user: { id: string; email?: string | null } | null };
      error: unknown;
    }>;
    mfa: {
      getAuthenticatorAssuranceLevel: () => Promise<{
        data: {
          currentLevel: string | null;
          nextLevel: string | null;
        } | null;
        error: unknown;
      }>;
    };
  };
}

export type AuthGuardResult =
  | {
      authorized: true;
      user: { id: string; email: string | null };
      aal: 'aal2';
    }
  | {
      authorized: false;
      status: 401 | 403 | 503;
      code: 'CLOUD_NOT_CONFIGURED' | 'UNAUTHENTICATED' | 'FORBIDDEN_USER' | 'MFA_REQUIRED';
      error: string;
    };

export async function authorizeVaultAccess(
  supabase: AuthGuardClient | null,
  options?: { requireMfa?: boolean }
): Promise<AuthGuardResult> {
  if (!supabase) {
    return {
      authorized: false,
      status: 503,
      code: 'CLOUD_NOT_CONFIGURED',
      error: 'Cloud sync backend is not configured.',
    };
  }

  const { data: userData, error: userError } = await supabase.auth.getUser();
  if (userError || !userData?.user) {
    return {
      authorized: false,
      status: 401,
      code: 'UNAUTHENTICATED',
      error: 'Authentication required.',
    };
  }

  const user = userData.user;
  if (!isUserAllowedAdmin({ id: user.id, email: user.email })) {
    return {
      authorized: false,
      status: 403,
      code: 'FORBIDDEN_USER',
      error: 'Access denied. This vault is restricted to the authorized administrator.',
    };
  }

  const requireMfa = options?.requireMfa ?? true;
  if (requireMfa) {
    const { data: aalData, error: aalError } =
      await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

    if (aalError || !aalData || aalData.currentLevel !== 'aal2') {
      return {
        authorized: false,
        status: 403,
        code: 'MFA_REQUIRED',
        error: 'Multi-factor authentication (TOTP) verification is required.',
      };
    }
  }

  return {
    authorized: true,
    user: { id: user.id, email: user.email ?? null },
    aal: 'aal2',
  };
}
