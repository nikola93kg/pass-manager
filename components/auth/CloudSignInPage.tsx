// ============================================================
// CloudSignInPage — Single-Admin Application Authentication
// Separate security boundary from Master Password vault unlock.
// Public sign-up is intentionally disabled.
// ============================================================

'use client';

import { useState } from 'react';
import { ShieldCheck, Eye, EyeOff, Lock, KeyRound } from 'lucide-react';
import type { AuthSessionState } from '@/lib/types';

interface Props {
  onSignedIn: (session: AuthSessionState) => void;
  deepLinkItemId?: string | null;
}

export default function CloudSignInPage({ onSignedIn, deepLinkItemId }: Props) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('/api/auth/session', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || 'Authentication failed.');
        return;
      }

      onSignedIn(data as AuthSessionState);
    } catch {
      setError('Unable to reach authentication service.');
    } finally {
      setLoading(false);
      setPassword('');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 bg-vault-elevated border border-vault-accent/40 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-vault-accent/10">
            <ShieldCheck className="w-8 h-8 text-vault-accent" />
          </div>
          <h1 className="text-2xl font-bold text-vault-soft tracking-tight">
            NMark Pass Vault
          </h1>
          <p className="text-vault-muted text-sm mt-1.5 text-center">
            Step 1 of 3 · Sign in to your private admin account
          </p>
        </div>

        {deepLinkItemId && (
          <div className="mb-4 bg-vault-elevated/80 border border-vault-accent/30 rounded-xl px-4 py-3 text-xs text-vault-soft flex items-center gap-2.5">
            <KeyRound className="w-4 h-4 text-vault-accent shrink-0" />
            <span>
              Authenticate, verify MFA, and unlock your vault to view entry{' '}
              <code className="font-mono text-vault-accent">{deepLinkItemId}</code>.
            </span>
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          className="bg-vault-surface border border-vault-border rounded-2xl p-6 space-y-4 shadow-xl shadow-black/40"
        >
          <div>
            <label
              htmlFor="admin-email"
              className="block text-sm font-medium text-vault-soft/90 mb-1.5"
            >
              Admin Email
            </label>
            <input
              id="admin-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent text-sm"
              placeholder="admin@nmarkdesigns.com"
              autoComplete="username"
              autoFocus
              required
            />
          </div>

          <div>
            <label
              htmlFor="admin-password"
              className="block text-sm font-medium text-vault-soft/90 mb-1.5"
            >
              Account Password
            </label>
            <div className="relative">
              <input
                id="admin-password"
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent text-sm"
                placeholder="Supabase account password"
                autoComplete="current-password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPw((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-vault-muted hover:text-vault-soft"
                aria-label={showPw ? 'Hide password' : 'Show password'}
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="bg-red-950/60 border border-red-700/70 text-red-200 text-sm rounded-xl px-4 py-3"
            >
              {error}
            </div>
          )}

          <div className="bg-vault-bg/70 border border-vault-border rounded-xl px-3.5 py-2.5 text-xs text-vault-muted flex items-start gap-2">
            <Lock className="w-3.5 h-3.5 text-vault-accent shrink-0 mt-0.5" />
            <span>
              Your account login only unlocks encrypted cloud sync. Your separate{' '}
              <strong className="text-vault-soft">Master Password</strong> is never sent to
              the server and is required afterward to decrypt credentials locally.
            </span>
          </div>

          <button
            type="submit"
            disabled={loading || !email || !password}
            className="w-full bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg font-semibold py-2.5 rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
                Signing in...
              </>
            ) : (
              'Continue to MFA Verification'
            )}
          </button>
        </form>

        <p className="text-center text-xs text-vault-muted/70 mt-6">
          Private single-admin vault · Public registration disabled
        </p>
      </div>
    </div>
  );
}
