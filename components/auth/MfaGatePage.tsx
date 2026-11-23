// ============================================================
// MfaGatePage — Mandatory TOTP MFA Enrollment & Verification
// Elevates session from aal1 -> aal2 before encrypted vault access.
// ============================================================

'use client';

import { useState, useEffect } from 'react';
import { ShieldAlert, Smartphone, LogOut, Copy, Check } from 'lucide-react';

interface Props {
  mode: 'enroll' | 'challenge';
  userEmail: string | null;
  onVerified: () => void;
  onSignOut: () => void;
}

export default function MfaGatePage({ mode, userEmail, onVerified, onSignOut }: Props) {
  const [factorId, setFactorId] = useState<string | null>(null);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [enrolling, setEnrolling] = useState(mode === 'enroll');
  const [error, setError] = useState('');

  useEffect(() => {
    if (mode !== 'enroll') return;
    let cancelled = false;

    const startEnroll = async () => {
      setEnrolling(true);
      setError('');
      try {
        const res = await fetch('/api/auth/mfa', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'enroll' }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (!cancelled) setError(data.error || 'Could not initialize TOTP enrollment.');
          return;
        }
        if (!cancelled) {
          setFactorId(data.factorId ?? null);
          setQrCode(data.qrCode ?? null);
          setSecret(data.secret ?? null);
        }
      } catch {
        if (!cancelled) setError('Network error initializing MFA.');
      } finally {
        if (!cancelled) setEnrolling(false);
      }
    };

    void startEnroll();
    return () => {
      cancelled = true;
    };
  }, [mode]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('/api/auth/mfa', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'verify',
          ...(factorId ? { factorId } : {}),
          code: code.trim(),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || 'Invalid authenticator code.');
        return;
      }
      onVerified();
    } catch {
      setError('Unable to verify MFA code.');
    } finally {
      setLoading(false);
      setCode('');
    }
  };

  const copySecret = async () => {
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    } catch {
      // ignore
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-7">
          <div className="w-16 h-16 bg-vault-elevated border border-vault-accent/40 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-vault-accent/10">
            <Smartphone className="w-8 h-8 text-vault-accent" />
          </div>
          <h1 className="text-2xl font-bold text-vault-soft">
            {mode === 'enroll' ? 'Set Up Mandatory MFA' : 'Two-Factor Verification'}
          </h1>
          <p className="text-vault-muted text-sm mt-1.5 text-center">
            Step 2 of 3 · {userEmail ?? 'Admin session'} requires TOTP verification (AAL2)
          </p>
        </div>

        <form
          onSubmit={handleVerify}
          className="bg-vault-surface border border-vault-border rounded-2xl p-6 space-y-5 shadow-xl shadow-black/40"
        >
          {mode === 'enroll' && (
            <div className="space-y-4">
              {enrolling ? (
                <div className="flex items-center justify-center py-8 text-sm text-vault-muted gap-2">
                  <div className="w-4 h-4 border-2 border-vault-accent border-t-transparent rounded-full animate-spin" />
                  Generating authenticator key...
                </div>
              ) : (
                <>
                  <p className="text-xs text-vault-muted leading-relaxed">
                    Scan this QR code in your authenticator app (1Password, Bitwarden,
                    Authy, Google Authenticator, or Yubico Authenticator), then enter the
                    6-digit code below.
                  </p>
                  {qrCode && (
                    <div className="flex justify-center">
                      <div className="bg-white p-3 rounded-xl inline-block">
                        <img
                          src={qrCode}
                          alt="TOTP Authenticator QR Code"
                          className="w-44 h-44"
                        />
                      </div>
                    </div>
                  )}
                  {secret && (
                    <div className="bg-vault-bg border border-vault-border rounded-xl p-3">
                      <p className="text-[11px] uppercase tracking-wider text-vault-muted mb-1">
                        Manual Setup Key
                      </p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 font-mono text-xs text-vault-accent break-all">
                          {secret}
                        </code>
                        <button
                          type="button"
                          onClick={copySecret}
                          className="p-1.5 rounded-lg bg-vault-elevated text-vault-soft hover:text-vault-accent transition-colors"
                          aria-label="Copy setup secret"
                        >
                          {copiedSecret ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          <div>
            <label
              htmlFor="totp-code"
              className="block text-sm font-medium text-vault-soft/90 mb-1.5"
            >
              6-Digit Authenticator Code
            </label>
            <input
              id="totp-code"
              type="text"
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-3 text-center text-xl font-mono tracking-[0.4em] text-vault-soft placeholder-vault-muted/40 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent"
              placeholder="000000"
              autoComplete="one-time-code"
              autoFocus
              required
            />
          </div>

          {error && (
            <div
              role="alert"
              className="bg-red-950/60 border border-red-700/70 text-red-200 text-sm rounded-xl px-4 py-3 flex items-start gap-2"
            >
              <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || enrolling || code.length !== 6}
            className="w-full bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg font-semibold py-2.5 rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
                Verifying...
              </>
            ) : mode === 'enroll' ? (
              'Confirm MFA & Continue'
            ) : (
              'Verify & Continue to Vault'
            )}
          </button>

          <button
            type="button"
            onClick={onSignOut}
            className="w-full flex items-center justify-center gap-2 text-xs text-vault-muted hover:text-vault-soft py-1.5 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out
          </button>
        </form>
      </div>
    </div>
  );
}
