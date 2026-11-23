// ============================================================
// SetupPage — First-run: create master password
// ============================================================

'use client';

import { useState, useRef } from 'react';
import { createVault } from '@/lib/vaultService';
import { useVaultStore } from '@/store/vaultStore';
import { ShieldCheck, Eye, EyeOff, Lock } from 'lucide-react';

interface Props {
  onComplete: () => void;
}

const STRENGTH_LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
const STRENGTH_COLORS = [
  'bg-red-600',
  'bg-orange-500',
  'bg-yellow-500',
  'bg-blue-500',
  'bg-green-500',
];

function getStrength(pw: string): number {
  let score = 0;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 4);
}

export default function SetupPage({ onComplete }: Props) {
  const unlock = useVaultStore((s) => s.unlock);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const pwRef = useRef<HTMLInputElement>(null);
  const strength = getStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password.length < 8) {
      setError('Master password must be at least 8 characters.');
      return;
    }
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const { key, vault, salt } = await createVault(password);
      unlock(key, vault, salt);
      onComplete();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Setup failed.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950 p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center mb-4">
            <ShieldCheck className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">Create Your Vault</h1>
          <p className="text-gray-400 text-sm mt-2 text-center">
            Choose a strong master password. It cannot be recovered if lost.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="bg-gray-900 rounded-2xl p-6 space-y-5">
          {/* Password field */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Master Password
            </label>
            <div className="relative">
              <input
                ref={pwRef}
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                placeholder="Enter master password"
                autoComplete="new-password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPw((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                aria-label={showPw ? 'Hide password' : 'Show password'}
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {/* Strength meter */}
            {password.length > 0 && (
              <div className="mt-2">
                <div className="flex gap-1 mb-1">
                  {[0, 1, 2, 3, 4].map((i) => (
                    <div
                      key={i}
                      className={`h-1 flex-1 rounded-full transition-colors ${
                        i <= strength ? STRENGTH_COLORS[strength] : 'bg-gray-700'
                      }`}
                    />
                  ))}
                </div>
                <p className="text-xs text-gray-400">
                  Strength:{' '}
                  <span className="font-medium text-gray-200">
                    {STRENGTH_LABELS[strength]}
                  </span>
                </p>
              </div>
            )}
          </div>

          {/* Confirm field */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Confirm Password
            </label>
            <div className="relative">
              <input
                type={showConfirm ? 'text' : 'password'}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                placeholder="Confirm master password"
                autoComplete="new-password"
                required
              />
              <button
                type="button"
                onClick={() => setShowConfirm((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                aria-label={showConfirm ? 'Hide password' : 'Show password'}
              >
                {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {confirm.length > 0 && password !== confirm && (
              <p className="text-xs text-red-400 mt-1">Passwords do not match.</p>
            )}
          </div>

          {/* Error */}
          {error && (
            <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm rounded-lg px-4 py-3">
              {error}
            </div>
          )}

          {/* Warning */}
          <div className="bg-yellow-900/20 border border-yellow-700/50 text-yellow-300 text-xs rounded-lg px-4 py-3">
            <Lock className="w-3.5 h-3.5 inline mr-1.5 -mt-0.5" />
            Your master password is never stored. If you forget it, your data cannot be recovered.
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading || password.length === 0 || confirm.length === 0}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Deriving key with Argon2id...
              </>
            ) : (
              'Create Vault'
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
