// ============================================================
// UnlockPage — Enter master password to decrypt vault
// ============================================================

'use client';

import { useState } from 'react';
import { unlockVault } from '@/lib/vaultService';
import { useVaultStore } from '@/store/vaultStore';
import { ShieldCheck, Eye, EyeOff } from 'lucide-react';

export default function UnlockPage() {
  const unlock = useVaultStore((s) => s.unlock);
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const { key, vault, salt } = await unlockVault(password);
      unlock(key, vault, salt);
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : 'Failed to unlock vault.';
      // Sanitize — don't echo password-derived messages with sensitive content
      if (msg.toLowerCase().includes('decryption')) {
        setError('Incorrect password. Please try again.');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
      setPassword('');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-950 p-4">
      <div className="w-full max-w-sm">
        {/* Header */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center mb-4">
            <ShieldCheck className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">Unlock Vault</h1>
          <p className="text-gray-400 text-sm mt-2">Enter your master password</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="bg-gray-900 rounded-2xl p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Master Password
            </label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                placeholder="Master password"
                autoComplete="current-password"
                autoFocus
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
          </div>

          {error && (
            <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm rounded-lg px-4 py-3">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || password.length === 0}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Unlocking...
              </>
            ) : (
              'Unlock'
            )}
          </button>
        </form>

        <p className="text-center text-xs text-gray-600 mt-6">
          All data is encrypted with AES-256-GCM + Argon2id
        </p>
      </div>
    </div>
  );
}
