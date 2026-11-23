// ============================================================
// UnlockPage — Enter Master Password to Decrypt Vault Locally
// Separate boundary from application auth & MFA.
// Preserves unsynced local state and surfaces pre-unlock conflicts.
// ============================================================

'use client';

import { useState } from 'react';
import { unlockVault, loadSyncMetadata } from '@/lib/vaultService';
import { useVaultStore } from '@/store/vaultStore';
import {
  ShieldCheck,
  Eye,
  EyeOff,
  Cloud,
  CloudOff,
  HardDrive,
  KeyRound,
  LogOut,
  AlertTriangle,
} from 'lucide-react';
import type { EncryptedVaultBlob, VaultConflict } from '@/lib/types';

interface Props {
  cloudEnabled?: boolean;
  userEmail?: string | null;
  remoteBlob?: EncryptedVaultBlob | null;
  pendingConflict?: VaultConflict | null;
  cloudOfflineWarning?: string | null;
  deepLinkItemId?: string | null;
  onSignOut?: () => void;
}

export default function UnlockPage({
  cloudEnabled,
  userEmail,
  remoteBlob,
  pendingConflict,
  cloudOfflineWarning,
  deepLinkItemId,
  onSignOut,
}: Props) {
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
      // CRITICAL: When a local/cloud conflict exists, ALWAYS unlock the local
      // encrypted blob first so unsynced local data is preserved for resolution.
      const blobToDecrypt = pendingConflict ? undefined : (remoteBlob ?? undefined);
      const result = await unlockVault(password, blobToDecrypt);
      const syncMeta = loadSyncMetadata();

      unlock(result.key, result.vault, result.salt, result.revision, {
        migratedFromV1: result.migratedFromV1,
        pendingConflict: pendingConflict ?? null,
        hasUnsavedChanges: Boolean(syncMeta?.hasUnsavedLocalChanges),
        offlineCloud: Boolean(cloudOfflineWarning),
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to unlock vault.';
      if (msg.toLowerCase().includes('decryption')) {
        setError('Incorrect master password or tampered vault envelope.');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
      setPassword('');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-7">
          <div className="w-16 h-16 bg-vault-elevated border border-vault-accent/40 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-vault-accent/10">
            <ShieldCheck className="w-8 h-8 text-vault-accent" />
          </div>
          <h1 className="text-2xl font-bold text-vault-soft tracking-tight">
            NMark Pass Vault
          </h1>
          <p className="text-vault-muted text-sm mt-1.5 text-center">
            Enter your master password to decrypt locally
          </p>

          <div className="mt-3 inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-vault-surface border border-vault-border text-xs text-vault-muted">
            {cloudEnabled ? (
              cloudOfflineWarning ? (
                <>
                  <CloudOff className="w-3.5 h-3.5 text-amber-400" />
                  <span>Cloud Unreachable · Local Cache</span>
                </>
              ) : (
                <>
                  <Cloud className="w-3.5 h-3.5 text-vault-accent" />
                  <span>MFA Verified · {userEmail ?? 'Cloud Sync'}</span>
                </>
              )
            ) : (
              <>
                <HardDrive className="w-3.5 h-3.5 text-vault-accent" />
                <span>Local Encrypted Vault</span>
              </>
            )}
          </div>
        </div>

        {pendingConflict && (
          <div
            role="alert"
            className="mb-4 bg-amber-950/50 border border-amber-500/50 rounded-xl px-4 py-3 text-xs text-amber-200 flex items-start gap-2.5"
          >
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>
              Local vault (rev #{pendingConflict.localRevision}) and cloud vault (rev #
              {pendingConflict.remoteRevision}) have diverged. Unlock with your local master
              password to resolve safely without losing changes.
            </span>
          </div>
        )}

        {cloudOfflineWarning && !pendingConflict && (
          <div
            role="status"
            className="mb-4 bg-amber-950/30 border border-amber-600/40 rounded-xl px-4 py-3 text-xs text-amber-200 flex items-start gap-2.5"
          >
            <CloudOff className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>{cloudOfflineWarning}</span>
          </div>
        )}

        {deepLinkItemId && (
          <div className="mb-4 bg-vault-elevated/80 border border-vault-accent/30 rounded-xl px-4 py-3 text-xs text-vault-soft flex items-center gap-2.5">
            <KeyRound className="w-4 h-4 text-vault-accent shrink-0" />
            <span>
              Unlock your vault to open entry{' '}
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
              htmlFor="vault-master-password"
              className="block text-sm font-medium text-vault-soft/90 mb-1.5"
            >
              Master Password
            </label>
            <div className="relative">
              <input
                id="vault-master-password"
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent text-sm"
                placeholder="Master password"
                autoComplete="current-password"
                autoFocus
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

          <button
            type="submit"
            disabled={loading || password.length === 0}
            className="w-full bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg font-semibold py-2.5 rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
                Deriving key &amp; unlocking...
              </>
            ) : (
              'Unlock Vault'
            )}
          </button>

          {cloudEnabled && onSignOut && (
            <button
              type="button"
              onClick={onSignOut}
              className="w-full flex items-center justify-center gap-2 text-xs text-vault-muted hover:text-vault-soft pt-1 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign out of cloud session
            </button>
          )}
        </form>

        <p className="text-center text-xs text-vault-muted/70 mt-6">
          AES-256-GCM (AAD) + Argon2id (64 MiB) · Zero-Knowledge
        </p>
      </div>
    </div>
  );
}
