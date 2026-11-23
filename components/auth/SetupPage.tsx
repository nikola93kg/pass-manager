// ============================================================
// SetupPage — First-run: Create Master Password OR Restore Backup
// Branded for NMark Pass Vault.
// ============================================================

'use client';

import { useState, useRef } from 'react';
import {
  createVault,
  verifyBackupImport,
  commitVerifiedBackupImport,
  markCloudSynced,
  markLocalUnsynced,
} from '@/lib/vaultService';
import { pushCloudVault } from '@/lib/cloudSync';
import { useVaultStore } from '@/store/vaultStore';
import { ShieldCheck, Eye, EyeOff, Lock, Upload, LogOut } from 'lucide-react';

interface Props {
  onComplete: () => void;
  cloudEnabled?: boolean;
  onSignOut?: () => void;
}

const STRENGTH_LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
const STRENGTH_COLORS = [
  'bg-red-500',
  'bg-orange-500',
  'bg-amber-400',
  'bg-vault-accent',
  'bg-emerald-400',
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

export default function SetupPage({ onComplete, cloudEnabled, onSignOut }: Props) {
  const unlock = useVaultStore((s) => s.unlock);
  const [tab, setTab] = useState<'create' | 'restore'>('create');

  // Create vault state
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Restore verified backup state
  const fileRef = useRef<HTMLInputElement>(null);
  const [backupJson, setBackupJson] = useState<string | null>(null);
  const [backupFileName, setBackupFileName] = useState('');
  const [backupPw, setBackupPw] = useState('');
  const [showBackupPw, setShowBackupPw] = useState(false);

  const strength = getStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password.length < 12) {
      setError('Master password must be at least 12 characters for production security.');
      return;
    }
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      const { key, vault, salt, revision, blob } = await createVault(password);
      await markLocalUnsynced(blob);
      if (cloudEnabled) {
        await pushCloudVault(blob, 0);
        await markCloudSynced(blob);
      }
      unlock(key, vault, salt, revision);
      onComplete();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Vault setup failed.');
    } finally {
      setLoading(false);
      setPassword('');
      setConfirm('');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError('');
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setError('Backup file exceeds the 5 MiB limit.');
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result;
      if (typeof content === 'string') {
        setBackupJson(content);
        setBackupFileName(file.name);
      }
    };
    reader.readAsText(file);
  };

  const handleRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!backupJson || !backupPw) return;
    setError('');
    setLoading(true);

    try {
      const verified = await verifyBackupImport(backupJson, backupPw);
      const { blob, revision } = await commitVerifiedBackupImport(verified, {
        nextRevision: 1,
      });
      await markLocalUnsynced(blob);
      if (cloudEnabled) {
        await pushCloudVault(blob, 0);
        await markCloudSynced(blob);
      }
      unlock(verified.key, verified.vault, verified.salt, revision);
      onComplete();
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : 'Could not decrypt backup. Verify file integrity and master password.'
      );
    } finally {
      setLoading(false);
      setBackupPw('');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-7">
          <div className="w-16 h-16 bg-vault-elevated border border-vault-accent/40 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-vault-accent/10">
            <ShieldCheck className="w-8 h-8 text-vault-accent" />
          </div>
          <h1 className="text-2xl font-bold text-vault-soft tracking-tight">
            NMark Pass Vault
          </h1>
          <p className="text-vault-muted text-sm mt-1.5 text-center">
            {cloudEnabled
              ? 'Step 3 of 3 · Initialize your zero-knowledge encrypted vault'
              : 'Create a strong master password. It cannot be recovered if lost.'}
          </p>
        </div>

        {/* Mode Switch */}
        <div className="grid grid-cols-2 gap-2 p-1 bg-vault-surface border border-vault-border rounded-xl mb-4">
          <button
            type="button"
            onClick={() => {
              setTab('create');
              setError('');
            }}
            className={`py-2 text-xs font-semibold rounded-lg transition-colors ${
              tab === 'create'
                ? 'bg-vault-accent text-vault-bg'
                : 'text-vault-muted hover:text-vault-soft'
            }`}
          >
            Create New Vault
          </button>
          <button
            type="button"
            onClick={() => {
              setTab('restore');
              setError('');
            }}
            className={`py-2 text-xs font-semibold rounded-lg transition-colors ${
              tab === 'restore'
                ? 'bg-vault-accent text-vault-bg'
                : 'text-vault-muted hover:text-vault-soft'
            }`}
          >
            Restore Encrypted Backup
          </button>
        </div>

        {tab === 'create' ? (
          <form
            onSubmit={handleSubmit}
            className="bg-vault-surface border border-vault-border rounded-2xl p-6 space-y-5 shadow-xl shadow-black/40"
          >
            <div>
              <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
                Master Password (min. 12 characters)
              </label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent text-sm"
                  placeholder="Enter a strong passphrase"
                  autoComplete="new-password"
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

              {password.length > 0 && (
                <div className="mt-2">
                  <div className="flex gap-1 mb-1">
                    {[0, 1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className={`h-1 flex-1 rounded-full transition-colors ${
                          i <= strength ? STRENGTH_COLORS[strength] : 'bg-vault-border'
                        }`}
                      />
                    ))}
                  </div>
                  <p className="text-xs text-vault-muted">
                    Strength:{' '}
                    <span className="font-medium text-vault-soft">
                      {STRENGTH_LABELS[strength]}
                    </span>
                  </p>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
                Confirm Master Password
              </label>
              <div className="relative">
                <input
                  type={showConfirm ? 'text' : 'password'}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent text-sm"
                  placeholder="Re-enter master password"
                  autoComplete="new-password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-vault-muted hover:text-vault-soft"
                  aria-label={showConfirm ? 'Hide password' : 'Show password'}
                >
                  {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {confirm.length > 0 && password !== confirm && (
                <p className="text-xs text-red-400 mt-1">Passwords do not match.</p>
              )}
            </div>

            {error && (
              <div
                role="alert"
                className="bg-red-950/60 border border-red-700/70 text-red-200 text-sm rounded-xl px-4 py-3"
              >
                {error}
              </div>
            )}

            <div className="bg-amber-950/30 border border-amber-600/40 text-amber-200 text-xs rounded-xl px-4 py-3 leading-relaxed">
              <Lock className="w-3.5 h-3.5 inline mr-1.5 -mt-0.5 text-amber-400" />
              Zero-knowledge guarantee: your master password is never stored or sent to
              any server. If you forget it, your encrypted vault cannot be recovered.
            </div>

            <button
              type="submit"
              disabled={loading || password.length === 0 || confirm.length === 0}
              className="w-full bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg font-semibold py-2.5 rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
                  Deriving key with Argon2id...
                </>
              ) : (
                'Create Encrypted Vault'
              )}
            </button>
          </form>
        ) : (
          <form
            onSubmit={handleRestore}
            className="bg-vault-surface border border-vault-border rounded-2xl p-6 space-y-4 shadow-xl shadow-black/40"
          >
            <div>
              <input
                ref={fileRef}
                type="file"
                accept=".json"
                onChange={handleFileChange}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                className="w-full flex items-center justify-center gap-2 bg-vault-bg hover:bg-vault-elevated border border-dashed border-vault-accent/50 rounded-xl px-4 py-4 text-sm text-vault-soft transition-colors"
              >
                <Upload className="w-4 h-4 text-vault-accent" />
                {backupFileName || 'Choose encrypted vault backup (.json)'}
              </button>
            </div>

            <div>
              <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
                Backup Master Password
              </label>
              <div className="relative">
                <input
                  type={showBackupPw ? 'text' : 'password'}
                  value={backupPw}
                  onChange={(e) => setBackupPw(e.target.value)}
                  className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
                  placeholder="Enter master password for this backup"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowBackupPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-vault-muted hover:text-vault-soft"
                  aria-label={showBackupPw ? 'Hide password' : 'Show password'}
                >
                  {showBackupPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
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
              disabled={loading || !backupJson || !backupPw}
              className="w-full bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg font-semibold py-2.5 rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
                  Verifying &amp; Decrypting...
                </>
              ) : (
                'Verify & Restore Backup'
              )}
            </button>
          </form>
        )}

        {cloudEnabled && onSignOut && (
          <button
            type="button"
            onClick={onSignOut}
            className="mt-4 w-full flex items-center justify-center gap-2 text-xs text-vault-muted hover:text-vault-soft py-1.5 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out of cloud account
          </button>
        )}
      </div>
    </div>
  );
}
