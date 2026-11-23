// ============================================================
// ConflictModal — Safe Multi-Tab & Cloud Sync Conflict Recovery
// Never silently overwrites newer encrypted vault data.
// ============================================================

'use client';

import { useState } from 'react';
import { AlertTriangle, Download, RefreshCw, ShieldAlert } from 'lucide-react';
import { useVaultStore } from '@/store/vaultStore';
import { decryptVault, base64ToBuf, deriveKey } from '@/lib/crypto';
import { exportVault, triggerDownload } from '@/lib/vaultService';

export default function ConflictModal() {
  const {
    conflict,
    cryptoKey,
    resolveConflictKeepLocal,
    resolveConflictAcceptRemote,
  } = useVaultStore();

  const [busy, setBusy] = useState(false);
  const [needPassword, setNeedPassword] = useState(false);
  const [masterPw, setMasterPw] = useState('');
  const [error, setError] = useState('');

  if (!conflict) return null;

  const handleDownloadLocalBackup = () => {
    const json = exportVault();
    if (!json) return;
    const filename = `nmark-vault-conflict-backup-${new Date().toISOString().split('T')[0]}.json`;
    triggerDownload(json, filename);
  };

  const handleAcceptRemote = async () => {
    setError('');
    setBusy(true);
    try {
      let keyToUse = cryptoKey;
      if (needPassword) {
        if (!masterPw) {
          setError('Enter the master password for the newer remote vault.');
          setBusy(false);
          return;
        }
        const salt = base64ToBuf(conflict.remoteBlob.kdf.salt);
        keyToUse = await deriveKey(masterPw, salt, {
          memory: conflict.remoteBlob.kdf.memory,
          iterations: conflict.remoteBlob.kdf.iterations,
          parallelism: conflict.remoteBlob.kdf.parallelism,
        });
      }

      if (!keyToUse) {
        setNeedPassword(true);
        setBusy(false);
        return;
      }

      try {
        const remoteVault = await decryptVault(conflict.remoteBlob, keyToUse);
        await resolveConflictAcceptRemote(remoteVault, conflict.remoteBlob);
      } catch {
        // Remote vault may have been re-keyed with a new master password
        setNeedPassword(true);
        setError(
          'Could not decrypt remote revision with current session key. Enter its master password.'
        );
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load remote vault.');
    } finally {
      setBusy(false);
    }
  };

  const handleKeepLocal = async () => {
    setError('');
    setBusy(true);
    try {
      await resolveConflictKeepLocal();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to push local revision.');
    } finally {
      setBusy(false);
    }
  };

  const reasonDetail =
    conflict.reason === 'equal_revision_diverged'
      ? `Both local and cloud are at revision #${conflict.remoteRevision}, but their encrypted ciphertexts differ (concurrent offline edits).`
      : conflict.reason === 'unsaved_local_changes'
        ? `This browser has unsynced local changes (rev #${conflict.localRevision}) while cloud holds revision #${conflict.remoteRevision}.`
        : conflict.reason === 'local_ahead_of_cloud'
          ? `Local vault (rev #${conflict.localRevision}) is ahead of cloud (rev #${conflict.remoteRevision}).`
          : `Another ${conflict.source === 'cloud' ? 'device' : 'browser tab'} saved revision #${conflict.remoteRevision} while this session was based on revision #${conflict.localRevision}.`;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="conflict-title"
    >
      <div className="bg-vault-surface border border-amber-500/50 rounded-2xl w-full max-w-lg p-6 space-y-5 shadow-2xl">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h2 id="conflict-title" className="text-lg font-bold text-vault-soft">
              {conflict.source === 'cloud'
                ? 'Cloud Sync Conflict Detected'
                : 'Multi-Tab Modification Detected'}
            </h2>
            <p className="text-xs text-vault-muted mt-1 leading-relaxed">
              {reasonDetail} Your local data was preserved and nothing was overwritten.
            </p>
          </div>
        </div>

        <div className="bg-vault-bg/80 border border-vault-border rounded-xl p-3.5 text-xs text-vault-muted space-y-1.5">
          <p className="font-medium text-vault-soft">Recommended recovery steps:</p>
          <p>1. Export a local encrypted backup first for safety.</p>
          <p>
            2. Choose <strong className="text-vault-soft">Load Newer Revision</strong> (saves
            local state as a recovery snapshot) or{' '}
            <strong className="text-vault-soft">Keep My Local Changes</strong> (saves remote
            state as a recovery snapshot before superseding it).
          </p>
        </div>

        {needPassword && (
          <div>
            <label className="block text-xs font-medium text-vault-soft mb-1.5">
              Master Password for Remote Revision #{conflict.remoteRevision}
            </label>
            <input
              type="password"
              value={masterPw}
              onChange={(e) => setMasterPw(e.target.value)}
              placeholder="Enter master password"
              className="w-full bg-vault-bg border border-vault-border rounded-xl px-3.5 py-2 text-sm text-vault-soft focus:outline-none focus:border-vault-accent"
            />
          </div>
        )}

        {error && (
          <div className="bg-red-950/60 border border-red-700/70 text-red-200 text-xs rounded-xl px-3.5 py-2.5 flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex flex-col gap-2.5 pt-1">
          <button
            type="button"
            onClick={handleDownloadLocalBackup}
            className="w-full flex items-center justify-center gap-2 bg-vault-elevated hover:bg-vault-border text-vault-soft text-sm font-medium py-2.5 rounded-xl border border-vault-border transition-colors"
          >
            <Download className="w-4 h-4 text-vault-accent" />
            1. Export Encrypted Local Backup First
          </button>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <button
              type="button"
              disabled={busy}
              onClick={handleAcceptRemote}
              className="flex items-center justify-center gap-2 bg-vault-accent hover:bg-vault-accent-hover disabled:opacity-50 text-vault-bg text-sm font-semibold py-2.5 px-4 rounded-xl transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${busy ? 'animate-spin' : ''}`} />
              Load Newer (#{conflict.remoteRevision})
            </button>

            <button
              type="button"
              disabled={busy}
              onClick={handleKeepLocal}
              className="flex items-center justify-center gap-2 bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/50 disabled:opacity-50 text-amber-200 text-sm font-medium py-2.5 px-4 rounded-xl transition-colors"
            >
              Keep My Local Changes
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
