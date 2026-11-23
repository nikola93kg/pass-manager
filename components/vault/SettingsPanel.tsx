// ============================================================
// SettingsPanel — Security Controls, Verified Backup Import,
// Recovery Snapshots, Cloud Migration, and Safe Reset.
// ============================================================

'use client';

import { useState, useRef, useEffect } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import {
  exportVault,
  triggerDownload,
  changePassword,
  verifyMasterPassword,
  verifyBackupImport,
  commitVerifiedBackupImport,
  listRecoverySnapshots,
  restoreRecoverySnapshot,
  safeResetVault,
  createRecoverySnapshot,
  loadBlob,
  type VerifiedBackupResult,
} from '@/lib/vaultService';
import { pushCloudVault } from '@/lib/cloudSync';
import {
  Save,
  Upload,
  Download,
  Lock,
  Eye,
  EyeOff,
  ShieldCheck,
  AlertTriangle,
  History,
  Trash2,
  CloudUpload,
} from 'lucide-react';
import type { RecoverySnapshot } from '@/lib/types';

export default function SettingsPanel() {
  const {
    vault,
    revision,
    syncMode,
    saveSettings,
    lock,
    unlock,
    updateCryptoMaterial,
  } = useVaultStore();

  const settings = vault?.settings ?? {
    autoLockMinutes: 5,
    clipboardClearSeconds: 20,
    lockOnBlur: false,
    autoHidePasswordSeconds: 30,
  };

  const [autoLock, setAutoLock] = useState(settings.autoLockMinutes);
  const [clipClear, setClipClear] = useState(settings.clipboardClearSeconds);
  const [autoHide, setAutoHide] = useState(settings.autoHidePasswordSeconds ?? 30);
  const [lockOnBlur, setLockOnBlur] = useState(settings.lockOnBlur ?? false);
  const [settingsSaved, setSettingsSaved] = useState(false);
  const [settingsError, setSettingsError] = useState('');

  // Change master password
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [showCurrentPw, setShowCurrentPw] = useState(false);
  const [showNewPw, setShowNewPw] = useState(false);
  const [changePwLoading, setChangePwLoading] = useState(false);
  const [changePwError, setChangePwError] = useState('');
  const [changePwSuccess, setChangePwSuccess] = useState(false);

  // Verified Backup Import (never overwrites before decrypting!)
  const fileRef = useRef<HTMLInputElement>(null);
  const [pendingImportJson, setPendingImportJson] = useState<string | null>(null);
  const [pendingImportName, setPendingImportName] = useState('');
  const [importPw, setImportPw] = useState('');
  const [verifiedPreview, setVerifiedPreview] = useState<VerifiedBackupResult | null>(null);
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState('');
  const [importSuccess, setImportSuccess] = useState('');

  // Recovery snapshots
  const [snapshots, setSnapshots] = useState<RecoverySnapshot[]>([]);
  const [restoreTarget, setRestoreTarget] = useState<RecoverySnapshot | null>(null);
  const [restorePw, setRestorePw] = useState('');
  const [restoreError, setRestoreError] = useState('');
  const [restoreBusy, setRestoreBusy] = useState(false);

  // Safe Reset
  const [confirmResetOpen, setConfirmResetOpen] = useState(false);
  const [resetPhrase, setResetPhrase] = useState('');
  const [exportedBeforeReset, setExportedBeforeReset] = useState(false);

  // Manual Cloud Sync
  const [cloudMigrateMsg, setCloudMigrateMsg] = useState('');

  useEffect(() => {
    setSnapshots(listRecoverySnapshots());
  }, [revision]);

  const handleSaveSettings = async () => {
    setSettingsError('');
    setSettingsSaved(false);
    try {
      await saveSettings({
        autoLockMinutes: autoLock,
        clipboardClearSeconds: clipClear,
        lockOnBlur,
        autoHidePasswordSeconds: autoHide,
      });
      setSettingsSaved(true);
      setTimeout(() => setSettingsSaved(false), 2500);
    } catch (err: unknown) {
      setSettingsError(err instanceof Error ? err.message : 'Failed to save.');
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setChangePwError('');
    setChangePwSuccess(false);

    if (!currentPw) {
      setChangePwError('Please enter your current master password.');
      return;
    }
    if (newPw.length < 12) {
      setChangePwError('New master password must be at least 12 characters.');
      return;
    }
    if (newPw !== confirmPw) {
      setChangePwError('Passwords do not match.');
      return;
    }
    if (!vault) return;

    setChangePwLoading(true);
    try {
      const valid = await verifyMasterPassword(currentPw);
      if (!valid) {
        setChangePwError('Current master password is incorrect.');
        return;
      }

      const { key, salt, blob, revision: nextRev } = await changePassword(
        vault,
        newPw,
        revision
      );
      await updateCryptoMaterial(key, salt, nextRev, blob);
      setSnapshots(listRecoverySnapshots());
      setChangePwSuccess(true);
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
      setTimeout(() => setChangePwSuccess(false), 3500);
    } catch (err: unknown) {
      setChangePwError(err instanceof Error ? err.message : 'Failed to change password.');
    } finally {
      setChangePwLoading(false);
    }
  };

  const handleExport = () => {
    const json = exportVault();
    if (!json) return;
    const filename = `nmark-vault-backup-${new Date().toISOString().split('T')[0]}.json`;
    triggerDownload(json, filename);
    setExportedBeforeReset(true);
  };

  const handleSelectImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError('');
    setImportSuccess('');
    setVerifiedPreview(null);
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setImportError('Backup file exceeds the 5 MiB limit.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result;
      if (typeof content !== 'string') return;
      setPendingImportJson(content);
      setPendingImportName(file.name);
    };
    reader.readAsText(file);
    if (fileRef.current) fileRef.current.value = '';
  };

  const handleVerifyImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pendingImportJson || !importPw) return;
    setImportError('');
    setImportBusy(true);
    try {
      const verified = await verifyBackupImport(pendingImportJson, importPw);
      setVerifiedPreview(verified);
    } catch (err: unknown) {
      setImportError(
        err instanceof Error
          ? err.message
          : 'Backup verification failed. Your existing vault was not modified.'
      );
    } finally {
      setImportBusy(false);
      setImportPw('');
    }
  };

  const handleCommitImport = async () => {
    if (!verifiedPreview) return;
    setImportBusy(true);
    setImportError('');
    try {
      const { blob, revision: newRev } = await commitVerifiedBackupImport(verifiedPreview);
      if (syncMode === 'cloud') {
        await pushCloudVault(blob, revision);
      }
      unlock(verifiedPreview.key, verifiedPreview.vault, verifiedPreview.salt, newRev);
      setSnapshots(listRecoverySnapshots());
      setVerifiedPreview(null);
      setPendingImportJson(null);
      setPendingImportName('');
      setImportSuccess(
        `Verified backup restored (${verifiedPreview.itemCount} entries). Previous vault saved to Recovery Snapshots.`
      );
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : 'Failed to commit backup.');
    } finally {
      setImportBusy(false);
    }
  };

  const handleRestoreSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!restoreTarget || !restorePw) return;
    setRestoreError('');
    setRestoreBusy(true);
    try {
      const res = await restoreRecoverySnapshot(restoreTarget, restorePw);
      if (syncMode === 'cloud') {
        await pushCloudVault(res.blob, revision);
      }
      unlock(res.key, res.vault, res.salt, res.revision);
      setRestoreTarget(null);
      setRestorePw('');
      setSnapshots(listRecoverySnapshots());
    } catch (err: unknown) {
      setRestoreError(
        err instanceof Error ? err.message : 'Incorrect master password for this snapshot.'
      );
    } finally {
      setRestoreBusy(false);
    }
  };

  const handleSafeReset = () => {
    if (resetPhrase !== 'RESET VAULT') return;
    safeResetVault();
    lock();
    window.location.reload();
  };

  const handleCreateManualSnapshot = () => {
    createRecoverySnapshot('manual');
    setSnapshots(listRecoverySnapshots());
  };

  const handleManualCloudPush = async () => {
    setCloudMigrateMsg('');
    const local = loadBlob();
    if (!local || local.version !== 2) {
      setCloudMigrateMsg('No v2 local encrypted blob available to sync.');
      return;
    }
    try {
      await pushCloudVault(local, Math.max(0, local.revision - 1));
      setCloudMigrateMsg('Encrypted vault synced to cloud.');
    } catch (err: unknown) {
      setCloudMigrateMsg(err instanceof Error ? err.message : 'Cloud sync failed.');
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-xl space-y-6">
        <div>
          <h2 className="text-xl font-bold text-vault-soft">Security &amp; Settings</h2>
          <p className="text-xs text-vault-muted mt-1">
            All vault changes are encrypted locally with AES-256-GCM (AAD) before storage.
          </p>
        </div>

        {/* Auto-Lock & Session Security */}
        <section className="bg-vault-surface border border-vault-border rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-vault-soft">
            <Lock className="w-4 h-4 text-vault-accent" />
            Auto-Lock &amp; Clipboard Security
          </div>

          <div>
            <label className="block text-sm text-vault-muted mb-1.5">
              Lock after inactivity:{' '}
              <span className="text-vault-soft font-mono">{autoLock} min</span>
            </label>
            <input
              type="range"
              min={1}
              max={60}
              value={autoLock}
              onChange={(e) => setAutoLock(Number(e.target.value))}
              className="w-full accent-vault-accent"
            />
          </div>

          <div>
            <label className="block text-sm text-vault-muted mb-1.5">
              Best-effort clipboard clear after:{' '}
              <span className="text-vault-soft font-mono">{clipClear}s</span>
            </label>
            <input
              type="range"
              min={5}
              max={120}
              value={clipClear}
              onChange={(e) => setClipClear(Number(e.target.value))}
              className="w-full accent-vault-accent"
            />
          </div>

          <div>
            <label className="block text-sm text-vault-muted mb-1.5">
              Auto-hide revealed passwords after:{' '}
              <span className="text-vault-soft font-mono">{autoHide}s</span>
            </label>
            <input
              type="range"
              min={5}
              max={120}
              value={autoHide}
              onChange={(e) => setAutoHide(Number(e.target.value))}
              className="w-full accent-vault-accent"
            />
          </div>

          <label className="flex items-start gap-3 pt-1 cursor-pointer">
            <input
              type="checkbox"
              checked={lockOnBlur}
              onChange={(e) => setLockOnBlur(e.target.checked)}
              className="mt-1 rounded border-vault-border bg-vault-bg accent-vault-accent"
            />
            <span className="text-sm text-vault-soft">
              Lock immediately when switching tabs or windows
              <span className="block text-xs text-vault-muted mt-0.5">
                Off by default so you can switch windows to paste credentials or pick backup files.
              </span>
            </span>
          </label>

          {settingsError && <p className="text-sm text-red-400">{settingsError}</p>}
          <button
            onClick={handleSaveSettings}
            className="flex items-center gap-2 bg-vault-accent hover:bg-vault-accent-hover text-vault-bg text-sm font-semibold px-4 py-2.5 rounded-xl transition-colors"
          >
            <Save className="w-4 h-4" />
            {settingsSaved ? 'Saved!' : 'Save Security Settings'}
          </button>
        </section>

        {/* Change Master Password */}
        <section className="bg-vault-surface border border-vault-border rounded-2xl p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-vault-soft mb-4">
            <ShieldCheck className="w-4 h-4 text-vault-accent" />
            Rotate Master Password
          </div>
          <form onSubmit={handleChangePassword} className="space-y-3">
            <div className="relative">
              <input
                type={showCurrentPw ? 'text' : 'password'}
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                placeholder="Current master password"
                className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowCurrentPw((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-vault-muted hover:text-vault-soft"
                aria-label={showCurrentPw ? 'Hide current password' : 'Show current password'}
              >
                {showCurrentPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <div className="relative">
              <input
                type={showNewPw ? 'text' : 'password'}
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                placeholder="New master password (min. 12 characters)"
                className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setShowNewPw((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-vault-muted hover:text-vault-soft"
                aria-label={showNewPw ? 'Hide new password' : 'Show new password'}
              >
                {showNewPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <input
              type={showNewPw ? 'text' : 'password'}
              value={confirmPw}
              onChange={(e) => setConfirmPw(e.target.value)}
              placeholder="Confirm new master password"
              className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
              autoComplete="new-password"
            />
            {changePwError && <p className="text-sm text-red-400">{changePwError}</p>}
            {changePwSuccess && (
              <p className="text-sm text-emerald-400">
                Master password rotated with fresh salt &amp; recovery snapshot!
              </p>
            )}
            <button
              type="submit"
              disabled={changePwLoading || !currentPw || !newPw || !confirmPw}
              className="flex items-center gap-2 bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg text-sm font-semibold px-4 py-2.5 rounded-xl transition-colors"
            >
              {changePwLoading ? (
                <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
              ) : (
                <ShieldCheck className="w-4 h-4" />
              )}
              {changePwLoading ? 'Re-encrypting vault...' : 'Change Master Password'}
            </button>
          </form>
        </section>

        {/* Verified Backup & Restore */}
        <section className="bg-vault-surface border border-vault-border rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-vault-soft">
            <Download className="w-4 h-4 text-vault-accent" />
            Encrypted Backup &amp; Verified Import
          </div>

          <div className="space-y-3">
            <p className="text-xs text-vault-muted leading-relaxed">
              Backups export your <strong className="text-vault-soft">encrypted envelope only</strong>{' '}
              (Format v2). Before any import replaces your current vault, you must verify its
              master password and an encrypted recovery snapshot is saved automatically.
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={handleExport}
                className="flex items-center gap-2 bg-vault-elevated hover:bg-vault-border text-vault-soft text-sm font-medium px-4 py-2.5 rounded-xl border border-vault-border transition-colors"
              >
                <Download className="w-4 h-4 text-vault-accent" />
                Export Encrypted Backup
              </button>
              <button
                type="button"
                onClick={handleCreateManualSnapshot}
                className="flex items-center gap-2 bg-vault-bg hover:bg-vault-elevated text-vault-muted hover:text-vault-soft text-sm font-medium px-4 py-2.5 rounded-xl border border-vault-border transition-colors"
              >
                <History className="w-4 h-4 text-vault-accent" />
                Save Recovery Snapshot
              </button>
              {syncMode === 'cloud' && (
                <button
                  type="button"
                  onClick={handleManualCloudPush}
                  className="flex items-center gap-2 bg-vault-bg hover:bg-vault-elevated text-vault-muted hover:text-vault-soft text-sm font-medium px-4 py-2.5 rounded-xl border border-vault-border transition-colors"
                >
                  <CloudUpload className="w-4 h-4 text-vault-accent" />
                  Push to Cloud
                </button>
              )}
            </div>
            {cloudMigrateMsg && (
              <p className="text-xs text-vault-accent">{cloudMigrateMsg}</p>
            )}

            <div className="border-t border-vault-border pt-4 space-y-3">
              <input
                ref={fileRef}
                type="file"
                accept=".json"
                onChange={handleSelectImportFile}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                className="flex items-center gap-2 bg-vault-elevated hover:bg-vault-border text-vault-soft text-sm font-medium px-4 py-2.5 rounded-xl border border-vault-border transition-colors"
              >
                <Upload className="w-4 h-4 text-vault-accent" />
                {pendingImportName ? `Selected: ${pendingImportName}` : 'Select Encrypted Backup to Import'}
              </button>

              {pendingImportJson && !verifiedPreview && (
                <form
                  onSubmit={handleVerifyImport}
                  className="bg-vault-bg border border-vault-border rounded-xl p-4 space-y-3"
                >
                  <p className="text-xs text-vault-muted">
                    Step 1: Enter the master password of <strong className="text-vault-soft">{pendingImportName}</strong> to verify decryptability before replacing your current vault.
                  </p>
                  <input
                    type="password"
                    value={importPw}
                    onChange={(e) => setImportPw(e.target.value)}
                    placeholder="Backup master password"
                    className="w-full bg-vault-surface border border-vault-border rounded-lg px-3.5 py-2 text-sm text-vault-soft focus:outline-none focus:border-vault-accent"
                    required
                  />
                  <div className="flex gap-2">
                    <button
                      type="submit"
                      disabled={importBusy || !importPw}
                      className="bg-vault-accent hover:bg-vault-accent-hover disabled:opacity-50 text-vault-bg text-xs font-semibold px-4 py-2 rounded-lg"
                    >
                      {importBusy ? 'Verifying...' : 'Verify Backup'}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setPendingImportJson(null);
                        setPendingImportName('');
                        setImportPw('');
                      }}
                      className="text-xs text-vault-muted hover:text-vault-soft px-3 py-2"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}

              {verifiedPreview && (
                <div className="bg-emerald-950/30 border border-emerald-600/50 rounded-xl p-4 space-y-3">
                  <p className="text-xs text-emerald-200">
                    Backup verified! Format v{verifiedPreview.sourceVersion} containing{' '}
                    <strong>{verifiedPreview.itemCount} entries</strong>. Your existing vault
                    will be snapshotted before restoring.
                  </p>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={importBusy}
                      onClick={handleCommitImport}
                      className="bg-emerald-500 hover:bg-emerald-400 text-vault-bg text-xs font-semibold px-4 py-2 rounded-lg"
                    >
                      {importBusy ? 'Restoring...' : 'Confirm & Replace Active Vault'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setVerifiedPreview(null)}
                      className="text-xs text-vault-muted hover:text-vault-soft px-3 py-2"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {importError && <p className="text-sm text-red-400">{importError}</p>}
              {importSuccess && <p className="text-sm text-emerald-400">{importSuccess}</p>}
            </div>
          </div>
        </section>

        {/* Encrypted Recovery Snapshots */}
        {snapshots.length > 0 && (
          <section className="bg-vault-surface border border-vault-border rounded-2xl p-5 space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-vault-soft">
              <History className="w-4 h-4 text-vault-accent" />
              Encrypted Recovery Snapshots ({snapshots.length})
            </div>
            <p className="text-xs text-vault-muted">
              Automatic encrypted restore points created before risky operations.
            </p>
            <div className="space-y-2">
              {snapshots.map((snap) => (
                <div
                  key={`${snap.createdAt}-${snap.reason}`}
                  className="flex items-center justify-between gap-3 bg-vault-bg border border-vault-border rounded-xl px-3.5 py-2.5 text-xs"
                >
                  <div>
                    <p className="text-vault-soft font-medium capitalize">
                      {snap.reason.replace('_', ' ')} · v{snap.blob.version}
                    </p>
                    <p className="text-vault-muted">
                      {new Date(snap.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setRestoreTarget(snap);
                      setRestoreError('');
                      setRestorePw('');
                    }}
                    className="px-3 py-1.5 rounded-lg bg-vault-elevated hover:bg-vault-border text-vault-accent font-medium"
                  >
                    Restore
                  </button>
                </div>
              ))}
            </div>

            {restoreTarget && (
              <form
                onSubmit={handleRestoreSnapshot}
                className="bg-vault-bg border border-vault-accent/40 rounded-xl p-4 space-y-3 mt-2"
              >
                <p className="text-xs text-vault-soft">
                  Enter the master password for the snapshot from{' '}
                  <strong>{new Date(restoreTarget.createdAt).toLocaleString()}</strong>:
                </p>
                <input
                  type="password"
                  value={restorePw}
                  onChange={(e) => setRestorePw(e.target.value)}
                  placeholder="Snapshot master password"
                  className="w-full bg-vault-surface border border-vault-border rounded-lg px-3.5 py-2 text-sm text-vault-soft focus:outline-none focus:border-vault-accent"
                  required
                />
                {restoreError && <p className="text-xs text-red-400">{restoreError}</p>}
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={restoreBusy || !restorePw}
                    className="bg-vault-accent hover:bg-vault-accent-hover text-vault-bg text-xs font-semibold px-4 py-2 rounded-lg"
                  >
                    {restoreBusy ? 'Verifying...' : 'Verify & Restore Snapshot'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setRestoreTarget(null)}
                    className="text-xs text-vault-muted hover:text-vault-soft px-3 py-2"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </section>
        )}

        {/* Safe Reset Danger Zone */}
        <section className="bg-vault-surface border border-red-900/50 rounded-2xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Safe Local Vault Reset
          </div>
          <p className="text-xs text-vault-muted leading-relaxed">
            Resets the active local vault in this browser. An encrypted recovery snapshot is
            automatically stored before clearing, and exporting an offline backup first is
            strongly recommended.
          </p>
          {!confirmResetOpen ? (
            <button
              type="button"
              onClick={() => setConfirmResetOpen(true)}
              className="flex items-center gap-2 bg-red-950/60 hover:bg-red-900/60 border border-red-700/60 text-red-200 text-xs font-medium px-4 py-2 rounded-xl transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Begin Safe Reset...
            </button>
          ) : (
            <div className="bg-red-950/30 border border-red-800/60 rounded-xl p-4 space-y-3">
              {!exportedBeforeReset && (
                <button
                  type="button"
                  onClick={handleExport}
                  className="text-xs text-vault-accent hover:underline flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download encrypted backup before resetting
                </button>
              )}
              <input
                type="text"
                value={resetPhrase}
                onChange={(e) => setResetPhrase(e.target.value)}
                placeholder='Type "RESET VAULT" to confirm'
                className="w-full bg-vault-bg border border-red-800/60 rounded-lg px-3 py-2 text-xs text-vault-soft"
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={resetPhrase !== 'RESET VAULT'}
                  onClick={handleSafeReset}
                  className="bg-red-600 hover:bg-red-500 disabled:opacity-40 text-white text-xs font-semibold px-4 py-2 rounded-lg"
                >
                  Confirm Local Reset
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setConfirmResetOpen(false);
                    setResetPhrase('');
                  }}
                  className="text-xs text-vault-muted hover:text-vault-soft px-3 py-2"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </section>

        {/* Crypto info */}
        <section className="bg-vault-surface/50 border border-vault-border rounded-2xl p-4">
          <p className="text-xs text-vault-muted leading-relaxed">
            <strong className="text-vault-soft">Cryptography:</strong> Format v2 · AES-256-GCM
            with authenticated envelope metadata (AAD) + Argon2id (64 MiB, 3 iterations, 1
            lane). Master passwords never leave this browser.
          </p>
        </section>
      </div>
    </div>
  );
}
