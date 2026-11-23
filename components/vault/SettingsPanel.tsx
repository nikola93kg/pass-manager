// ============================================================
// SettingsPanel — auto-lock, clipboard, import, change password
// ============================================================

'use client';

import { useState, useRef } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import {
  importVault,
  exportVault,
  triggerDownload,
  changePassword,
  verifyMasterPassword,
} from '@/lib/vaultService';
import {
  Save,
  Upload,
  Download,
  Lock,
  Eye,
  EyeOff,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';

export default function SettingsPanel() {
  const { vault, saveSettings, lock, updateCryptoMaterial } = useVaultStore();
  const settings = vault?.settings ?? {
    autoLockMinutes: 5,
    clipboardClearSeconds: 20,
    lockOnBlur: false,
  };

  const [autoLock, setAutoLock] = useState(settings.autoLockMinutes);
  const [clipClear, setClipClear] = useState(settings.clipboardClearSeconds);
  const [lockOnBlur, setLockOnBlur] = useState(settings.lockOnBlur ?? false);
  const [settingsSaved, setSettingsSaved] = useState(false);
  const [settingsError, setSettingsError] = useState('');

  // Change password
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [showCurrentPw, setShowCurrentPw] = useState(false);
  const [showNewPw, setShowNewPw] = useState(false);
  const [changePwLoading, setChangePwLoading] = useState(false);
  const [changePwError, setChangePwError] = useState('');
  const [changePwSuccess, setChangePwSuccess] = useState(false);

  // Import
  const fileRef = useRef<HTMLInputElement>(null);
  const [importError, setImportError] = useState('');
  const [importSuccess, setImportSuccess] = useState(false);

  const handleSaveSettings = async () => {
    setSettingsError('');
    setSettingsSaved(false);
    try {
      await saveSettings({
        autoLockMinutes: autoLock,
        clipboardClearSeconds: clipClear,
        lockOnBlur,
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
    if (newPw.length < 8) {
      setChangePwError('Password must be at least 8 characters.');
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

      const { key, salt } = await changePassword(vault, newPw);
      updateCryptoMaterial(key, salt);
      setChangePwSuccess(true);
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
      setTimeout(() => setChangePwSuccess(false), 3000);
    } catch (err: unknown) {
      setChangePwError(err instanceof Error ? err.message : 'Failed to change password.');
    } finally {
      setChangePwLoading(false);
    }
  };

  const handleExport = () => {
    const json = exportVault();
    if (!json) return;
    const filename = `vault-backup-${new Date().toISOString().split('T')[0]}.json`;
    triggerDownload(json, filename);
  };

  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError('');
    setImportSuccess(false);
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result;
      if (typeof content !== 'string') return;
      try {
        importVault(content);
        setImportSuccess(true);
        // Force re-lock so user must re-unlock with new vault's password
        setTimeout(() => {
          lock();
        }, 2000);
      } catch (err: unknown) {
        setImportError(err instanceof Error ? err.message : 'Import failed.');
      }
    };
    reader.readAsText(file);
    // Reset input
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-lg space-y-6">
        <h2 className="text-xl font-bold text-white">Settings</h2>

        {/* Security Settings */}
        <section className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 mb-1">
            <Lock className="w-4 h-4 text-blue-400" />
            Auto-Lock
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1.5">
              Lock after inactivity:{' '}
              <span className="text-white font-mono">{autoLock} min</span>
            </label>
            <input
              type="range"
              min={1}
              max={60}
              value={autoLock}
              onChange={(e) => setAutoLock(Number(e.target.value))}
              className="w-full accent-blue-500"
            />
            <div className="flex justify-between text-xs text-gray-600 mt-1">
              <span>1 min</span>
              <span>60 min</span>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1.5">
              Clear clipboard after:{' '}
              <span className="text-white font-mono">{clipClear}s</span>
            </label>
            <input
              type="range"
              min={5}
              max={120}
              value={clipClear}
              onChange={(e) => setClipClear(Number(e.target.value))}
              className="w-full accent-blue-500"
            />
            <div className="flex justify-between text-xs text-gray-600 mt-1">
              <span>5s</span>
              <span>120s</span>
            </div>
          </div>

          <label className="flex items-start gap-3 pt-1 cursor-pointer">
            <input
              type="checkbox"
              checked={lockOnBlur}
              onChange={(e) => setLockOnBlur(e.target.checked)}
              className="mt-1 rounded border-gray-700 bg-gray-800 accent-blue-500"
            />
            <span className="text-sm text-gray-300">
              Lock immediately when switching tabs or windows
              <span className="block text-xs text-gray-500 mt-0.5">
                Off by default so you can switch windows to paste passwords or import backups.
              </span>
            </span>
          </label>

          {settingsError && (
            <p className="text-sm text-red-400">{settingsError}</p>
          )}
          <button
            onClick={handleSaveSettings}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors"
          >
            <Save className="w-4 h-4" />
            {settingsSaved ? 'Saved!' : 'Save Settings'}
          </button>
        </section>

        {/* Change Master Password */}
        <section className="bg-gray-900 border border-gray-800 rounded-2xl p-5">
          <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 mb-4">
            <ShieldCheck className="w-4 h-4 text-blue-400" />
            Change Master Password
          </div>
          <form onSubmit={handleChangePassword} className="space-y-3">
            <div className="relative">
              <input
                type={showCurrentPw ? 'text' : 'password'}
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                placeholder="Current master password"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowCurrentPw((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
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
                placeholder="New master password"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setShowNewPw((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                aria-label={showNewPw ? 'Hide new password' : 'Show new password'}
              >
                {showNewPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <input
              type={showNewPw ? 'text' : 'password'}
              value={confirmPw}
              onChange={(e) => setConfirmPw(e.target.value)}
              placeholder="Confirm new password"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
              autoComplete="new-password"
            />
            {changePwError && <p className="text-sm text-red-400">{changePwError}</p>}
            {changePwSuccess && (
              <p className="text-sm text-green-400">Password changed successfully!</p>
            )}
            <button
              type="submit"
              disabled={changePwLoading || !currentPw || !newPw || !confirmPw}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors"
            >
              {changePwLoading ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <ShieldCheck className="w-4 h-4" />
              )}
              {changePwLoading ? 'Deriving key...' : 'Change Password'}
            </button>
          </form>
        </section>

        {/* Backup & Restore */}
        <section className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-gray-300 mb-1">
            <Download className="w-4 h-4 text-blue-400" />
            Backup &amp; Restore
          </div>

          <div className="space-y-3">
            <div>
              <p className="text-sm text-gray-400 mb-2">
                Export your encrypted vault blob. The export is still fully encrypted — your
                master password is required to decrypt it.
              </p>
              <button
                onClick={handleExport}
                className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors"
              >
                <Download className="w-4 h-4" />
                Export Encrypted Backup
              </button>
            </div>

            <div className="border-t border-gray-800 pt-3">
              <div className="flex items-start gap-2 text-yellow-300 text-xs bg-yellow-900/20 border border-yellow-700/50 rounded-lg px-3 py-2.5 mb-3">
                <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                <span>
                  Importing will overwrite your current vault and lock you out. You will need
                  the original master password of the imported file.
                </span>
              </div>
              <input
                ref={fileRef}
                type="file"
                accept=".json"
                onChange={handleImportFile}
                className="hidden"
                id="import-file"
              />
              <button
                onClick={() => fileRef.current?.click()}
                className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white text-sm font-medium px-4 py-2.5 rounded-lg transition-colors"
              >
                <Upload className="w-4 h-4" />
                Import Vault Backup
              </button>
              {importError && <p className="text-sm text-red-400 mt-2">{importError}</p>}
              {importSuccess && (
                <p className="text-sm text-green-400 mt-2">
                  Vault imported. Locking now — re-unlock with the imported vault&apos;s password.
                </p>
              )}
            </div>
          </div>
        </section>

        {/* Info */}
        <section className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
          <p className="text-xs text-gray-600 leading-relaxed">
            <strong className="text-gray-500">Encryption:</strong> AES-256-GCM with Argon2id key derivation (65536 KB, 3 iterations).
            Your master password is never stored, transmitted, or logged. All data remains entirely on your device.
          </p>
        </section>
      </div>
    </div>
  );
}
