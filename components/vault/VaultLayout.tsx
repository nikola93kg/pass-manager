// ============================================================
// VaultLayout — Main Shell: Sidebar, Status Banners, ConflictModal
// ============================================================

'use client';

import { useState } from 'react';
import { AlertTriangle, X, ShieldCheck, RefreshCw } from 'lucide-react';
import { useInactivityLock } from '@/hooks/useInactivityLock';
import { useVaultStore } from '@/store/vaultStore';
import Sidebar from './Sidebar';
import ItemList from './ItemList';
import SettingsPanel from './SettingsPanel';
import ConflictModal from './ConflictModal';
import type { VaultCategory } from '@/lib/types';

export type ActiveView = 'all' | VaultCategory | 'settings';

interface Props {
  userEmail?: string | null;
  onSignOut?: () => void;
}

export default function VaultLayout({ userEmail, onSignOut }: Props) {
  // Activate wall-clock auto-lock & multi-tab sync
  useInactivityLock();

  const {
    saveError,
    clearSaveError,
    hasUnsavedChanges,
    syncStatus,
    retrySave,
    migratedFromV1,
    clearMigrationNotice,
  } = useVaultStore();

  const [activeView, setActiveView] = useState<ActiveView>('all');
  const [search, setSearch] = useState('');

  return (
    <div className="flex h-screen bg-vault-bg overflow-hidden">
      <Sidebar
        activeView={activeView}
        onViewChange={(v) => {
          setActiveView(v);
          setSearch('');
        }}
        userEmail={userEmail}
        onSignOut={onSignOut}
      />

      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Transparent v1 -> v2 Migration Notice */}
        {migratedFromV1 && (
          <div className="flex items-center justify-between gap-3 bg-vault-elevated border-b border-vault-accent/40 px-6 py-2.5 text-xs text-vault-soft">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-vault-accent shrink-0" />
              <span>
                Your v1 vault was safely upgraded to encrypted Format v2 (with authenticated
                metadata). An encrypted v1 recovery snapshot was preserved in Settings.
              </span>
            </div>
            <button
              type="button"
              onClick={clearMigrationNotice}
              className="p-1 text-vault-muted hover:text-vault-soft shrink-0"
              aria-label="Dismiss migration notice"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Save / Sync Error Banner */}
        {saveError && (
          <div
            role="alert"
            className="flex items-center justify-between gap-3 bg-red-950/70 border-b border-red-700/60 px-6 py-2.5 text-xs text-red-200"
          >
            <div className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span className="truncate">{saveError}</span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {hasUnsavedChanges && syncStatus !== 'conflict' && (
                <button
                  type="button"
                  onClick={() => void retrySave()}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-900/70 hover:bg-red-800 text-red-100 font-medium"
                >
                  <RefreshCw className="w-3 h-3" />
                  Retry
                </button>
              )}
              <button
                type="button"
                onClick={clearSaveError}
                className="p-1 text-red-300 hover:text-white rounded transition-colors"
                aria-label="Dismiss error"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {activeView === 'settings' ? (
          <SettingsPanel />
        ) : (
          <ItemList
            activeView={activeView}
            search={search}
            onSearchChange={setSearch}
          />
        )}
      </main>

      <ConflictModal />
    </div>
  );
}
