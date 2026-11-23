// ============================================================
// VaultLayout — Main shell: sidebar + content area
// ============================================================

'use client';

import { useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { useInactivityLock } from '@/hooks/useInactivityLock';
import { useVaultStore } from '@/store/vaultStore';
import Sidebar from './Sidebar';
import ItemList from './ItemList';
import SettingsPanel from './SettingsPanel';
import type { VaultCategory } from '@/lib/types';

export type ActiveView = 'all' | VaultCategory | 'settings';

export default function VaultLayout() {
  // Activate inactivity auto-lock
  useInactivityLock();

  const { saveError, clearSaveError } = useVaultStore();
  const [activeView, setActiveView] = useState<ActiveView>('all');
  const [search, setSearch] = useState('');

  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden">
      <Sidebar
        activeView={activeView}
        onViewChange={(v) => {
          setActiveView(v);
          setSearch('');
        }}
      />

      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {saveError && (
          <div
            role="alert"
            className="flex items-center justify-between gap-3 bg-red-900/40 border-b border-red-700/60 px-6 py-2.5 text-sm text-red-200"
          >
            <div className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span className="truncate">
                Failed to save vault: {saveError}
              </span>
            </div>
            <button
              type="button"
              onClick={clearSaveError}
              className="p-1 text-red-300 hover:text-white rounded transition-colors shrink-0"
              aria-label="Dismiss error"
            >
              <X className="w-4 h-4" />
            </button>
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
    </div>
  );
}
