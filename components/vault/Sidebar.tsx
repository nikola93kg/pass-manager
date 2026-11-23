// ============================================================
// Sidebar — navigation, lock, export
// ============================================================

'use client';

import { useVaultStore } from '@/store/vaultStore';
import { exportVault, triggerDownload } from '@/lib/vaultService';
import {
  LayoutList,
  Briefcase,
  FolderKanban,
  User,
  Settings,
  Download,
  Lock,
  ShieldCheck,
} from 'lucide-react';
import type { ActiveView } from './VaultLayout';

interface Props {
  activeView: ActiveView;
  onViewChange: (v: ActiveView) => void;
}

type NavItem = {
  id: ActiveView;
  label: string;
  icon: React.ReactNode;
};

const NAV_ITEMS: NavItem[] = [
  { id: 'all',      label: 'All Items',  icon: <LayoutList className="w-4 h-4" /> },
  { id: 'posao',    label: 'Posao',      icon: <Briefcase className="w-4 h-4" /> },
  { id: 'projekti', label: 'Projekti',   icon: <FolderKanban className="w-4 h-4" /> },
  { id: 'licno',    label: 'Lično',      icon: <User className="w-4 h-4" /> },
];

export default function Sidebar({ activeView, onViewChange }: Props) {
  const { lock, vault } = useVaultStore();
  const itemCount = vault?.items?.length ?? 0;

  const countFor = (cat: string) =>
    vault?.items?.filter((i) => i.category === cat).length ?? 0;

  const getCounts = (id: ActiveView) => {
    if (id === 'all') return itemCount;
    if (id === 'settings') return null;
    return countFor(id);
  };

  const handleExport = () => {
    const json = exportVault();
    if (!json) return;
    const filename = `vault-backup-${new Date().toISOString().split('T')[0]}.json`;
    triggerDownload(json, filename);
  };

  const handleLock = () => {
    lock();
  };

  return (
    <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-gray-800">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-6 h-6 text-blue-400" />
          <span className="font-bold text-white text-lg">Vault</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const count = getCounts(item.id);
          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors text-left ${
                activeView === item.id
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
              }`}
            >
              {item.icon}
              <span className="flex-1">{item.label}</span>
              {count !== null && count > 0 && (
                <span
                  className={`text-xs px-1.5 py-0.5 rounded-full font-mono ${
                    activeView === item.id
                      ? 'bg-blue-500 text-white'
                      : 'bg-gray-700 text-gray-400'
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}

        {/* Divider */}
        <div className="border-t border-gray-800 my-2" />

        {/* Settings */}
        <button
          onClick={() => onViewChange('settings')}
          className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors text-left ${
            activeView === 'settings'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
          }`}
        >
          <Settings className="w-4 h-4" />
          Settings
        </button>
      </nav>

      {/* Bottom actions */}
      <div className="px-2 py-3 border-t border-gray-800 space-y-0.5">
        <button
          onClick={handleExport}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
        >
          <Download className="w-4 h-4" />
          Export Backup
        </button>
        <button
          onClick={handleLock}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-red-400 hover:bg-red-900/30 hover:text-red-300 transition-colors"
        >
          <Lock className="w-4 h-4" />
          Lock Vault
        </button>
      </div>
    </aside>
  );
}
