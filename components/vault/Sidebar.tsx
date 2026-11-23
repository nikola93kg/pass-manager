// ============================================================
// Sidebar — NMark Pass Vault Navigation, Sync Status, Lock
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
  Cloud,
  CloudOff,
  HardDrive,
  AlertTriangle,
  RefreshCw,
  LogOut,
} from 'lucide-react';
import type { ActiveView } from './VaultLayout';

interface Props {
  activeView: ActiveView;
  onViewChange: (v: ActiveView) => void;
  userEmail?: string | null;
  onSignOut?: () => void;
}

type NavItem = {
  id: ActiveView;
  label: string;
  icon: React.ReactNode;
};

const NAV_ITEMS: NavItem[] = [
  { id: 'all', label: 'All Items', icon: <LayoutList className="w-4 h-4" /> },
  { id: 'posao', label: 'Posao', icon: <Briefcase className="w-4 h-4" /> },
  { id: 'projekti', label: 'Projekti', icon: <FolderKanban className="w-4 h-4" /> },
  { id: 'licno', label: 'Lično', icon: <User className="w-4 h-4" /> },
];

export default function Sidebar({ activeView, onViewChange, userEmail, onSignOut }: Props) {
  const { lock, vault, syncMode, syncStatus, hasUnsavedChanges, revision, retrySave } =
    useVaultStore();
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
    const filename = `nmark-vault-backup-${new Date().toISOString().split('T')[0]}.json`;
    triggerDownload(json, filename);
  };

  const renderSyncBadge = () => {
    if (syncStatus === 'saving') {
      return (
        <div className="flex items-center gap-2 text-xs text-vault-accent">
          <RefreshCw className="w-3.5 h-3.5 animate-spin shrink-0" />
          <span>Encrypting &amp; saving...</span>
        </div>
      );
    }
    if (syncStatus === 'conflict') {
      return (
        <div className="flex items-center gap-2 text-xs text-amber-300">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span>Sync conflict (rev #{revision})</span>
        </div>
      );
    }
    if (syncStatus === 'offline_local' || hasUnsavedChanges) {
      return (
        <button
          type="button"
          onClick={() => void retrySave()}
          className="w-full flex items-center gap-2 text-xs text-amber-300 hover:text-amber-200 text-left"
          title="Click to retry sync"
        >
          <CloudOff className="w-3.5 h-3.5 shrink-0" />
          <span className="truncate">Unsynced local · Retry</span>
        </button>
      );
    }
    if (syncMode === 'cloud') {
      return (
        <div className="flex items-center gap-2 text-xs text-emerald-300">
          <Cloud className="w-3.5 h-3.5 shrink-0" />
          <span>Cloud synced · rev #{revision}</span>
        </div>
      );
    }
    return (
      <div className="flex items-center gap-2 text-xs text-vault-muted">
        <HardDrive className="w-3.5 h-3.5 text-vault-accent shrink-0" />
        <span>Local vault · rev #{revision}</span>
      </div>
    );
  };

  return (
    <aside className="w-60 bg-vault-surface border-r border-vault-border flex flex-col shrink-0">
      {/* Brand Header */}
      <div className="px-4 py-5 border-b border-vault-border">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-vault-elevated border border-vault-accent/40 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-vault-accent" />
          </div>
          <div className="min-w-0">
            <span className="font-bold text-vault-soft text-sm block leading-tight">
              NMark Pass Vault
            </span>
            <span className="text-[11px] text-vault-muted block truncate">
              {userEmail ?? 'Zero-Knowledge v2'}
            </span>
          </div>
        </div>
      </div>

      {/* Sync Status Pill */}
      <div className="px-3 py-2.5 border-b border-vault-border/70 bg-vault-bg/40">
        {renderSyncBadge()}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2.5 py-3 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const count = getCounts(item.id);
          const active = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium transition-colors text-left ${
                active
                  ? 'bg-vault-accent text-vault-bg font-semibold shadow-sm shadow-vault-accent/20'
                  : 'text-vault-muted hover:bg-vault-elevated hover:text-vault-soft'
              }`}
            >
              {item.icon}
              <span className="flex-1">{item.label}</span>
              {count !== null && count > 0 && (
                <span
                  className={`text-xs px-2 py-0.5 rounded-full font-mono ${
                    active
                      ? 'bg-vault-bg/20 text-vault-bg'
                      : 'bg-vault-elevated text-vault-muted'
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}

        <div className="border-t border-vault-border my-2.5" />

        <button
          onClick={() => onViewChange('settings')}
          className={`w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium transition-colors text-left ${
            activeView === 'settings'
              ? 'bg-vault-accent text-vault-bg font-semibold'
              : 'text-vault-muted hover:bg-vault-elevated hover:text-vault-soft'
          }`}
        >
          <Settings className="w-4 h-4" />
          Security &amp; Settings
        </button>
      </nav>

      {/* Bottom Actions */}
      <div className="px-2.5 py-3 border-t border-vault-border space-y-1">
        <button
          onClick={handleExport}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium text-vault-muted hover:bg-vault-elevated hover:text-vault-soft transition-colors"
        >
          <Download className="w-4 h-4 text-vault-accent" />
          Export Encrypted Backup
        </button>
        <button
          onClick={() => lock()}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium text-red-300 hover:bg-red-950/50 hover:text-red-200 transition-colors"
        >
          <Lock className="w-4 h-4" />
          Lock Vault
        </button>
        {syncMode === 'cloud' && onSignOut && (
          <button
            onClick={onSignOut}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium text-vault-muted hover:bg-vault-elevated hover:text-vault-soft transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign Out Session
          </button>
        )}
      </div>
    </aside>
  );
}
