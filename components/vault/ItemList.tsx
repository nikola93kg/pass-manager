// ============================================================
// ItemList — Vault entries with search, tag filters, auto-hide
// password reveal, safe URL launch, and Client Hub deep linking.
// ============================================================

'use client';

import { useState, useMemo, useEffect, useRef } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import {
  Plus,
  Search,
  Globe,
  User,
  Copy,
  Eye,
  EyeOff,
  Check,
  Briefcase,
  FolderKanban,
  ExternalLink,
  Link2,
  Tag,
  AlertCircle,
  X,
} from 'lucide-react';
import type { VaultItem, VaultCategory } from '@/lib/types';
import type { ActiveView } from './VaultLayout';
import { useClipboard } from '@/hooks/useClipboard';
import { generateVaultItemId, getSafeExternalUrl } from '@/lib/urlSafety';
import { getAppOrigin } from '@/lib/env';
import EntryModal from './EntryModal';

interface Props {
  activeView: ActiveView;
  search: string;
  onSearchChange: (v: string) => void;
}

const CATEGORY_ICONS: Record<VaultCategory, React.ReactNode> = {
  posao: <Briefcase className="w-3.5 h-3.5" />,
  projekti: <FolderKanban className="w-3.5 h-3.5" />,
  licno: <User className="w-3.5 h-3.5" />,
};

const CATEGORY_COLORS: Record<VaultCategory, string> = {
  posao: 'bg-vault-accent/20 text-vault-accent border border-vault-accent/30',
  projekti: 'bg-fuchsia-950/60 text-fuchsia-300 border border-fuchsia-700/40',
  licno: 'bg-emerald-950/60 text-emerald-300 border border-emerald-700/40',
};

const CATEGORY_LABELS: Record<VaultCategory, string> = {
  posao: 'Posao',
  projekti: 'Projekti',
  licno: 'Lično',
};

const VIEW_TITLES: Record<ActiveView, string> = {
  all: 'All Credentials',
  posao: 'Posao',
  projekti: 'Projekti',
  licno: 'Lično',
  settings: 'Settings',
};

export default function ItemList({ activeView, search, onSearchChange }: Props) {
  const {
    vault,
    addVaultItem,
    updateVaultItem,
    deleteVaultItem,
    pendingDeepLinkItemId,
    setPendingDeepLinkItemId,
  } = useVaultStore();
  const { copiedId, secondsLeft, copyToClipboard } = useClipboard();

  const [modalOpen, setModalOpen] = useState(false);
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());
  const [deepLinkNotFoundId, setDeepLinkNotFoundId] = useState<string | null>(null);
  const revealTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const autoHideSeconds = vault?.settings?.autoHidePasswordSeconds ?? 30;

  // Resolve Client Hub deep-link target once vault is unlocked
  useEffect(() => {
    if (!pendingDeepLinkItemId || !vault) return;
    const match = vault.items.find((i) => i.id === pendingDeepLinkItemId);
    if (match) {
      setSelectedItem(match);
      setModalOpen(true);
      setDeepLinkNotFoundId(null);
    } else {
      setDeepLinkNotFoundId(pendingDeepLinkItemId);
    }
    setPendingDeepLinkItemId(null);
  }, [pendingDeepLinkItemId, vault, setPendingDeepLinkItemId]);

  // Clean up reveal auto-hide timers on unmount
  useEffect(() => {
    const timers = revealTimersRef.current;
    return () => {
      timers.forEach((t) => clearTimeout(t));
      timers.clear();
    };
  }, []);

  const allTags = useMemo(() => {
    const set = new Set<string>();
    for (const item of vault?.items ?? []) {
      for (const tag of item.tags ?? []) {
        set.add(tag);
      }
    }
    return Array.from(set).sort();
  }, [vault?.items]);

  const filtered = useMemo(() => {
    const items = vault?.items ?? [];
    let list = items;
    if (activeView !== 'all') {
      list = list.filter((i) => i.category === activeView);
    }
    if (selectedTag) {
      list = list.filter((i) => (i.tags ?? []).includes(selectedTag));
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (i) =>
          i.title.toLowerCase().includes(q) ||
          i.username.toLowerCase().includes(q) ||
          i.url.toLowerCase().includes(q) ||
          i.id.toLowerCase().includes(q) ||
          (i.tags ?? []).some((t) => t.toLowerCase().includes(q))
      );
    }
    return list;
  }, [vault?.items, activeView, selectedTag, search]);

  const toggleReveal = (id: string) => {
    const timers = revealTimersRef.current;
    setRevealedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
        const existing = timers.get(id);
        if (existing) {
          clearTimeout(existing);
          timers.delete(id);
        }
      } else {
        next.add(id);
        const existing = timers.get(id);
        if (existing) clearTimeout(existing);
        const timeout = setTimeout(() => {
          setRevealedIds((cur) => {
            const updated = new Set(cur);
            updated.delete(id);
            return updated;
          });
          timers.delete(id);
        }, autoHideSeconds * 1000);
        timers.set(id, timeout);
      }
      return next;
    });
  };

  const openCreate = () => {
    setSelectedItem(null);
    setModalOpen(true);
  };

  const openEdit = (item: VaultItem) => {
    setSelectedItem(item);
    setModalOpen(true);
  };

  const handleSave = async (item: VaultItem) => {
    if (selectedItem) {
      await updateVaultItem({ ...item, updatedAt: new Date().toISOString() });
    } else {
      await addVaultItem({
        ...item,
        id: generateVaultItemId(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }
    setModalOpen(false);
  };

  const handleDelete = async (id: string) => {
    await deleteVaultItem(id);
    setModalOpen(false);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-vault-border flex flex-wrap items-center gap-3 bg-vault-surface/40">
        <div>
          <h2 className="text-lg font-semibold text-vault-soft">
            {VIEW_TITLES[activeView]}
          </h2>
          <p className="text-xs text-vault-muted">
            {filtered.length} {filtered.length === 1 ? 'entry' : 'entries'}
          </p>
        </div>

        <div className="flex-1 min-w-[200px] relative ml-0 sm:ml-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-vault-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search service, username, URL, tag, or ID..."
            className="w-full bg-vault-bg border border-vault-border rounded-xl pl-9 pr-4 py-2 text-sm text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent"
          />
        </div>

        <button
          onClick={openCreate}
          className="flex items-center gap-1.5 bg-vault-accent hover:bg-vault-accent-hover text-vault-bg text-sm font-semibold px-4 py-2 rounded-xl transition-colors shrink-0 shadow-sm shadow-vault-accent/20"
        >
          <Plus className="w-4 h-4" />
          Add Entry
        </button>
      </div>

      {/* Deep-Link Not Found Alert */}
      {deepLinkNotFoundId && (
        <div className="mx-4 mt-3 bg-amber-950/40 border border-amber-600/40 rounded-xl px-4 py-2.5 flex items-center justify-between gap-2 text-xs text-amber-200">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              Vault entry{' '}
              <code className="font-mono text-amber-300">{deepLinkNotFoundId}</code> was
              not found in this vault.
            </span>
          </div>
          <button
            type="button"
            onClick={() => setDeepLinkNotFoundId(null)}
            className="p-1 hover:text-white"
            aria-label="Dismiss"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Tag Filter Bar */}
      {allTags.length > 0 && (
        <div className="px-6 py-2.5 border-b border-vault-border/60 flex items-center gap-2 overflow-x-auto">
          <span className="text-[11px] uppercase tracking-wider text-vault-muted shrink-0">
            Tags:
          </span>
          <button
            type="button"
            onClick={() => setSelectedTag(null)}
            className={`px-2.5 py-0.5 rounded-full text-xs transition-colors shrink-0 ${
              selectedTag === null
                ? 'bg-vault-accent text-vault-bg font-semibold'
                : 'bg-vault-surface text-vault-muted hover:text-vault-soft border border-vault-border'
            }`}
          >
            All
          </button>
          {allTags.map((tag) => (
            <button
              key={tag}
              type="button"
              onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
              className={`px-2.5 py-0.5 rounded-full text-xs transition-colors shrink-0 inline-flex items-center gap-1 ${
                selectedTag === tag
                  ? 'bg-vault-accent text-vault-bg font-semibold'
                  : 'bg-vault-surface text-vault-muted hover:text-vault-soft border border-vault-border'
              }`}
            >
              <Tag className="w-3 h-3" />
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* Entry List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-vault-muted gap-3 pb-20">
            <div className="w-14 h-14 bg-vault-surface border border-vault-border rounded-2xl flex items-center justify-center">
              <Search className="w-6 h-6 text-vault-accent/70" />
            </div>
            <p className="text-sm">
              {search || selectedTag
                ? 'No matching entries found.'
                : 'Your vault is empty. Click "Add Entry" to store your first credential.'}
            </p>
          </div>
        ) : (
          filtered.map((item) => {
            const isRevealed = revealedIds.has(item.id);
            const isCopied = copiedId === item.id;
            const isLinkCopied = copiedId === `link-${item.id}`;
            const safeUrl = getSafeExternalUrl(item.url);

            return (
              <div
                key={item.id}
                className="group bg-vault-surface hover:bg-vault-elevated/80 border border-vault-border hover:border-vault-accent/40 rounded-xl p-4 cursor-pointer transition-all"
                onClick={() => openEdit(item)}
              >
                <div className="flex items-start gap-3">
                  {/* Icon */}
                  <div className="w-10 h-10 bg-vault-elevated border border-vault-border rounded-xl flex items-center justify-center shrink-0 text-vault-accent font-bold text-sm uppercase">
                    {item.title.slice(0, 1) || <Globe className="w-4 h-4" />}
                  </div>

                  {/* Main info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <p className="font-semibold text-vault-soft text-sm truncate">
                        {item.title}
                      </p>
                      <span
                        className={`text-[11px] px-2 py-0.5 rounded-full flex items-center gap-1 shrink-0 ${
                          CATEGORY_COLORS[item.category]
                        }`}
                      >
                        {CATEGORY_ICONS[item.category]}
                        {CATEGORY_LABELS[item.category]}
                      </span>
                    </div>

                    {item.username && (
                      <p className="text-xs text-vault-muted truncate flex items-center gap-1.5">
                        <User className="w-3 h-3 shrink-0" />
                        {item.username}
                      </p>
                    )}

                    {item.url && (
                      <p className="text-xs text-vault-muted/70 truncate flex items-center gap-1.5 mt-0.5">
                        <Globe className="w-3 h-3 shrink-0" />
                        {item.url}
                      </p>
                    )}

                    {(item.tags ?? []).length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {(item.tags ?? []).map((t) => (
                          <span
                            key={t}
                            className="text-[10px] px-2 py-0.5 rounded-full bg-vault-bg/80 border border-vault-border text-vault-muted"
                          >
                            #{t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Quick Actions */}
                  <div
                    className="flex items-center gap-1 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 focus-within:opacity-100 transition-opacity"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {safeUrl && (
                      <a
                        href={safeUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        title="Open login URL"
                        className="p-1.5 text-vault-muted hover:text-vault-accent hover:bg-vault-bg/60 rounded-lg transition-colors"
                      >
                        <ExternalLink className="w-4 h-4" />
                      </a>
                    )}
                    <button
                      type="button"
                      title={
                        isLinkCopied ? 'Deep link copied' : 'Copy Client Hub deep link'
                      }
                      onClick={() =>
                        copyToClipboard(
                          `${getAppOrigin()}/item/${item.id}`,
                          `link-${item.id}`,
                          { autoClear: false }
                        )
                      }
                      className="p-1.5 text-vault-muted hover:text-vault-accent hover:bg-vault-bg/60 rounded-lg transition-colors"
                    >
                      {isLinkCopied ? (
                        <Check className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Link2 className="w-4 h-4" />
                      )}
                    </button>
                    <button
                      type="button"
                      title={
                        isRevealed
                          ? 'Hide password'
                          : `Reveal password (auto-hides in ${autoHideSeconds}s)`
                      }
                      onClick={() => toggleReveal(item.id)}
                      className="p-1.5 text-vault-muted hover:text-vault-soft hover:bg-vault-bg/60 rounded-lg transition-colors"
                    >
                      {isRevealed ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                    <button
                      type="button"
                      title={isCopied ? `Clears in ${secondsLeft}s` : 'Copy password'}
                      onClick={() => copyToClipboard(item.password, item.id)}
                      className={`p-1.5 rounded-lg transition-colors ${
                        isCopied
                          ? 'text-emerald-400 hover:bg-vault-bg/60'
                          : 'text-vault-muted hover:text-vault-soft hover:bg-vault-bg/60'
                      }`}
                    >
                      {isCopied ? (
                        <Check className="w-4 h-4" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Revealed password */}
                {isRevealed && (
                  <div
                    className="mt-2.5 ml-13 font-mono text-xs bg-vault-bg text-emerald-300 px-3 py-2 rounded-lg border border-vault-border break-all flex items-center justify-between gap-2"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <span>{item.password || '(empty)'}</span>
                    <span className="text-[10px] text-vault-muted shrink-0">
                      auto-hides in {autoHideSeconds}s
                    </span>
                  </div>
                )}

                {/* Copy countdown */}
                {isCopied && (
                  <div className="mt-1.5 ml-13 text-xs text-emerald-400">
                    Copied! Best-effort clipboard clear in {secondsLeft}s
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Entry modal */}
      {modalOpen && (
        <EntryModal
          item={selectedItem}
          onSave={handleSave}
          onDelete={handleDelete}
          onClose={() => setModalOpen(false)}
        />
      )}
    </div>
  );
}
