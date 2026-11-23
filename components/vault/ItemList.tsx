// ============================================================
// ItemList — main vault content area with search + list
// ============================================================

'use client';

import { useState, useMemo } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import { Plus, Search, Globe, User, Copy, Eye, EyeOff, Check, Briefcase, FolderKanban } from 'lucide-react';
import type { VaultItem, VaultCategory } from '@/lib/types';
import type { ActiveView } from './VaultLayout';
import { useClipboard } from '@/hooks/useClipboard';
import EntryModal from './EntryModal';
import { v4 as uuidv4 } from 'uuid';

interface Props {
  activeView: ActiveView;
  search: string;
  onSearchChange: (v: string) => void;
}

const CATEGORY_ICONS: Record<VaultCategory, React.ReactNode> = {
  posao:    <Briefcase className="w-3.5 h-3.5" />,
  projekti: <FolderKanban className="w-3.5 h-3.5" />,
  licno:    <User className="w-3.5 h-3.5" />,
};

const CATEGORY_COLORS: Record<VaultCategory, string> = {
  posao:    'bg-blue-900/40 text-blue-300',
  projekti: 'bg-purple-900/40 text-purple-300',
  licno:    'bg-green-900/40 text-green-300',
};

const CATEGORY_LABELS: Record<VaultCategory, string> = {
  posao: 'Posao',
  projekti: 'Projekti',
  licno: 'Lično',
};

const VIEW_TITLES: Record<ActiveView, string> = {
  all: 'All Items',
  posao: 'Posao',
  projekti: 'Projekti',
  licno: 'Lično',
  settings: 'Settings',
};

export default function ItemList({ activeView, search, onSearchChange }: Props) {
  const { vault, addVaultItem, updateVaultItem, deleteVaultItem } = useVaultStore();
  const { copiedId, secondsLeft, copyToClipboard } = useClipboard();

  const [modalOpen, setModalOpen] = useState(false);
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    const items = vault?.items ?? [];
    let list = items;
    if (activeView !== 'all') {
      list = list.filter((i) => i.category === activeView);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (i) =>
          i.title.toLowerCase().includes(q) ||
          i.username.toLowerCase().includes(q) ||
          i.url.toLowerCase().includes(q)
      );
    }
    return list;
  }, [vault?.items, activeView, search]);

  const toggleReveal = (id: string) => {
    setRevealedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
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
        id: uuidv4(),
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
      <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">
            {VIEW_TITLES[activeView]}
          </h2>
          <p className="text-xs text-gray-500">{filtered.length} items</p>
        </div>
        <div className="flex-1 relative ml-2">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search vault..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-3 py-2 rounded-lg transition-colors shrink-0"
        >
          <Plus className="w-4 h-4" />
          Add
        </button>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-1">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-600 gap-3 pb-20">
            <div className="w-14 h-14 bg-gray-800 rounded-full flex items-center justify-center">
              <Search className="w-6 h-6" />
            </div>
            <p className="text-sm">
              {search ? 'No results found.' : 'No items yet. Add one to get started.'}
            </p>
          </div>
        ) : (
          filtered.map((item) => {
            const isRevealed = revealedIds.has(item.id);
            const isCopied = copiedId === item.id;
            return (
              <div
                key={item.id}
                className="group bg-gray-900 hover:bg-gray-800 border border-gray-800 hover:border-gray-700 rounded-xl p-4 cursor-pointer transition-all"
                onClick={() => openEdit(item)}
              >
                <div className="flex items-start gap-3">
                  {/* Icon */}
                  <div className="w-9 h-9 bg-gray-700 rounded-lg flex items-center justify-center shrink-0 text-gray-300">
                    <Globe className="w-4 h-4" />
                  </div>

                  {/* Main content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <p className="font-medium text-white text-sm truncate">
                        {item.title}
                      </p>
                      <span
                        className={`text-xs px-1.5 py-0.5 rounded-full flex items-center gap-1 shrink-0 ${
                          CATEGORY_COLORS[item.category]
                        }`}
                      >
                        {CATEGORY_ICONS[item.category]}
                        {CATEGORY_LABELS[item.category]}
                      </span>
                    </div>
                    {item.username && (
                      <p className="text-xs text-gray-400 truncate flex items-center gap-1">
                        <User className="w-3 h-3" />
                        {item.username}
                      </p>
                    )}
                    {item.url && (
                      <p className="text-xs text-gray-500 truncate flex items-center gap-1 mt-0.5">
                        <Globe className="w-3 h-3" />
                        {item.url}
                      </p>
                    )}
                  </div>

                  {/* Actions */}
                  <div
                    className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {/* Reveal password */}
                    <button
                      title={isRevealed ? 'Hide password' : 'Reveal password'}
                      onClick={() => toggleReveal(item.id)}
                      className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      {isRevealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                    {/* Copy password */}
                    <button
                      title={isCopied ? `Clears in ${secondsLeft}s` : 'Copy password'}
                      onClick={() => copyToClipboard(item.password, item.id)}
                      className={`p-1.5 rounded-lg transition-colors ${
                        isCopied
                          ? 'text-green-400 hover:bg-gray-700'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700'
                      }`}
                    >
                      {isCopied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Revealed password */}
                {isRevealed && (
                  <div
                    className="mt-2 ml-12 font-mono text-xs bg-gray-800 text-green-400 px-3 py-1.5 rounded-lg border border-gray-700 break-all"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {item.password}
                  </div>
                )}

                {/* Copy timer */}
                {isCopied && (
                  <div className="mt-1.5 ml-12 text-xs text-green-500">
                    Copied! Clipboard clears in {secondsLeft}s
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
