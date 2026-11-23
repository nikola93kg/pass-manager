// ============================================================
// EntryModal — View/Edit/Create vault item
// ============================================================

'use client';

import { useState, useEffect } from 'react';
import type { VaultItem, VaultCategory } from '@/lib/types';
import { Eye, EyeOff, X, Trash2, RefreshCw, Copy, Check } from 'lucide-react';
import PasswordGenerator from './PasswordGenerator';
import { useClipboard } from '@/hooks/useClipboard';

interface Props {
  item: VaultItem | null;
  onSave: (item: VaultItem) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onClose: () => void;
}

const CATEGORIES: VaultCategory[] = ['posao', 'projekti', 'licno'];
const CATEGORY_LABELS: Record<VaultCategory, string> = {
  posao: 'Posao',
  projekti: 'Projekti',
  licno: 'Lično',
};

const EMPTY_ITEM: Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'> = {
  category: 'licno',
  title: '',
  username: '',
  password: '',
  url: '',
  notes: '',
};

export default function EntryModal({ item, onSave, onDelete, onClose }: Props) {
  const isEdit = item !== null;
  const [form, setForm] = useState<Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>>(
    item
      ? {
          category: item.category,
          title: item.title,
          username: item.username,
          password: item.password,
          url: item.url,
          notes: item.notes,
        }
      : { ...EMPTY_ITEM }
  );
  const [showPw, setShowPw] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState('');
  const { copiedId, secondsLeft, copyToClipboard } = useClipboard();

  // Trap focus inside modal
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [onClose]);

  const set = <K extends keyof typeof form>(key: K, val: (typeof form)[K]) => {
    setForm((prev) => ({ ...prev, [key]: val }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim()) return;
    setError('');
    setSaving(true);
    try {
      await onSave({
        id: item?.id ?? '',
        createdAt: item?.createdAt ?? '',
        updatedAt: '',
        ...form,
      });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save entry.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!item) return;
    setError('');
    setSaving(true);
    try {
      await onDelete(item.id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete entry.');
    } finally {
      setSaving(false);
    }
  };

  const handleGeneratedPassword = (pw: string) => {
    set('password', pw);
    setShowGenerator(false);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal="true"
    >
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="text-lg font-semibold text-white">
            {isEdit ? 'Edit Entry' : 'New Entry'}
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded-lg transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Title */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Title <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.title}
              onChange={(e) => set('title', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm"
              placeholder="e.g. GitHub"
              required
              autoFocus
            />
          </div>

          {/* Category */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Category
            </label>
            <div className="flex gap-2">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => set('category', cat)}
                  className={`flex-1 py-2 rounded-lg text-sm font-medium transition-colors border ${
                    form.category === cat
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600'
                  }`}
                >
                  {CATEGORY_LABELS[cat]}
                </button>
              ))}
            </div>
          </div>

          {/* Username */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Username / Email
            </label>
            <input
              type="text"
              value={form.username}
              onChange={(e) => set('username', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm"
              placeholder="user@example.com"
              autoComplete="off"
            />
          </div>

          {/* Password */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-sm font-medium text-gray-300">
                Password
              </label>
              <button
                type="button"
                onClick={() => setShowGenerator((v) => !v)}
                className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                Generate
              </button>
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={form.password}
                  onChange={(e) => set('password', e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm font-mono"
                  placeholder="Password"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                  aria-label={showPw ? 'Hide' : 'Show'}
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => form.password && copyToClipboard(form.password, 'modal-pw')}
                className={`p-2.5 rounded-lg border transition-colors ${
                  copiedId === 'modal-pw'
                    ? 'bg-green-900/30 border-green-700 text-green-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600'
                }`}
                title={copiedId === 'modal-pw' ? `Clears in ${secondsLeft}s` : 'Copy password'}
              >
                {copiedId === 'modal-pw' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            {showGenerator && (
              <div className="mt-2">
                <PasswordGenerator onUse={handleGeneratedPassword} />
              </div>
            )}
          </div>

          {/* URL */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              URL
            </label>
            <input
              type="url"
              value={form.url}
              onChange={(e) => set('url', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm"
              placeholder="https://example.com"
              autoComplete="off"
            />
          </div>

          {/* Notes */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">
              Notes
            </label>
            <textarea
              value={form.notes}
              onChange={(e) => set('notes', e.target.value)}
              rows={3}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-sm resize-none"
              placeholder="Optional notes..."
            />
          </div>

          {/* Timestamps */}
          {isEdit && (
            <div className="text-xs text-gray-600 space-y-0.5">
              <p>Created: {new Date(item.createdAt).toLocaleString()}</p>
              <p>Updated: {new Date(item.updatedAt).toLocaleString()}</p>
            </div>
          )}

          {/* Confirm delete dialog */}
          {confirmDelete && (
            <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 space-y-3">
              <p className="text-sm text-red-300 font-medium">
                Delete &quot;{item?.title}&quot;? This cannot be undone.
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleDelete}
                  disabled={saving}
                  className="flex-1 bg-red-700 hover:bg-red-600 text-white text-sm font-medium py-2 rounded-lg transition-colors"
                >
                  Delete
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmDelete(false)}
                  className="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium py-2 rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm rounded-lg px-4 py-2.5">
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-2 pt-2">
            {isEdit && !confirmDelete && (
              <button
                type="button"
                onClick={() => setConfirmDelete(true)}
                className="p-2.5 text-red-400 hover:text-red-300 hover:bg-red-900/30 rounded-lg transition-colors"
                title="Delete entry"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
            <div className="flex-1" />
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !form.title.trim()}
              className="px-5 py-2.5 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg transition-colors flex items-center gap-2"
            >
              {saving ? (
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : null}
              {isEdit ? 'Save Changes' : 'Add Entry'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
