// ============================================================
// EntryModal — View / Edit / Create Vault Entry
// Features: tags chips, stable item ID + Client Hub deep-link
// copy, safe https/http URL launch, inline CSPRNG generator.
// ============================================================

'use client';

import { useState, useEffect } from 'react';
import type { VaultItem, VaultCategory } from '@/lib/types';
import {
  Eye,
  EyeOff,
  X,
  Trash2,
  RefreshCw,
  Copy,
  Check,
  ExternalLink,
  Link2,
  Tag,
} from 'lucide-react';
import PasswordGenerator from './PasswordGenerator';
import { useClipboard } from '@/hooks/useClipboard';
import { getSafeExternalUrl } from '@/lib/urlSafety';
import { getAppOrigin } from '@/lib/env';

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
  tags: [],
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
          tags: item.tags ?? [],
        }
      : { ...EMPTY_ITEM }
  );
  const [tagInput, setTagInput] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState('');
  const { copiedId, secondsLeft, copyToClipboard } = useClipboard();

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

  const addTag = () => {
    const cleaned = tagInput.trim().toLowerCase().slice(0, 32);
    if (!cleaned) return;
    if (!form.tags.includes(cleaned) && form.tags.length < 10) {
      set('tags', [...form.tags, cleaned]);
    }
    setTagInput('');
  };

  const removeTag = (tag: string) => {
    set(
      'tags',
      form.tags.filter((t) => t !== tag)
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim()) return;
    setError('');

    if (form.url.trim() && !getSafeExternalUrl(form.url)) {
      setError('URL must start with https:// or http:// and be valid.');
      return;
    }

    setSaving(true);
    try {
      await onSave({
        id: item?.id ?? '',
        createdAt: item?.createdAt ?? '',
        updatedAt: '',
        ...form,
        title: form.title.trim(),
        url: form.url.trim(),
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

  const safeHref = getSafeExternalUrl(form.url);
  const deepLinkUrl = item ? `${getAppOrigin()}/item/${item.id}` : null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="dialog"
      aria-modal="true"
    >
      <div className="bg-vault-surface border border-vault-border rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto shadow-2xl shadow-black/60">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-vault-border">
          <h2 className="text-lg font-semibold text-vault-soft">
            {isEdit ? 'Edit Credential' : 'New Credential'}
          </h2>
          <button
            onClick={onClose}
            className="p-1.5 text-vault-muted hover:text-vault-soft hover:bg-vault-elevated rounded-lg transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Service / Title */}
          <div>
            <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
              Service Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.title}
              onChange={(e) => set('title', e.target.value)}
              className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent focus:ring-1 focus:ring-vault-accent text-sm"
              placeholder="e.g. Cloudflare — Client Acme"
              required
              autoFocus
            />
          </div>

          {/* Category */}
          <div>
            <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
              Category
            </label>
            <div className="flex gap-2">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => set('category', cat)}
                  className={`flex-1 py-2 rounded-xl text-sm font-medium transition-colors border ${
                    form.category === cat
                      ? 'bg-vault-accent border-vault-accent text-vault-bg font-semibold'
                      : 'bg-vault-bg border-vault-border text-vault-muted hover:text-vault-soft'
                  }`}
                >
                  {CATEGORY_LABELS[cat]}
                </button>
              ))}
            </div>
          </div>

          {/* Username */}
          <div>
            <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
              Username / Email
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={form.username}
                onChange={(e) => set('username', e.target.value)}
                className="flex-1 bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
                placeholder="user@example.com"
                autoComplete="off"
              />
              {form.username && (
                <button
                  type="button"
                  onClick={() =>
                    copyToClipboard(form.username, 'modal-user', { autoClear: false })
                  }
                  className="p-2.5 rounded-xl bg-vault-bg border border-vault-border text-vault-muted hover:text-vault-soft transition-colors"
                  title="Copy username"
                >
                  {copiedId === 'modal-user' ? (
                    <Check className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              )}
            </div>
          </div>

          {/* Password */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-sm font-medium text-vault-soft/90">
                Password
              </label>
              <button
                type="button"
                onClick={() => setShowGenerator((v) => !v)}
                className="flex items-center gap-1 text-xs text-vault-accent hover:underline"
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
                  className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 pr-10 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm font-mono"
                  placeholder="Password"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-vault-muted hover:text-vault-soft"
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => form.password && copyToClipboard(form.password, 'modal-pw')}
                className={`p-2.5 rounded-xl border transition-colors ${
                  copiedId === 'modal-pw'
                    ? 'bg-emerald-950/50 border-emerald-600 text-emerald-300'
                    : 'bg-vault-bg border-vault-border text-vault-muted hover:text-vault-soft'
                }`}
                title={copiedId === 'modal-pw' ? `Clears in ${secondsLeft}s` : 'Copy password'}
              >
                {copiedId === 'modal-pw' ? (
                  <Check className="w-4 h-4" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
            {showGenerator && (
              <div className="mt-2">
                <PasswordGenerator
                  onUse={(pw) => {
                    set('password', pw);
                    setShowGenerator(false);
                  }}
                />
              </div>
            )}
          </div>

          {/* Login URL */}
          <div>
            <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
              Login URL
            </label>
            <div className="flex gap-2">
              <input
                type="url"
                value={form.url}
                onChange={(e) => set('url', e.target.value)}
                className="flex-1 bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
                placeholder="https://dash.cloudflare.com"
                autoComplete="off"
              />
              {safeHref && (
                <a
                  href={safeHref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2.5 rounded-xl bg-vault-bg border border-vault-border text-vault-accent hover:bg-vault-elevated transition-colors flex items-center"
                  title="Open login URL in new tab"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              )}
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
              Tags
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ',') {
                    e.preventDefault();
                    addTag();
                  }
                }}
                className="flex-1 bg-vault-bg border border-vault-border rounded-xl px-4 py-2 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm"
                placeholder="hosting, dns, client-acme (Enter to add)"
              />
              <button
                type="button"
                onClick={addTag}
                className="px-3.5 py-2 text-xs font-medium bg-vault-elevated hover:bg-vault-border text-vault-soft rounded-xl border border-vault-border transition-colors"
              >
                Add
              </button>
            </div>
            {form.tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {form.tags.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs bg-vault-elevated border border-vault-accent/30 text-vault-soft"
                  >
                    <Tag className="w-3 h-3 text-vault-accent" />
                    {tag}
                    <button
                      type="button"
                      onClick={() => removeTag(tag)}
                      className="text-vault-muted hover:text-red-300 ml-0.5"
                      aria-label={`Remove tag ${tag}`}
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Notes */}
          <div>
            <label className="block text-sm font-medium text-vault-soft/90 mb-1.5">
              Notes
            </label>
            <textarea
              value={form.notes}
              onChange={(e) => set('notes', e.target.value)}
              rows={3}
              className="w-full bg-vault-bg border border-vault-border rounded-xl px-4 py-2.5 text-vault-soft placeholder-vault-muted/50 focus:outline-none focus:border-vault-accent text-sm resize-none"
              placeholder="Recovery hints, account notes..."
            />
          </div>

          {/* Stable Entry ID & Client Hub Deep Link */}
          {isEdit && deepLinkUrl && (
            <div className="bg-vault-bg/70 border border-vault-border rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium text-vault-muted">
                  Stable Vault Item ID (Client Hub Reference)
                </span>
                <button
                  type="button"
                  onClick={() =>
                    copyToClipboard(deepLinkUrl, 'modal-deeplink', { autoClear: false })
                  }
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-vault-accent hover:underline"
                >
                  {copiedId === 'modal-deeplink' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Copied link
                    </>
                  ) : (
                    <>
                      <Link2 className="w-3.5 h-3.5" />
                      Copy Deep Link
                    </>
                  )}
                </button>
              </div>
              <code className="block font-mono text-[11px] text-vault-soft/80 break-all">
                {item.id}
              </code>
              <div className="text-[11px] text-vault-muted/70 flex flex-wrap gap-x-4 gap-y-0.5 pt-1">
                <span>Created: {new Date(item.createdAt).toLocaleString()}</span>
                <span>Updated: {new Date(item.updatedAt).toLocaleString()}</span>
              </div>
            </div>
          )}

          {/* Confirm delete dialog */}
          {confirmDelete && (
            <div className="bg-red-950/50 border border-red-700/70 rounded-xl p-4 space-y-3">
              <p className="text-sm text-red-200 font-medium">
                Delete &quot;{item?.title}&quot;? This cannot be undone.
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={handleDelete}
                  disabled={saving}
                  className="flex-1 bg-red-600 hover:bg-red-500 text-white text-sm font-medium py-2 rounded-xl transition-colors"
                >
                  Delete
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmDelete(false)}
                  className="flex-1 bg-vault-elevated hover:bg-vault-border text-vault-soft text-sm font-medium py-2 rounded-xl transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-950/60 border border-red-700/70 text-red-200 text-sm rounded-xl px-4 py-2.5">
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-2 pt-2">
            {isEdit && !confirmDelete && (
              <button
                type="button"
                onClick={() => setConfirmDelete(true)}
                className="p-2.5 text-red-400 hover:text-red-300 hover:bg-red-950/40 rounded-xl transition-colors"
                title="Delete entry"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            )}
            <div className="flex-1" />
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 text-sm font-medium text-vault-muted hover:text-vault-soft bg-vault-elevated hover:bg-vault-border rounded-xl transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !form.title.trim()}
              className="px-5 py-2.5 text-sm font-semibold text-vault-bg bg-vault-accent hover:bg-vault-accent-hover disabled:opacity-50 rounded-xl transition-colors flex items-center gap-2"
            >
              {saving && (
                <div className="w-4 h-4 border-2 border-vault-bg border-t-transparent rounded-full animate-spin" />
              )}
              {isEdit ? 'Save Changes' : 'Add Entry'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
