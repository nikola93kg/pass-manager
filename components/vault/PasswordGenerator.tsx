// ============================================================
// PasswordGenerator — Inline CSPRNG password generator widget
// Uses crypto.getRandomValues exclusively with rejection sampling.
// ============================================================

'use client';

import { useState, useCallback } from 'react';
import { generatePassword } from '@/lib/passwordGenerator';
import { RefreshCw, Copy, Check, ArrowRight } from 'lucide-react';
import type { PasswordGenOptions } from '@/lib/types';
import { useClipboard } from '@/hooks/useClipboard';

interface Props {
  onUse: (password: string) => void;
}

const DEFAULTS: PasswordGenOptions = {
  length: 24,
  uppercase: true,
  lowercase: true,
  digits: true,
  symbols: true,
};

export default function PasswordGenerator({ onUse }: Props) {
  const [options, setOptions] = useState<PasswordGenOptions>(DEFAULTS);
  const [generated, setGenerated] = useState('');
  const [error, setError] = useState('');
  const { copiedId, secondsLeft, copyToClipboard } = useClipboard();

  const generate = useCallback(() => {
    setError('');
    try {
      const pw = generatePassword(options);
      setGenerated(pw);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Generation failed.';
      setError(msg);
    }
  }, [options]);

  const toggle = (
    key: keyof Pick<PasswordGenOptions, 'uppercase' | 'lowercase' | 'digits' | 'symbols'>
  ) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
    setGenerated('');
  };

  const setLength = (val: number) => {
    setOptions((prev) => ({ ...prev, length: Math.min(128, Math.max(8, val)) }));
    setGenerated('');
  };

  return (
    <div className="bg-vault-bg/80 border border-vault-border rounded-xl p-4 space-y-3">
      <p className="text-xs font-semibold text-vault-accent uppercase tracking-wider">
        CSPRNG Password Generator
      </p>

      <div className="flex items-center gap-3">
        <label className="text-xs text-vault-muted w-20 shrink-0">
          Length: <span className="text-vault-soft font-mono">{options.length}</span>
        </label>
        <input
          type="range"
          min={8}
          max={128}
          value={options.length}
          onChange={(e) => setLength(Number(e.target.value))}
          className="flex-1 accent-vault-accent"
        />
      </div>

      <div className="flex flex-wrap gap-2">
        {(
          [
            { key: 'uppercase', label: 'A–Z' },
            { key: 'lowercase', label: 'a–z' },
            { key: 'digits', label: '0–9' },
            { key: 'symbols', label: '!@#' },
          ] as const
        ).map(({ key, label }) => (
          <button
            key={key}
            type="button"
            onClick={() => toggle(key)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              options[key]
                ? 'bg-vault-accent border-vault-accent text-vault-bg font-semibold'
                : 'bg-vault-surface border-vault-border text-vault-muted hover:text-vault-soft'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {generated && (
        <div className="flex items-center gap-2">
          <code className="flex-1 bg-vault-surface border border-vault-border rounded-lg px-3 py-2 text-xs font-mono text-emerald-300 break-all">
            {generated}
          </code>
          <button
            type="button"
            onClick={() => copyToClipboard(generated, 'gen')}
            className={`p-2 rounded-lg border transition-colors shrink-0 ${
              copiedId === 'gen'
                ? 'bg-emerald-950/50 border-emerald-600 text-emerald-300'
                : 'bg-vault-surface border-vault-border text-vault-muted hover:text-vault-soft'
            }`}
            title={copiedId === 'gen' ? `Clears in ${secondsLeft}s` : 'Copy'}
          >
            {copiedId === 'gen' ? (
              <Check className="w-3.5 h-3.5" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      )}

      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={generate}
          className="flex items-center gap-1.5 bg-vault-elevated hover:bg-vault-border text-vault-soft text-xs font-medium px-3 py-2 rounded-lg border border-vault-border transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-vault-accent" />
          Generate
        </button>
        {generated && (
          <button
            type="button"
            onClick={() => onUse(generated)}
            className="flex items-center gap-1.5 bg-vault-accent hover:bg-vault-accent-hover text-vault-bg text-xs font-semibold px-3 py-2 rounded-lg transition-colors"
          >
            Use This
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}
