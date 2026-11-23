// ============================================================
// PasswordGenerator — inline password generator widget
// Uses crypto.getRandomValues exclusively
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
  length: 20,
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

  const toggle = (key: keyof Pick<PasswordGenOptions, 'uppercase' | 'lowercase' | 'digits' | 'symbols'>) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
    setGenerated('');
  };

  const setLength = (val: number) => {
    setOptions((prev) => ({ ...prev, length: Math.min(128, Math.max(4, val)) }));
    setGenerated('');
  };

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-4 space-y-3">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
        Password Generator
      </p>

      {/* Length slider */}
      <div className="flex items-center gap-3">
        <label className="text-xs text-gray-400 w-14 shrink-0">
          Length: <span className="text-gray-200 font-mono">{options.length}</span>
        </label>
        <input
          type="range"
          min={4}
          max={128}
          value={options.length}
          onChange={(e) => setLength(Number(e.target.value))}
          className="flex-1 accent-blue-500"
        />
      </div>

      {/* Options */}
      <div className="flex flex-wrap gap-2">
        {(
          [
            { key: 'uppercase', label: 'A–Z' },
            { key: 'lowercase', label: 'a–z' },
            { key: 'digits',    label: '0–9' },
            { key: 'symbols',   label: '!@#' },
          ] as const
        ).map(({ key, label }) => (
          <button
            key={key}
            type="button"
            onClick={() => toggle(key)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              options[key]
                ? 'bg-blue-600 border-blue-500 text-white'
                : 'bg-gray-800 border-gray-600 text-gray-400 hover:text-gray-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Generated output */}
      {generated && (
        <div className="flex items-center gap-2">
          <code className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs font-mono text-green-400 break-all">
            {generated}
          </code>
          <button
            type="button"
            onClick={() => copyToClipboard(generated, 'gen')}
            className={`p-2 rounded-lg border transition-colors shrink-0 ${
              copiedId === 'gen'
                ? 'bg-green-900/30 border-green-700 text-green-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
            }`}
            title={copiedId === 'gen' ? `Clears in ${secondsLeft}s` : 'Copy'}
          >
            {copiedId === 'gen' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      )}

      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}

      {/* Buttons */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={generate}
          className="flex items-center gap-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs font-medium px-3 py-2 rounded-lg transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Generate
        </button>
        {generated && (
          <button
            type="button"
            onClick={() => onUse(generated)}
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium px-3 py-2 rounded-lg transition-colors"
          >
            Use This
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}
