// ============================================================
// useClipboard — Best-effort secure clipboard with auto-clear
// - Avoids overwriting a newer clipboard value when readText()
//   is available and indicates the clipboard changed.
// - Automatically clears pending secret if the vault locks.
// - Cleans up intervals on unmount while still clearing clipboard.
// ============================================================

'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import { useVaultStore } from '@/store/vaultStore';

const DEFAULT_CLEAR_SECONDS = 20;

async function safeClearClipboardIfUnchanged(expectedText: string | null): Promise<void> {
  if (typeof navigator === 'undefined' || !navigator.clipboard) return;

  try {
    if (typeof navigator.clipboard.readText === 'function' && expectedText !== null) {
      const current = await navigator.clipboard.readText();
      // Preserve newer clipboard value copied by the user elsewhere
      if (current !== expectedText) {
        return;
      }
    }
  } catch {
    // readText may be blocked when unfocused or denied by permissions;
    // fall through to best-effort clear.
  }

  try {
    await navigator.clipboard.writeText('');
  } catch {
    // Best-effort clear only (browsers may restrict clipboard writes in background tabs)
  }
}

export function useClipboard() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastCopiedRef = useRef<string | null>(null);
  const isMountedRef = useRef(true);

  const vault = useVaultStore((s) => s.vault);
  const isUnlocked = useVaultStore((s) => s.isUnlocked);
  const clearSeconds =
    vault?.settings?.clipboardClearSeconds ?? DEFAULT_CLEAR_SECONDS;

  const clearTimers = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  // Clear pending secret if the vault locks while a copy countdown is active
  useEffect(() => {
    if (!isUnlocked && lastCopiedRef.current !== null) {
      const pending = lastCopiedRef.current;
      lastCopiedRef.current = null;
      clearTimers();
      void safeClearClipboardIfUnchanged(pending);
      if (isMountedRef.current) {
        setCopiedId(null);
        setSecondsLeft(0);
      }
    }
  }, [isUnlocked, clearTimers]);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      // Stop countdown interval on unmount, but let any pending clipboard-clear
      // timeout still execute so copied secrets do not linger indefinitely.
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, []);

  const copyToClipboard = useCallback(
    async (text: string, id: string, options?: { autoClear?: boolean }) => {
      clearTimers();
      const shouldAutoClear = options?.autoClear ?? true;

      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }

      if (isMountedRef.current) {
        setCopiedId(id);
        setSecondsLeft(shouldAutoClear ? clearSeconds : 0);
      }

      if (!shouldAutoClear) {
        lastCopiedRef.current = null;
        timerRef.current = setTimeout(() => {
          timerRef.current = null;
          if (isMountedRef.current) {
            setCopiedId(null);
          }
        }, 2500);
        return;
      }

      lastCopiedRef.current = text;

      intervalRef.current = setInterval(() => {
        if (!isMountedRef.current) {
          if (intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
          }
          return;
        }
        setSecondsLeft((s) => {
          if (s <= 1) {
            if (intervalRef.current) {
              clearInterval(intervalRef.current);
              intervalRef.current = null;
            }
            return 0;
          }
          return s - 1;
        });
      }, 1000);

      timerRef.current = setTimeout(async () => {
        const expected = lastCopiedRef.current;
        lastCopiedRef.current = null;
        timerRef.current = null;
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
        await safeClearClipboardIfUnchanged(expected);
        if (isMountedRef.current) {
          setCopiedId(null);
          setSecondsLeft(0);
        }
      }, clearSeconds * 1000);
    },
    [clearSeconds, clearTimers]
  );

  return { copiedId, secondsLeft, copyToClipboard };
}
